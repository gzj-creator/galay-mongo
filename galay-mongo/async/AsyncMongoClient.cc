#include "AsyncMongoClient.h"

#include "galay-mongo/base/SocketOptions.h"
#include "galay-mongo/protocol/Builder.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace galay::mongo
{

namespace
{

int32_t readInt32LE(const char* p)
{
    return static_cast<int32_t>(
        (static_cast<uint32_t>(static_cast<uint8_t>(p[0]))      ) |
        (static_cast<uint32_t>(static_cast<uint8_t>(p[1])) <<  8) |
        (static_cast<uint32_t>(static_cast<uint8_t>(p[2])) << 16) |
        (static_cast<uint32_t>(static_cast<uint8_t>(p[3])) << 24));
}

void writeInt32LE(char* p, int32_t value)
{
    const auto u = static_cast<uint32_t>(value);
    p[0] = static_cast<char>(u & 0xFF);
    p[1] = static_cast<char>((u >> 8) & 0xFF);
    p[2] = static_cast<char>((u >> 16) & 0xFF);
    p[3] = static_cast<char>((u >> 24) & 0xFF);
}

MongoError mapIoError(const IOError& io_error, MongoErrorType fallback)
{
    if (IOError::contains(io_error.code(), galay::kernel::kTimeout)) {
        return MongoError(MONGO_ERROR_TIMEOUT, io_error.message());
    }
    if (IOError::contains(io_error.code(), galay::kernel::kDisconnectError)) {
        return MongoError(MONGO_ERROR_CONNECTION_CLOSED, io_error.message());
    }
    return MongoError(fallback, io_error.message());
}

std::string escapeScramUsername(const std::string& username)
{
    std::string escaped;
    escaped.reserve(username.size());

    for (char ch : username) {
        if (ch == '=') {
            escaped += "=3D";
        } else if (ch == ',') {
            escaped += "=2C";
        } else {
            escaped.push_back(ch);
        }
    }

    return escaped;
}

std::unordered_map<std::string, std::string> parseScramPayload(const std::string& payload)
{
    std::unordered_map<std::string, std::string> kv;

    size_t start = 0;
    while (start < payload.size()) {
        size_t comma = payload.find(',', start);
        if (comma == std::string::npos) {
            comma = payload.size();
        }

        const std::string item = payload.substr(start, comma - start);
        const size_t eq = item.find('=');
        if (eq != std::string::npos && eq > 0) {
            kv[item.substr(0, eq)] = item.substr(eq + 1);
        }

        start = comma + 1;
    }

    return kv;
}

std::string base64Encode(const std::vector<uint8_t>& bytes)
{
    if (bytes.empty()) {
        return "";
    }

    std::string out;
    out.resize(4 * ((bytes.size() + 2) / 3));

    const int written = ::EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(out.data()),
        reinterpret_cast<const unsigned char*>(bytes.data()),
        static_cast<int>(bytes.size()));

    if (written < 0) {
        return "";
    }

    out.resize(static_cast<size_t>(written));
    return out;
}

std::expected<std::vector<uint8_t>, MongoError> base64Decode(const std::string& text)
{
    if (text.empty()) {
        return std::vector<uint8_t>{};
    }

    std::vector<uint8_t> out((text.size() * 3) / 4 + 4);
    int written = ::EVP_DecodeBlock(
        reinterpret_cast<unsigned char*>(out.data()),
        reinterpret_cast<const unsigned char*>(text.data()),
        static_cast<int>(text.size()));

    if (written < 0) {
        return std::unexpected(MongoError(MONGO_ERROR_AUTH, "base64 decode failed"));
    }

    size_t padding = 0;
    if (!text.empty() && text.back() == '=') {
        ++padding;
        if (text.size() >= 2 && text[text.size() - 2] == '=') {
            ++padding;
        }
    }

    size_t size = static_cast<size_t>(written);
    if (padding <= size) {
        size -= padding;
    }
    out.resize(size);
    return out;
}

std::expected<std::vector<uint8_t>, MongoError>
pbkdf2HmacSha256(const std::string& password,
                 const std::vector<uint8_t>& salt,
                 int iterations)
{
    std::vector<uint8_t> key(32, 0);

    const int ok = ::PKCS5_PBKDF2_HMAC(
        password.c_str(),
        static_cast<int>(password.size()),
        salt.data(),
        static_cast<int>(salt.size()),
        iterations,
        EVP_sha256(),
        static_cast<int>(key.size()),
        key.data());

    if (ok != 1) {
        return std::unexpected(MongoError(MONGO_ERROR_AUTH, "PKCS5_PBKDF2_HMAC failed"));
    }

    return key;
}

std::expected<std::vector<uint8_t>, MongoError>
hmacSha256(const std::vector<uint8_t>& key, const std::string& data)
{
    std::vector<uint8_t> output(EVP_MAX_MD_SIZE, 0);
    unsigned int out_len = 0;

    unsigned char* digest = ::HMAC(EVP_sha256(),
                                   key.data(),
                                   static_cast<int>(key.size()),
                                   reinterpret_cast<const unsigned char*>(data.data()),
                                   static_cast<int>(data.size()),
                                   output.data(),
                                   &out_len);
    if (digest == nullptr) {
        return std::unexpected(MongoError(MONGO_ERROR_AUTH, "HMAC failed"));
    }

    output.resize(out_len);
    return output;
}

std::expected<std::vector<uint8_t>, MongoError> sha256(const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> output(SHA256_DIGEST_LENGTH, 0);
    if (::SHA256(data.data(), data.size(), output.data()) == nullptr) {
        return std::unexpected(MongoError(MONGO_ERROR_AUTH, "SHA256 failed"));
    }
    return output;
}

std::vector<uint8_t> xorBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b)
{
    const size_t size = std::min(a.size(), b.size());
    std::vector<uint8_t> out(size, 0);
    for (size_t i = 0; i < size; ++i) {
        out[i] = static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return out;
}

std::expected<std::string, MongoError> generateClientNonce()
{
    std::vector<uint8_t> random_bytes(18, 0);
    if (::RAND_bytes(random_bytes.data(), static_cast<int>(random_bytes.size())) != 1) {
        return std::unexpected(MongoError(MONGO_ERROR_INTERNAL,
                                          "RAND_bytes failed while generating SCRAM nonce"));
    }
    return base64Encode(random_bytes);
}

std::expected<int32_t, MongoError> readConversationId(const MongoDocument& doc)
{
    const auto* field = doc.find("conversationId");
    if (field == nullptr) {
        return std::unexpected(MongoError(MONGO_ERROR_AUTH,
                                          "Missing conversationId in SCRAM response"));
    }

    int64_t value = 0;
    if (field->isInt32()) {
        value = field->toInt32();
    } else if (field->isInt64()) {
        value = field->toInt64();
    } else if (field->isDouble()) {
        value = static_cast<int64_t>(field->toDouble());
    } else {
        return std::unexpected(MongoError(MONGO_ERROR_AUTH,
                                          "Invalid conversationId type in SCRAM response"));
    }

    if (value <= 0 || value > std::numeric_limits<int32_t>::max()) {
        return std::unexpected(MongoError(MONGO_ERROR_AUTH, "Invalid conversationId value"));
    }

    return static_cast<int32_t>(value);
}

std::expected<std::string, MongoError> readBinaryPayloadAsString(const MongoDocument& doc)
{
    const auto* payload_field = doc.find("payload");
    if (payload_field == nullptr || !payload_field->isBinary()) {
        return std::unexpected(MongoError(MONGO_ERROR_AUTH,
                                          "Missing payload in SCRAM response"));
    }

    const auto& payload = payload_field->toBinary();
    return std::string(payload.begin(), payload.end());
}

MongoDocument buildClientMetadata(const std::string& app_name)
{
    MongoDocument driver;
    driver.append("name", "galay-mongo");
    driver.append("version", "1.1.1");

    MongoDocument os;
#if defined(__APPLE__)
    os.append("type", "Darwin");
    os.append("name", "macOS");
#elif defined(__linux__)
    os.append("type", "Linux");
    os.append("name", "Linux");
#elif defined(_WIN32)
    os.append("type", "Windows");
    os.append("name", "Windows");
#else
    os.append("type", "Unknown");
    os.append("name", "Unknown");
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
    os.append("architecture", "arm64");
#elif defined(__x86_64__) || defined(_M_X64)
    os.append("architecture", "x86_64");
#elif defined(__i386__) || defined(_M_IX86)
    os.append("architecture", "x86");
#endif

    MongoDocument client;
    if (!app_name.empty()) {
        MongoDocument app;
        app.append("name", app_name);
        client.append("application", app);
    }
    client.append("driver", driver);
    client.append("os", os);
    return client;
}

struct DecodeView
{
    const char* data = nullptr;
    int32_t msg_len = 0;
};

struct SendSegment
{
    const char* data = nullptr;
    size_t len = 0;
};

constexpr size_t kAsyncMaxMessageSize = 128 * 1024 * 1024;

std::expected<std::optional<DecodeView>, MongoError>
prepareDecodeView(std::span<const struct iovec> read_iovecs, std::string& parse_buffer)
{
    if (read_iovecs.empty()) {
        return std::optional<DecodeView>{};
    }

    const auto& first = read_iovecs.front();
    size_t total_len = first.iov_len;
    for (size_t i = 1; i < read_iovecs.size(); ++i) {
        total_len += read_iovecs[i].iov_len;
    }
    if (total_len < 4) {
        return std::optional<DecodeView>{};
    }

    int32_t msg_len = 0;
    if (first.iov_len >= 4) {
        msg_len = readInt32LE(static_cast<const char*>(first.iov_base));
    } else {
        char header_bytes[4];
        size_t copied = 0;
        for (const auto& iov : read_iovecs) {
            if (copied >= 4) {
                break;
            }
            const size_t chunk = std::min(iov.iov_len, static_cast<size_t>(4 - copied));
            std::memcpy(header_bytes + copied, iov.iov_base, chunk);
            copied += chunk;
        }
        msg_len = readInt32LE(header_bytes);
    }

    if (msg_len < 16) {
        return std::unexpected(MongoError(MONGO_ERROR_PROTOCOL,
                                          "Invalid Mongo message length in response"));
    }
    if (static_cast<size_t>(msg_len) > kAsyncMaxMessageSize) {
        return std::unexpected(MongoError(MONGO_ERROR_PROTOCOL,
                                          "Mongo message exceeds max supported size"));
    }
    if (total_len < static_cast<size_t>(msg_len)) {
        return std::optional<DecodeView>{};
    }

    if (first.iov_len >= static_cast<size_t>(msg_len)) {
        return std::optional<DecodeView>(
            DecodeView{static_cast<const char*>(first.iov_base), msg_len});
    }

    const size_t msg_size = static_cast<size_t>(msg_len);
    if (parse_buffer.size() < msg_size) {
        parse_buffer.resize(msg_size);
    }

    size_t copied = std::min(first.iov_len, msg_size);
    if (copied > 0) {
        std::memcpy(parse_buffer.data(), first.iov_base, copied);
    }

    for (size_t i = 1; i < read_iovecs.size() && copied < msg_size; ++i) {
        const auto& iov = read_iovecs[i];
        const size_t chunk = std::min(iov.iov_len, msg_size - copied);
        std::memcpy(parse_buffer.data() + copied, iov.iov_base, chunk);
        copied += chunk;
    }

    return std::optional<DecodeView>(DecodeView{parse_buffer.data(), msg_len});
}

void fillSendIovecsFromSegments(std::vector<struct iovec>& iovecs,
                                std::span<const SendSegment> segments,
                                size_t sent)
{
    iovecs.clear();
    size_t skip = sent;

    for (const auto& segment : segments) {
        if (segment.data == nullptr || segment.len == 0) {
            continue;
        }
        if (skip >= segment.len) {
            skip -= segment.len;
            continue;
        }

        iovecs.push_back(iovec{
            const_cast<char*>(segment.data + skip),
            segment.len - skip
        });
        skip = 0;
    }
}

constexpr size_t kMongoMaxWriteIovecs = 3;

size_t totalSegmentLength(std::span<const SendSegment> segments)
{
    size_t total = 0;
    for (const auto& segment : segments) {
        total += segment.len;
    }
    return total;
}

bool prepareWriteWindow(std::array<struct iovec, kMongoMaxWriteIovecs>& write_iovecs,
                        size_t& write_iov_count,
                        std::vector<struct iovec>& scratch,
                        std::span<const SendSegment> segments,
                        size_t sent,
                        std::optional<MongoError>& result_error)
{
    fillSendIovecsFromSegments(scratch, segments, sent);
    if (scratch.empty()) {
        result_error = MongoError(MONGO_ERROR_INTERNAL,
                                  "sendSegments produced empty iovecs");
        write_iov_count = 0;
        return false;
    }
    if (scratch.size() > write_iovecs.size()) {
        result_error = MongoError(MONGO_ERROR_INTERNAL,
                                  "Mongo write iovec count exceeds supported window");
        write_iov_count = 0;
        return false;
    }

    write_iov_count = scratch.size();
    for (size_t i = 0; i < write_iov_count; ++i) {
        write_iovecs[i] = scratch[i];
    }
    return true;
}

bool prepareReadWindow(AsyncMongoClient& client,
                       std::array<struct iovec, 2>& read_iovecs,
                       size_t& read_iov_count,
                       std::string_view no_space_message,
                       std::optional<MongoError>& result_error)
{
    read_iov_count = client.ringBuffer().getWriteIovecs(read_iovecs.data(), read_iovecs.size());
    if (read_iov_count == 0) {
        result_error = MongoError(MONGO_ERROR_RECV, std::string(no_space_message));
        return false;
    }
    return true;
}

void applyReadResult(AsyncMongoClient& client,
                     std::expected<size_t, IOError> result,
                     MongoErrorType io_error_type,
                     std::string_view closed_message,
                     std::optional<MongoError>& result_error)
{
    if (!result.has_value()) {
        result_error = mapIoError(result.error(), io_error_type);
        return;
    }
    if (result.value() == 0) {
        result_error = MongoError(MONGO_ERROR_CONNECTION_CLOSED, std::string(closed_message));
        return;
    }
    client.ringBuffer().produce(result.value());
}

void applyWriteResult(std::expected<size_t, IOError> result,
                      size_t& sent,
                      MongoErrorType io_error_type,
                      std::string_view closed_message,
                      std::optional<MongoError>& result_error)
{
    if (!result.has_value()) {
        result_error = mapIoError(result.error(), io_error_type);
        return;
    }
    if (result.value() == 0) {
        result_error = MongoError(MONGO_ERROR_CONNECTION_CLOSED, std::string(closed_message));
        return;
    }
    sent += result.value();
}

bool isSimplePingCommand(const MongoDocument& command, const std::string& database)
{
    if (command.empty() || command.size() > 2) {
        return false;
    }

    const MongoValue* ping = command.find("ping");
    if (ping == nullptr) {
        return false;
    }

    const MongoValue* db = command.find("$db");
    if (db != nullptr) {
        if (command.size() != 2) {
            return false;
        }
        if (!db->isString() || db->toString() != database) {
            return false;
        }
    } else if (command.size() != 1) {
        return false;
    }

    if (ping->isInt32()) {
        return ping->toInt32() == 1;
    }
    if (ping->isInt64()) {
        return ping->toInt64() == 1;
    }
    if (ping->isDouble()) {
        return std::abs(ping->toDouble() - 1.0) < 1e-12;
    }
    return false;
}

MongoError makeServerError(MongoReply&& reply, std::string_view default_message)
{
    return MongoError(MONGO_ERROR_SERVER,
                      reply.errorCode(),
                      reply.errorMessage().empty()
                          ? std::string(default_message)
                          : reply.errorMessage());
}

} // namespace

struct AsyncMongoClientInternals
{
    enum class AuthPhase {
        HelloReply,
        SaslStartReply,
        SaslContinueReply,
        SaslFinalReply,
    };

    struct ConnectFlowState {
        AsyncMongoClient& client;
        MongoConfig config;
        bool auth_enabled = false;
        AuthPhase auth_phase = AuthPhase::HelloReply;
        std::string auth_db;
        int32_t auth_conversation_id = 0;
        std::string auth_client_nonce;
        std::string auth_client_first_bare;
        std::string auth_expected_server_signature;
        std::string encoded_request;

        ConnectFlowState(AsyncMongoClient& client_ref, MongoConfig cfg)
            : client(client_ref)
            , config(std::move(cfg))
        {
        }

        std::expected<void, MongoError> initialize()
        {
            auth_enabled = !config.username.empty() || !config.password.empty();
            auth_db = !config.auth_database.empty()
                ? config.auth_database
                : (!config.database.empty() ? config.database : "admin");

            if ((config.username.empty() && !config.password.empty()) ||
                (!config.username.empty() && config.password.empty())) {
                return std::unexpected(MongoError(
                    MONGO_ERROR_INVALID_PARAM,
                    "Both username and password are required for SCRAM authentication"));
            }

            MongoDocument hello;
            hello.append("hello", int32_t(1));
            hello.append("helloOk", true);
            hello.append("$db", config.hello_database.empty() ? std::string("admin")
                                                              : config.hello_database);
            hello.append("client", buildClientMetadata(config.app_name));

            encoded_request.clear();
            protocol::MongoProtocol::appendOpMsg(
                encoded_request,
                client.nextRequestId(),
                hello);
            return {};
        }

        std::expected<bool, MongoError> handleReply(MongoReply&& reply)
        {
            switch (auth_phase) {
            case AuthPhase::HelloReply:
                return handleHelloReply(std::move(reply));
            case AuthPhase::SaslStartReply:
                return handleSaslStartReply(std::move(reply));
            case AuthPhase::SaslContinueReply:
                return handleSaslContinueReply(std::move(reply));
            case AuthPhase::SaslFinalReply:
                return handleSaslFinalReply(std::move(reply));
            }

            return std::unexpected(MongoError(MONGO_ERROR_INTERNAL,
                                              "Unknown auth phase in connect flow"));
        }

    private:
        std::expected<bool, MongoError> handleHelloReply(MongoReply&&)
        {
            if (!auth_enabled) {
                return true;
            }

            auto nonce_or_err = generateClientNonce();
            if (!nonce_or_err) {
                return std::unexpected(nonce_or_err.error());
            }

            auth_client_nonce = std::move(nonce_or_err.value());
            auth_client_first_bare =
                "n=" + escapeScramUsername(config.username) + ",r=" + auth_client_nonce;
            const std::string client_first_message = "n,," + auth_client_first_bare;

            MongoValue::Binary payload(client_first_message.begin(), client_first_message.end());

            MongoDocument sasl_start;
            sasl_start.append("saslStart", int32_t(1));
            sasl_start.append("mechanism", "SCRAM-SHA-256");
            sasl_start.append("payload", std::move(payload));
            sasl_start.append("autoAuthorize", int32_t(1));
            sasl_start.append("$db", auth_db);

            encoded_request.clear();
            protocol::MongoProtocol::appendOpMsg(
                encoded_request,
                client.nextRequestId(),
                sasl_start);
            auth_phase = AuthPhase::SaslStartReply;
            return false;
        }

        std::expected<bool, MongoError> handleSaslStartReply(MongoReply&& reply)
        {
            const auto& doc = reply.document();

            auto conversation_id_or_err = readConversationId(doc);
            if (!conversation_id_or_err) {
                return std::unexpected(conversation_id_or_err.error());
            }
            auth_conversation_id = conversation_id_or_err.value();

            auto server_first_or_err = readBinaryPayloadAsString(doc);
            if (!server_first_or_err) {
                return std::unexpected(server_first_or_err.error());
            }
            const std::string server_first_message = std::move(server_first_or_err.value());

            const auto kv = parseScramPayload(server_first_message);
            const auto nonce_it = kv.find("r");
            const auto salt_it = kv.find("s");
            const auto iter_it = kv.find("i");
            if (nonce_it == kv.end() || salt_it == kv.end() || iter_it == kv.end()) {
                return std::unexpected(MongoError(MONGO_ERROR_AUTH,
                                                  "Invalid SCRAM server-first-message"));
            }

            const std::string& server_nonce = nonce_it->second;
            if (server_nonce.rfind(auth_client_nonce, 0) != 0) {
                return std::unexpected(MongoError(MONGO_ERROR_AUTH,
                                                  "SCRAM server nonce does not include client nonce"));
            }

            int iterations = 0;
            const auto parse_iter_result = std::from_chars(
                iter_it->second.data(),
                iter_it->second.data() + iter_it->second.size(),
                iterations);
            if (parse_iter_result.ec != std::errc{} || iterations <= 0) {
                return std::unexpected(MongoError(MONGO_ERROR_AUTH,
                                                  "Invalid SCRAM iteration count"));
            }

            auto salt_or_err = base64Decode(salt_it->second);
            if (!salt_or_err) {
                return std::unexpected(MongoError(MONGO_ERROR_AUTH,
                                                  "Invalid SCRAM salt: " +
                                                      salt_or_err.error().message()));
            }

            const std::string client_final_without_proof = "c=biws,r=" + server_nonce;
            const std::string auth_message = auth_client_first_bare + "," +
                                             server_first_message + "," +
                                             client_final_without_proof;

            auto salted_password =
                pbkdf2HmacSha256(config.password, salt_or_err.value(), iterations);
            if (!salted_password) {
                return std::unexpected(salted_password.error());
            }

            auto client_key = hmacSha256(salted_password.value(), "Client Key");
            if (!client_key) {
                return std::unexpected(client_key.error());
            }

            auto stored_key = sha256(client_key.value());
            if (!stored_key) {
                return std::unexpected(stored_key.error());
            }

            auto client_signature = hmacSha256(stored_key.value(), auth_message);
            if (!client_signature) {
                return std::unexpected(client_signature.error());
            }

            auto server_key = hmacSha256(salted_password.value(), "Server Key");
            if (!server_key) {
                return std::unexpected(server_key.error());
            }

            auto server_signature = hmacSha256(server_key.value(), auth_message);
            if (!server_signature) {
                return std::unexpected(server_signature.error());
            }

            const auto client_proof = xorBytes(client_key.value(), client_signature.value());
            auth_expected_server_signature = base64Encode(server_signature.value());
            if (auth_expected_server_signature.empty()) {
                return std::unexpected(MongoError(MONGO_ERROR_AUTH,
                                                  "Failed to encode SCRAM server signature"));
            }

            const std::string client_final_message =
                client_final_without_proof + ",p=" + base64Encode(client_proof);

            MongoValue::Binary continue_payload(client_final_message.begin(),
                                                client_final_message.end());
            MongoDocument sasl_continue;
            sasl_continue.append("saslContinue", int32_t(1));
            sasl_continue.append("conversationId", auth_conversation_id);
            sasl_continue.append("payload", std::move(continue_payload));
            sasl_continue.append("$db", auth_db);

            encoded_request.clear();
            protocol::MongoProtocol::appendOpMsg(
                encoded_request,
                client.nextRequestId(),
                sasl_continue);
            auth_phase = AuthPhase::SaslContinueReply;
            return false;
        }

        std::expected<bool, MongoError> handleSaslContinueReply(MongoReply&& reply)
        {
            const auto& doc = reply.document();

            auto server_final_or_err = readBinaryPayloadAsString(doc);
            if (!server_final_or_err) {
                return std::unexpected(server_final_or_err.error());
            }

            const auto kv = parseScramPayload(server_final_or_err.value());
            const auto error_it = kv.find("e");
            if (error_it != kv.end()) {
                return std::unexpected(MongoError(MONGO_ERROR_AUTH,
                                                  "SCRAM server-final-message error: " +
                                                      error_it->second));
            }

            const auto verifier_it = kv.find("v");
            if (verifier_it == kv.end()) {
                return std::unexpected(MongoError(MONGO_ERROR_AUTH,
                                                  "SCRAM server-final-message missing verifier"));
            }

            if (verifier_it->second != auth_expected_server_signature) {
                return std::unexpected(MongoError(MONGO_ERROR_AUTH,
                                                  "SCRAM server signature mismatch"));
            }

            if (doc.getBool("done", false)) {
                return true;
            }

            MongoDocument final_continue;
            final_continue.append("saslContinue", int32_t(1));
            final_continue.append("conversationId", auth_conversation_id);
            final_continue.append("payload", MongoValue::Binary{});
            final_continue.append("$db", auth_db);

            encoded_request.clear();
            protocol::MongoProtocol::appendOpMsg(
                encoded_request,
                client.nextRequestId(),
                final_continue);
            auth_phase = AuthPhase::SaslFinalReply;
            return false;
        }

        std::expected<bool, MongoError> handleSaslFinalReply(MongoReply&& reply)
        {
            if (!reply.document().getBool("done", false)) {
                return std::unexpected(MongoError(MONGO_ERROR_AUTH,
                                                  "SCRAM authentication not finished"));
            }
            return true;
        }
    };

    static std::expected<std::optional<protocol::MongoMessage>, MongoError>
    tryParseMessage(AsyncMongoClient& client)
    {
        struct iovec read_iovecs[2];
        const size_t read_iovecs_count = client.m_ring_buffer.getReadIovecs(read_iovecs, 2);
        if (read_iovecs_count == 0) {
            return std::optional<protocol::MongoMessage>{};
        }

        auto decode_view_or_err = prepareDecodeView(
            std::span<const struct iovec>(read_iovecs, read_iovecs_count),
            client.m_decode_scratch);
        if (!decode_view_or_err) {
            return std::unexpected(decode_view_or_err.error());
        }
        if (!decode_view_or_err->has_value()) {
            return std::optional<protocol::MongoMessage>{};
        }

        const DecodeView& view = decode_view_or_err->value();
        auto message =
            protocol::MongoProtocol::decodeMessage(view.data, static_cast<size_t>(view.msg_len));
        if (!message) {
            return std::unexpected(message.error());
        }

        client.m_ring_buffer.consume(static_cast<size_t>(view.msg_len));
        return std::optional<protocol::MongoMessage>(std::move(message.value()));
    }

    static void clearDecodeScratch(AsyncMongoClient& client)
    {
        client.m_decode_scratch.clear();
    }

    static void completeConnectSuccess(AsyncMongoClient& client,
                                       const ConnectFlowState& state)
    {
        client.m_is_closed = false;
        if (state.auth_enabled) {
            MongoLogInfo(client.m_logger.get(),
                         "Mongo connected and authenticated successfully to {}:{}",
                         state.config.host,
                         state.config.port);
        } else {
            MongoLogInfo(client.m_logger.get(),
                         "Mongo connected successfully to {}:{}",
                         state.config.host,
                         state.config.port);
        }
    }
};

struct MongoConnectAwaitable::SharedState {
    SharedState(AsyncMongoClient& client_ref, MongoConfig config)
        : client(&client_ref)
        , flow(client_ref, std::move(config))
        , host(galay::kernel::IPType::IPV4, flow.config.host, flow.config.port)
    {
        client->ringBuffer().clear();
        AsyncMongoClientInternals::clearDecodeScratch(*client);

        auto init_result = flow.initialize();
        if (!init_result.has_value()) {
            pending_error = std::move(init_result.error());
            phase = Phase::Invalid;
            return;
        }

        auto nonblock_result = client->socket().option().handleNonBlock();
        if (!nonblock_result.has_value()) {
            pending_error = mapIoError(nonblock_result.error(), MONGO_ERROR_CONNECTION);
            phase = Phase::Invalid;
            return;
        }

        phase = Phase::Connect;
    }

    AsyncMongoClient* client = nullptr;
    AsyncMongoClientInternals::ConnectFlowState flow;
    galay::kernel::Host host;
    Phase phase = Phase::Invalid;
    size_t sent = 0;
    std::array<struct iovec, kMongoMaxWriteIovecs> write_iovecs{};
    size_t write_iov_count = 0;
    std::vector<struct iovec> send_iovec_scratch;
    std::array<struct iovec, 2> read_iovecs{};
    size_t read_iov_count = 0;
    std::optional<MongoError> pending_error;
    std::optional<Result> result;
    std::optional<protocol::MongoMessage> current_message;
};

MongoConnectAwaitable::Machine::Machine(std::shared_ptr<SharedState> state)
    : m_state(std::move(state))
{
}

galay::kernel::MachineAction<MongoConnectAwaitable::Machine::result_type>
MongoConnectAwaitable::Machine::advance()
{
        if (m_state->result.has_value()) {
            return galay::kernel::MachineAction<result_type>::complete(
                std::move(*m_state->result));
        }

        if (m_state->pending_error.has_value()) {
            m_state->result = std::unexpected(std::move(*m_state->pending_error));
            m_state->pending_error.reset();
            m_state->phase = Phase::Invalid;
            return galay::kernel::MachineAction<result_type>::complete(
                std::move(*m_state->result));
        }

        switch (m_state->phase) {
        case Phase::Invalid:
            m_state->result = std::unexpected(
                MongoError(MONGO_ERROR_INTERNAL, "Invalid Mongo connect awaitable"));
            return galay::kernel::MachineAction<result_type>::complete(
                std::move(*m_state->result));

        case Phase::Connect:
            return galay::kernel::MachineAction<result_type>::waitConnect(m_state->host);

        case Phase::SendRequest:
            return advanceSendRequest();

        case Phase::RecvReply:
            return advanceRecvReply();

        case Phase::HandleReply:
            return advanceHandleReply();

        case Phase::Done:
            if (!m_state->result.has_value()) {
                m_state->result = true;
            }
            return galay::kernel::MachineAction<result_type>::complete(
                std::move(*m_state->result));
        }

        m_state->result = std::unexpected(
            MongoError(MONGO_ERROR_INTERNAL, "Unknown Mongo connect awaitable phase"));
        return galay::kernel::MachineAction<result_type>::complete(std::move(*m_state->result));
    }

void MongoConnectAwaitable::Machine::onConnect(
    std::expected<void, galay::kernel::IOError> result)
{
        if (!result.has_value()) {
            m_state->pending_error = mapIoError(result.error(), MONGO_ERROR_CONNECTION);
            m_state->phase = Phase::Invalid;
            return;
        }

        trySetTcpNoDelay(m_state->client->socket().handle().fd,
                         m_state->flow.config.tcp_nodelay);
        m_state->sent = 0;
        m_state->phase = Phase::SendRequest;
    }

void MongoConnectAwaitable::Machine::onRead(
    std::expected<size_t, galay::kernel::IOError> result)
{
        applyReadResult(*m_state->client,
                        std::move(result),
                        MONGO_ERROR_RECV,
                        "Connection closed while receiving connect/auth reply",
                        m_state->pending_error);
        if (m_state->pending_error.has_value()) {
            m_state->phase = Phase::Invalid;
            return;
        }
        m_state->phase = Phase::RecvReply;
    }

void MongoConnectAwaitable::Machine::onWrite(
    std::expected<size_t, galay::kernel::IOError> result)
{
        applyWriteResult(std::move(result),
                         m_state->sent,
                         MONGO_ERROR_SEND,
                         "Connection closed during connect/auth request send",
                         m_state->pending_error);
        if (m_state->pending_error.has_value()) {
            m_state->phase = Phase::Invalid;
            return;
        }

        const std::array<SendSegment, 1> segments{{
            SendSegment{m_state->flow.encoded_request.data(),
                        m_state->flow.encoded_request.size()}
        }};
        if (m_state->sent >= totalSegmentLength(std::span<const SendSegment>(segments))) {
            m_state->phase = Phase::RecvReply;
        } else {
            m_state->phase = Phase::SendRequest;
        }
    }

galay::kernel::MachineAction<MongoConnectAwaitable::Machine::result_type>
MongoConnectAwaitable::Machine::advanceSendRequest()
{
        const std::array<SendSegment, 1> segments{{
            SendSegment{m_state->flow.encoded_request.data(),
                        m_state->flow.encoded_request.size()}
        }};
        const auto segment_span = std::span<const SendSegment>(segments);
        if (m_state->sent >= totalSegmentLength(segment_span)) {
            m_state->phase = Phase::RecvReply;
            return advance();
        }

        if (!prepareWriteWindow(m_state->write_iovecs,
                                m_state->write_iov_count,
                                m_state->send_iovec_scratch,
                                segment_span,
                                m_state->sent,
                                m_state->pending_error)) {
            return advance();
        }

        return galay::kernel::MachineAction<result_type>::waitWritev(
            m_state->write_iovecs.data(),
            m_state->write_iov_count);
    }

galay::kernel::MachineAction<MongoConnectAwaitable::Machine::result_type>
MongoConnectAwaitable::Machine::advanceRecvReply()
{
        auto message_or_err = AsyncMongoClientInternals::tryParseMessage(*m_state->client);
        if (!message_or_err.has_value()) {
            m_state->pending_error = std::move(message_or_err.error());
            return advance();
        }
        if (message_or_err->has_value()) {
            m_state->current_message = std::move(message_or_err->value());
            m_state->phase = Phase::HandleReply;
            return advance();
        }

        if (!prepareReadWindow(*m_state->client,
                               m_state->read_iovecs,
                               m_state->read_iov_count,
                               "No writable ring buffer space while receiving connect/auth reply",
                               m_state->pending_error)) {
            return advance();
        }

        return galay::kernel::MachineAction<result_type>::waitReadv(
            m_state->read_iovecs.data(),
            m_state->read_iov_count);
    }

galay::kernel::MachineAction<MongoConnectAwaitable::Machine::result_type>
MongoConnectAwaitable::Machine::advanceHandleReply()
{
        if (!m_state->current_message.has_value()) {
            m_state->pending_error = MongoError(MONGO_ERROR_INTERNAL,
                                                "Missing Mongo connect/auth reply message");
            return advance();
        }

        MongoReply reply(std::move(m_state->current_message->body));
        m_state->current_message.reset();
        if (!reply.ok()) {
            m_state->pending_error = makeServerError(std::move(reply),
                                                     "Mongo connect/auth command failed");
            return advance();
        }

        auto next_result = m_state->flow.handleReply(std::move(reply));
        if (!next_result.has_value()) {
            m_state->pending_error = std::move(next_result.error());
            return advance();
        }
        if (next_result.value()) {
            AsyncMongoClientInternals::completeConnectSuccess(*m_state->client, m_state->flow);
            m_state->result = true;
            m_state->phase = Phase::Done;
            return advance();
        }

        m_state->sent = 0;
        m_state->phase = Phase::SendRequest;
        return advance();
}

MongoConnectAwaitable::MongoConnectAwaitable(AsyncMongoClient& client, MongoConfig config)
    : m_state(std::make_shared<SharedState>(client, std::move(config)))
    , m_inner(galay::kernel::AwaitableBuilder<Result>::fromStateMachine(
                  client.socket().controller(),
                  Machine(m_state))
                  .build())
{
}

bool MongoConnectAwaitable::isInvalid() const
{
    return !m_state || m_state->phase == Phase::Invalid;
}

struct MongoCommandAwaitable::SharedState {
    SharedState(AsyncMongoClient& client_ref, std::string db, MongoDocument cmd)
        : client(&client_ref)
        , database(std::move(db))
        , command(std::move(cmd))
    {
        if (client->m_is_closed) {
            pending_error = MongoError(MONGO_ERROR_CONNECTION, "Mongo client is not connected");
            phase = Phase::Invalid;
            return;
        }

        request_id = client->nextRequestId();
        writeInt32LE(request_id_le.data(), request_id);

        if (isSimplePingCommand(command, database)) {
            if (client->m_ping_encoded_template.empty() || client->m_ping_template_db != database) {
                client->m_ping_template_db = database;
                client->m_ping_encoded_template.clear();
                protocol::MongoProtocol::appendOpMsgWithDatabase(
                    client->m_ping_encoded_template,
                    0,
                    command,
                    database);
            }
            if (client->m_ping_encoded_template.size() < 8) {
                pending_error = MongoError(MONGO_ERROR_INTERNAL, "Invalid cached ping template");
                phase = Phase::Invalid;
                return;
            }
            send_segments[0] = SendSegment{client->m_ping_encoded_template.data(), 4};
            send_segments[1] = SendSegment{request_id_le.data(), request_id_le.size()};
            send_segments[2] = SendSegment{
                client->m_ping_encoded_template.data() + 8,
                client->m_ping_encoded_template.size() - 8
            };
            send_segment_count = 3;
        } else {
            protocol::MongoProtocol::appendOpMsgWithDatabase(
                encoded_request,
                request_id,
                command,
                database);
            send_segments[0] = SendSegment{encoded_request.data(), encoded_request.size()};
            send_segment_count = 1;
        }
        total_len = totalSegmentLength(std::span<const SendSegment>(send_segments.data(),
                                                                    send_segment_count));
    }

    AsyncMongoClient* client = nullptr;
    std::string database;
    MongoDocument command;
    int32_t request_id = 0;
    std::array<char, 4> request_id_le{};
    std::string encoded_request;
    std::array<SendSegment, 3> send_segments{};
    size_t send_segment_count = 0;
    size_t total_len = 0;
    size_t sent = 0;
    std::vector<struct iovec> write_scratch;
    std::array<struct iovec, kMongoMaxWriteIovecs> write_iovecs{};
    size_t write_iov_count = 0;
    std::array<struct iovec, 2> read_iovecs{};
    size_t read_iov_count = 0;
    Phase phase = Phase::SendCommand;
    std::optional<MongoError> pending_error;
    std::optional<Result> result;
};

MongoCommandAwaitable::Machine::Machine(std::shared_ptr<SharedState> state)
    : m_state(std::move(state))
{
}

galay::kernel::MachineAction<MongoCommandAwaitable::Machine::result_type>
MongoCommandAwaitable::Machine::advance()
{
    if (m_state->result.has_value()) {
        return galay::kernel::MachineAction<result_type>::complete(std::move(*m_state->result));
    }
    if (m_state->pending_error.has_value()) {
        setError(std::move(*m_state->pending_error));
        m_state->pending_error.reset();
        return galay::kernel::MachineAction<result_type>::complete(std::move(*m_state->result));
    }

    switch (m_state->phase) {
    case Phase::Invalid:
        setError(MongoError(MONGO_ERROR_INTERNAL, "Mongo command machine entered invalid state"));
        return galay::kernel::MachineAction<result_type>::complete(std::move(*m_state->result));
    case Phase::SendCommand:
        return advanceSendCommand();
    case Phase::RecvReply:
        return advanceRecvReply();
    case Phase::Done:
        return galay::kernel::MachineAction<result_type>::complete(std::move(*m_state->result));
    }

    setError(MongoError(MONGO_ERROR_INTERNAL, "Unknown Mongo command machine state"));
    return galay::kernel::MachineAction<result_type>::complete(std::move(*m_state->result));
}

void MongoCommandAwaitable::Machine::onRead(
    std::expected<size_t, galay::kernel::IOError> result)
{
    applyReadResult(*m_state->client,
                    std::move(result),
                    MONGO_ERROR_RECV,
                    "Connection closed while receiving command reply",
                    m_state->pending_error);
    if (m_state->pending_error.has_value()) {
        m_state->phase = Phase::Invalid;
        return;
    }
    m_state->phase = Phase::RecvReply;
}

void MongoCommandAwaitable::Machine::onWrite(
    std::expected<size_t, galay::kernel::IOError> result)
{
    applyWriteResult(std::move(result),
                     m_state->sent,
                     MONGO_ERROR_SEND,
                     "Connection closed during command send",
                     m_state->pending_error);
    if (m_state->pending_error.has_value()) {
        m_state->phase = Phase::Invalid;
        return;
    }
    if (m_state->sent >= m_state->total_len) {
        m_state->sent = 0;
        m_state->phase = Phase::RecvReply;
    } else {
        m_state->phase = Phase::SendCommand;
    }
}

galay::kernel::MachineAction<MongoCommandAwaitable::Machine::result_type>
MongoCommandAwaitable::Machine::advanceSendCommand()
{
    if (m_state->sent >= m_state->total_len) {
        m_state->sent = 0;
        m_state->phase = Phase::RecvReply;
        return advance();
    }

    if (!prepareWriteWindow(m_state->write_iovecs,
                            m_state->write_iov_count,
                            m_state->write_scratch,
                            std::span<const SendSegment>(m_state->send_segments.data(),
                                                         m_state->send_segment_count),
                            m_state->sent,
                            m_state->pending_error)) {
        return advance();
    }
    return galay::kernel::MachineAction<result_type>::waitWritev(
        m_state->write_iovecs.data(),
        m_state->write_iov_count);
}

galay::kernel::MachineAction<MongoCommandAwaitable::Machine::result_type>
MongoCommandAwaitable::Machine::advanceRecvReply()
{
    auto message_or_err = AsyncMongoClientInternals::tryParseMessage(*m_state->client);
    if (!message_or_err.has_value()) {
        setError(std::move(message_or_err.error()));
        return galay::kernel::MachineAction<result_type>::complete(std::move(*m_state->result));
    }
    if (message_or_err->has_value()) {
        finishWithMessage(std::move(message_or_err->value()));
        return galay::kernel::MachineAction<result_type>::complete(std::move(*m_state->result));
    }

    if (!prepareReadWindow(*m_state->client,
                           m_state->read_iovecs,
                           m_state->read_iov_count,
                           "No writable ring buffer space while receiving command reply",
                           m_state->pending_error)) {
        return advance();
    }
    return galay::kernel::MachineAction<result_type>::waitReadv(
        m_state->read_iovecs.data(),
        m_state->read_iov_count);
}

void MongoCommandAwaitable::Machine::finishWithMessage(protocol::MongoMessage message)
{
    if (message.header.response_to != m_state->request_id) {
        setError(MongoError(MONGO_ERROR_PROTOCOL,
                            "Response responseTo does not match sent requestId"));
        return;
    }

    MongoReply reply(std::move(message.body));
    if (!reply.ok()) {
        setError(makeServerError(std::move(reply), "Mongo command failed"));
        return;
    }

    m_state->phase = Phase::Done;
    m_state->result = std::move(reply);
}

void MongoCommandAwaitable::Machine::setError(MongoError error) noexcept
{
    m_state->result = std::unexpected(std::move(error));
    m_state->phase = Phase::Invalid;
}

MongoCommandAwaitable::MongoCommandAwaitable(AsyncMongoClient& client,
                                             std::string database,
                                             MongoDocument command)
    : m_state(std::make_shared<SharedState>(client, std::move(database), std::move(command)))
    , m_inner(galay::kernel::AwaitableBuilder<Result>::fromStateMachine(
                  client.socket().controller(),
                  Machine(m_state))
                  .build())
{
}

bool MongoCommandAwaitable::isInvalid() const
{
    return m_state != nullptr && m_state->phase == Phase::Invalid;
}

struct MongoPipelineAwaitable::SharedState {
    SharedState(AsyncMongoClient& client_ref,
                std::string db,
                std::span<const MongoDocument> commands)
        : client(&client_ref)
        , database(std::move(db))
    {
        if (client->m_is_closed) {
            pending_error = MongoError(MONGO_ERROR_CONNECTION, "Mongo client is not connected");
            phase = Phase::Invalid;
            return;
        }
        if (commands.empty()) {
            pending_error = MongoError(MONGO_ERROR_INVALID_PARAM,
                                       "Pipeline commands must not be empty");
            phase = Phase::Invalid;
            return;
        }
        if (commands.size() > static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
            pending_error = MongoError(MONGO_ERROR_INVALID_PARAM,
                                       "Pipeline commands exceed supported size");
            phase = Phase::Invalid;
            return;
        }

        responses.resize(commands.size());
        first_request_id = client->reserveRequestIdBlock(commands.size());
        for (size_t i = 0; i < commands.size(); ++i) {
            responses[i].request_id = static_cast<int32_t>(
                static_cast<int64_t>(first_request_id) + static_cast<int64_t>(i));
        }

        encoded_batch = protocol::MongoCommandBuilder::encodePipeline(
            database,
            first_request_id,
            commands,
            client->m_pipeline_reserve_per_command);
        send_segments[0] = SendSegment{encoded_batch.data(), encoded_batch.size()};
        send_segment_count = 1;
        total_len = encoded_batch.size();
        phase = Phase::SendCommands;
    }

    AsyncMongoClient* client = nullptr;
    std::string database;
    int32_t first_request_id = 0;
    std::string encoded_batch;
    std::array<SendSegment, 1> send_segments{};
    size_t send_segment_count = 0;
    size_t total_len = 0;
    size_t sent = 0;
    size_t received = 0;
    std::vector<MongoPipelineResponse> responses;
    std::vector<struct iovec> write_scratch;
    std::array<struct iovec, kMongoMaxWriteIovecs> write_iovecs{};
    size_t write_iov_count = 0;
    std::array<struct iovec, 2> read_iovecs{};
    size_t read_iov_count = 0;
    Phase phase = Phase::Invalid;
    std::optional<MongoError> pending_error;
    std::optional<Result> result;
};

MongoPipelineAwaitable::Machine::Machine(std::shared_ptr<SharedState> state)
    : m_state(std::move(state))
{
}

galay::kernel::MachineAction<MongoPipelineAwaitable::Machine::result_type>
MongoPipelineAwaitable::Machine::advance()
{
    if (m_state->result.has_value()) {
        return galay::kernel::MachineAction<result_type>::complete(std::move(*m_state->result));
    }
    if (m_state->pending_error.has_value()) {
        setError(std::move(*m_state->pending_error));
        m_state->pending_error.reset();
        return galay::kernel::MachineAction<result_type>::complete(std::move(*m_state->result));
    }

    switch (m_state->phase) {
    case Phase::Invalid:
        setError(MongoError(MONGO_ERROR_INTERNAL, "Mongo pipeline machine entered invalid state"));
        return galay::kernel::MachineAction<result_type>::complete(std::move(*m_state->result));
    case Phase::SendCommands:
        return advanceSendCommands();
    case Phase::RecvReplies:
        return advanceRecvReplies();
    case Phase::Done:
        return galay::kernel::MachineAction<result_type>::complete(std::move(*m_state->result));
    }

    setError(MongoError(MONGO_ERROR_INTERNAL, "Unknown Mongo pipeline machine state"));
    return galay::kernel::MachineAction<result_type>::complete(std::move(*m_state->result));
}

void MongoPipelineAwaitable::Machine::onRead(
    std::expected<size_t, galay::kernel::IOError> result)
{
    applyReadResult(*m_state->client,
                    std::move(result),
                    MONGO_ERROR_RECV,
                    "Connection closed while receiving pipeline replies",
                    m_state->pending_error);
    if (m_state->pending_error.has_value()) {
        m_state->phase = Phase::Invalid;
        return;
    }
    m_state->phase = Phase::RecvReplies;
}

void MongoPipelineAwaitable::Machine::onWrite(
    std::expected<size_t, galay::kernel::IOError> result)
{
    applyWriteResult(std::move(result),
                     m_state->sent,
                     MONGO_ERROR_SEND,
                     "Connection closed during pipeline send",
                     m_state->pending_error);
    if (m_state->pending_error.has_value()) {
        m_state->phase = Phase::Invalid;
        return;
    }
    if (m_state->sent >= m_state->total_len) {
        m_state->phase = Phase::RecvReplies;
    } else {
        m_state->phase = Phase::SendCommands;
    }
}

galay::kernel::MachineAction<MongoPipelineAwaitable::Machine::result_type>
MongoPipelineAwaitable::Machine::advanceSendCommands()
{
    if (m_state->sent >= m_state->total_len) {
        m_state->phase = Phase::RecvReplies;
        return advance();
    }

    if (!prepareWriteWindow(m_state->write_iovecs,
                            m_state->write_iov_count,
                            m_state->write_scratch,
                            std::span<const SendSegment>(m_state->send_segments.data(),
                                                         m_state->send_segment_count),
                            m_state->sent,
                            m_state->pending_error)) {
        return advance();
    }

    return galay::kernel::MachineAction<result_type>::waitWritev(
        m_state->write_iovecs.data(),
        m_state->write_iov_count);
}

galay::kernel::MachineAction<MongoPipelineAwaitable::Machine::result_type>
MongoPipelineAwaitable::Machine::advanceRecvReplies()
{
    while (m_state->received < m_state->responses.size()) {
        auto parsed = AsyncMongoClientInternals::tryParseMessage(*m_state->client);
        if (!parsed.has_value()) {
            setError(std::move(parsed.error()));
            return galay::kernel::MachineAction<result_type>::complete(std::move(*m_state->result));
        }
        if (!parsed->has_value()) {
            if (!prepareReadWindow(*m_state->client,
                                   m_state->read_iovecs,
                                   m_state->read_iov_count,
                                   "No writable ring buffer space while receiving pipeline replies",
                                   m_state->pending_error)) {
                return advance();
            }
            return galay::kernel::MachineAction<result_type>::waitReadv(
                m_state->read_iovecs.data(),
                m_state->read_iov_count);
        }

        if (!storeResponse(std::move(parsed->value()))) {
            return galay::kernel::MachineAction<result_type>::complete(std::move(*m_state->result));
        }
        ++m_state->received;
    }

    m_state->phase = Phase::Done;
    m_state->result = std::move(m_state->responses);
    return galay::kernel::MachineAction<result_type>::complete(std::move(*m_state->result));
}

bool MongoPipelineAwaitable::Machine::storeResponse(protocol::MongoMessage message)
{
    const int32_t response_to = message.header.response_to;
    if (response_to <= 0) {
        setError(MongoError(MONGO_ERROR_PROTOCOL,
                            "Pipeline response has invalid responseTo"));
        return false;
    }

    const int64_t index_i64 =
        static_cast<int64_t>(response_to) - static_cast<int64_t>(m_state->first_request_id);
    if (index_i64 < 0 || index_i64 >= static_cast<int64_t>(m_state->responses.size())) {
        setError(MongoError(MONGO_ERROR_PROTOCOL,
                            "Pipeline responseTo does not match any in-flight requestId"));
        return false;
    }

    auto& slot = m_state->responses[static_cast<size_t>(index_i64)];
    if (slot.request_id != response_to) {
        setError(MongoError(MONGO_ERROR_PROTOCOL,
                            "Pipeline responseTo does not map to expected requestId"));
        return false;
    }
    if (slot.reply.has_value() || slot.error.has_value()) {
        setError(MongoError(MONGO_ERROR_PROTOCOL,
                            "Pipeline received duplicate response for the same requestId"));
        return false;
    }

    MongoReply reply(std::move(message.body));
    if (reply.ok()) {
        slot.reply = std::move(reply);
    } else {
        slot.error = makeServerError(std::move(reply), "Mongo pipeline command failed");
    }
    return true;
}

void MongoPipelineAwaitable::Machine::setError(MongoError error) noexcept
{
    m_state->result = std::unexpected(std::move(error));
    m_state->phase = Phase::Invalid;
}

MongoPipelineAwaitable::MongoPipelineAwaitable(AsyncMongoClient& client,
                                               std::string database,
                                               std::span<const MongoDocument> commands)
    : m_state(std::make_shared<SharedState>(client, std::move(database), commands))
    , m_inner(galay::kernel::AwaitableBuilder<Result>::fromStateMachine(
                  client.socket().controller(),
                  Machine(m_state))
                  .build())
{
}

bool MongoPipelineAwaitable::isInvalid() const
{
    return m_state != nullptr && m_state->phase == Phase::Invalid;
}

int32_t AsyncMongoClient::reserveRequestIdBlock(size_t count)
{
    if (count == 0) {
        count = 1;
    }

    if (m_next_request_id <= 0) {
        m_next_request_id = 1;
    }

    const int64_t max_request_id = std::numeric_limits<int32_t>::max();
    const int64_t first_candidate = static_cast<int64_t>(m_next_request_id);
    if (first_candidate + static_cast<int64_t>(count) - 1 > max_request_id) {
        m_next_request_id = 1;
    }

    const int32_t first = m_next_request_id;
    const int64_t next_candidate = static_cast<int64_t>(first) + static_cast<int64_t>(count);
    if (next_candidate > max_request_id) {
        m_next_request_id = 1;
    } else {
        m_next_request_id = static_cast<int32_t>(next_candidate);
    }

    return first;
}

int32_t AsyncMongoClient::nextRequestId()
{
    return reserveRequestIdBlock(1);
}

AsyncMongoClient::AsyncMongoClient(IOScheduler* scheduler,
                                   AsyncMongoConfig config,
                                   std::shared_ptr<MongoBufferProvider> buffer_provider)
    : m_config(std::move(config))
    , m_ring_buffer(m_config.buffer_size > 0 ? m_config.buffer_size
                                             : galay::kernel::RingBuffer::kDefaultCapacity,
                    std::move(buffer_provider))
    , m_pipeline_reserve_per_command(std::max<size_t>(32, m_config.pipeline_reserve_per_command))
{
    (void)scheduler;
    if (m_config.logger_name.empty()) {
        m_logger.ensure("MongoClientLogger");
    } else {
        m_logger.ensure(m_config.logger_name);
    }
}

AsyncMongoClient::AsyncMongoClient(AsyncMongoClient&& other) noexcept
    : m_is_closed(other.m_is_closed)
    , m_config(std::move(other.m_config))
    , m_socket(std::move(other.m_socket))
    , m_ring_buffer(std::move(other.m_ring_buffer))
    , m_decode_scratch(std::move(other.m_decode_scratch))
    , m_ping_template_db(std::move(other.m_ping_template_db))
    , m_ping_encoded_template(std::move(other.m_ping_encoded_template))
    , m_pipeline_reserve_per_command(other.m_pipeline_reserve_per_command)
    , m_next_request_id(other.m_next_request_id)
    , m_logger(std::move(other.m_logger))
{
    other.m_is_closed = true;
}

AsyncMongoClient& AsyncMongoClient::operator=(AsyncMongoClient&& other) noexcept
{
    if (this != &other) {
        if (!m_is_closed) {
            m_is_closed = true;
            m_socket.close();
        }
        m_is_closed = other.m_is_closed;
        m_config = std::move(other.m_config);
        m_socket = std::move(other.m_socket);
        m_ring_buffer = std::move(other.m_ring_buffer);
        m_decode_scratch = std::move(other.m_decode_scratch);
        m_ping_template_db = std::move(other.m_ping_template_db);
        m_ping_encoded_template = std::move(other.m_ping_encoded_template);
        m_pipeline_reserve_per_command = other.m_pipeline_reserve_per_command;
        m_next_request_id = other.m_next_request_id;
        m_logger = std::move(other.m_logger);
        other.m_is_closed = true;
    }
    return *this;
}

MongoConnectAwaitable AsyncMongoClient::connect(MongoConfig config)
{
    return MongoConnectAwaitable(*this, std::move(config));
}

MongoConnectAwaitable AsyncMongoClient::connect(std::string_view host,
                                                uint16_t port,
                                                std::string_view database)
{
    MongoConfig config;
    config.host.assign(host.data(), host.size());
    config.port = port;
    config.database.assign(database.data(), database.size());
    return connect(std::move(config));
}

MongoCommandAwaitable AsyncMongoClient::command(std::string database, MongoDocument command)
{
    return MongoCommandAwaitable(*this, std::move(database), std::move(command));
}

MongoCommandAwaitable AsyncMongoClient::ping(std::string database)
{
    MongoDocument ping_doc;
    ping_doc.append("ping", int32_t(1));
    return command(std::move(database), std::move(ping_doc));
}

MongoPipelineAwaitable AsyncMongoClient::pipeline(std::string database,
                                                  std::span<const MongoDocument> commands)
{
    return MongoPipelineAwaitable(*this, std::move(database), commands);
}

} // namespace galay::mongo
