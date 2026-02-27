#include "AsyncMongoClient.h"
#include "galay-mongo/base/SocketOptions.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstring>
#include <limits>
#include <unordered_map>

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

void patchRequestId(std::string& encoded_request, int32_t request_id)
{
    if (encoded_request.size() >= 8) {
        writeInt32LE(encoded_request.data() + 4, request_id);
    }
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

std::expected<std::vector<uint8_t>, MongoError>
sha256(const std::vector<uint8_t>& data)
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
    driver.append("version", "0.1.0");

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

constexpr size_t kAsyncMaxMessageSize = 128 * 1024 * 1024;

std::expected<std::optional<DecodeView>, MongoError>
prepareDecodeView(const std::vector<struct iovec>& read_iovecs, std::string& parse_buffer)
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

bool isSimplePingCommand(const MongoDocument& command, const std::string& database)
{
    if (command.size() != 2) {
        return false;
    }

    const MongoValue* ping = command.find("ping");
    const MongoValue* db = command.find("$db");
    if (ping == nullptr || db == nullptr) {
        return false;
    }
    if (!db->isString() || db->toString() != database) {
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

} // namespace

MongoConnectAwaitable::ProtocolFlowAwaitable::ProtocolFlowAwaitable(MongoConnectAwaitable* owner)
    : m_owner(owner)
    , m_connect_ctx(Host(IPType::IPV4, owner->m_config.host, owner->m_config.port))
    , m_send_ctx(nullptr, 0)
    , m_recv_ctx({})
{
}

IOEventType MongoConnectAwaitable::ProtocolFlowAwaitable::type() const
{
    if (m_owner->m_lifecycle != Lifecycle::Running) {
        return IOEventType::INVALID;
    }

    switch (m_owner->m_step) {
    case Step::Connecting:
        return IOEventType::CONNECT;
    case Step::Sending:
        return IOEventType::SEND;
    case Step::Receiving:
        return IOEventType::RECV;
    }

    return IOEventType::INVALID;
}

bool MongoConnectAwaitable::ProtocolFlowAwaitable::handleConnectResult()
{
    if (!m_connect_ctx.m_result.has_value()) {
        m_owner->setConnectError(m_connect_ctx.m_result.error());
        return true;
    }

    const int fd = m_owner->m_client.m_socket.handle().fd;
    trySetTcpNoDelay(fd, m_owner->m_config.tcp_nodelay);

    m_owner->m_client.m_socket.option().handleNonBlock();
    m_owner->m_step = Step::Sending;
    return false;
}

bool MongoConnectAwaitable::ProtocolFlowAwaitable::handleSendResult()
{
    if (!m_send_ctx.m_result.has_value()) {
        m_owner->setSendError(m_send_ctx.m_result.error());
        return true;
    }

    const size_t sent_once = m_send_ctx.m_result.value();
    if (sent_once == 0) {
        m_owner->setError(MongoError(MONGO_ERROR_CONNECTION_CLOSED,
                                     "Connection closed during connect/auth request send"));
        return true;
    }

    m_owner->m_sent += sent_once;
    if (m_owner->m_sent >= m_owner->m_encoded_request.size()) {
        m_owner->m_step = Step::Receiving;
    }
    return false;
}

bool MongoConnectAwaitable::ProtocolFlowAwaitable::prepareReadIovecs()
{
    m_recv_ctx.m_iovecs = m_owner->m_client.m_ring_buffer.getWriteIovecs();
    if (m_recv_ctx.m_iovecs.empty() || m_recv_ctx.m_iovecs.front().iov_len == 0) {
        m_owner->setError(MongoError(MONGO_ERROR_RECV,
                                     "No writable ring buffer space while receiving connect/auth reply"));
        return false;
    }
    return true;
}

bool MongoConnectAwaitable::ProtocolFlowAwaitable::parseAndAdvance()
{
    auto parse_result = m_owner->tryParseFromRingBuffer();
    if (!parse_result.has_value()) {
        m_owner->setError(std::move(parse_result.error()));
        return true;
    }

    if (!parse_result.value()) {
        return false;
    }

    if (m_owner->m_lifecycle == Lifecycle::Running) {
        m_owner->m_step = Step::Sending;
        return false;
    }

    return true;
}

bool MongoConnectAwaitable::ProtocolFlowAwaitable::handleReadResult()
{
    if (!m_recv_ctx.m_result.has_value()) {
        m_owner->setRecvError(m_recv_ctx.m_result.error());
        return true;
    }

    const size_t n = m_recv_ctx.m_result.value();
    if (n == 0) {
        m_owner->setError(MongoError(MONGO_ERROR_CONNECTION_CLOSED,
                                     "Connection closed while receiving connect/auth reply"));
        return true;
    }

    m_owner->m_client.m_ring_buffer.produce(n);
    return parseAndAdvance();
}

#ifdef USE_IOURING
bool MongoConnectAwaitable::ProtocolFlowAwaitable::handleComplete(struct io_uring_cqe* cqe,
                                                                  GHandle handle)
{
    if (m_owner->m_lifecycle != Lifecycle::Running) {
        return true;
    }

    if (cqe == nullptr) {
        return false;
    }

    switch (m_owner->m_step) {
    case Step::Connecting:
        if (!m_connect_ctx.handleComplete(cqe, handle)) {
            return false;
        }
        return handleConnectResult();

    case Step::Sending:
        if (m_owner->m_sent >= m_owner->m_encoded_request.size()) {
            m_owner->m_step = Step::Receiving;
            return false;
        }
        m_send_ctx.m_buffer = m_owner->m_encoded_request.data() + m_owner->m_sent;
        m_send_ctx.m_length = m_owner->m_encoded_request.size() - m_owner->m_sent;
        if (!m_send_ctx.handleComplete(cqe, handle)) {
            return false;
        }
        return handleSendResult();

    case Step::Receiving:
        if (parseAndAdvance()) {
            return true;
        }
        if (m_owner->m_step == Step::Sending) {
            return false;
        }
        if (!prepareReadIovecs()) {
            return true;
        }
        if (!m_recv_ctx.handleComplete(cqe, handle)) {
            return false;
        }
        return handleReadResult();
    }

    return true;
}
#else
bool MongoConnectAwaitable::ProtocolFlowAwaitable::handleComplete(GHandle handle)
{
    while (m_owner->m_lifecycle == Lifecycle::Running) {
        switch (m_owner->m_step) {
        case Step::Connecting:
            if (!m_connect_ctx.handleComplete(handle)) {
                return false;
            }
            if (handleConnectResult()) {
                return true;
            }
            break;

        case Step::Sending:
            if (m_owner->m_sent >= m_owner->m_encoded_request.size()) {
                m_owner->m_step = Step::Receiving;
                break;
            }
            m_send_ctx.m_buffer = m_owner->m_encoded_request.data() + m_owner->m_sent;
            m_send_ctx.m_length = m_owner->m_encoded_request.size() - m_owner->m_sent;
            if (!m_send_ctx.handleComplete(handle)) {
                return false;
            }
            if (handleSendResult()) {
                return true;
            }
            break;

        case Step::Receiving:
            if (parseAndAdvance()) {
                return true;
            }
            if (m_owner->m_step == Step::Sending) {
                break;
            }
            if (!prepareReadIovecs()) {
                return true;
            }
            if (!m_recv_ctx.handleComplete(handle)) {
                return false;
            }
            if (handleReadResult()) {
                return true;
            }
            break;
        }
    }

    return true;
}
#endif

MongoConnectAwaitable::MongoConnectAwaitable(AsyncMongoClient& client, MongoConfig config)
    : CustomAwaitable(client.m_socket.controller())
    , m_client(client)
    , m_config(std::move(config))
    , m_flow_awaitable(this)
{
    m_lifecycle = Lifecycle::Running;
    m_step = Step::Connecting;
    m_auth_phase = AuthPhase::HelloReply;
    m_auth_enabled = !m_config.username.empty() || !m_config.password.empty();
    m_auth_db = !m_config.auth_database.empty()
        ? m_config.auth_database
        : (!m_config.database.empty() ? m_config.database : "admin");

    if ((m_config.username.empty() && !m_config.password.empty()) ||
        (!m_config.username.empty() && m_config.password.empty())) {
        setError(MongoError(MONGO_ERROR_INVALID_PARAM,
                            "Both username and password are required for SCRAM authentication"));
        return;
    }

    MongoDocument hello;
    hello.append("hello", int32_t(1));
    hello.append("helloOk", true);
    const std::string hello_db =
        m_config.hello_database.empty() ? std::string("admin") : m_config.hello_database;
    hello.append("$db", hello_db);
    hello.append("client", buildClientMetadata(m_config.app_name));

    m_encoded_request.clear();
    protocol::MongoProtocol::appendOpMsg(m_encoded_request, m_client.nextRequestId(), hello);
    m_sent = 0;

    addTask(IOEventType::CONNECT, &m_flow_awaitable);
}

void MongoConnectAwaitable::reset() noexcept
{
    m_lifecycle = Lifecycle::Invalid;
    m_step = Step::Connecting;
    m_encoded_request.clear();
    m_sent = 0;
    m_auth_enabled = false;
    m_auth_phase = AuthPhase::HelloReply;
    m_auth_db.clear();
    m_auth_conversation_id = 0;
    m_auth_client_nonce.clear();
    m_auth_client_first_bare.clear();
    m_auth_expected_server_signature.clear();
    m_chain_error.reset();
}

void MongoConnectAwaitable::setError(MongoError error) noexcept
{
    m_chain_error = std::move(error);
    m_lifecycle = Lifecycle::Invalid;
}

void MongoConnectAwaitable::setConnectError(const IOError& io_error) noexcept
{
    setError(mapIoError(io_error, MONGO_ERROR_CONNECTION));
}

void MongoConnectAwaitable::setSendError(const IOError& io_error) noexcept
{
    setError(mapIoError(io_error, MONGO_ERROR_SEND));
}

void MongoConnectAwaitable::setRecvError(const IOError& io_error) noexcept
{
    setError(mapIoError(io_error, MONGO_ERROR_RECV));
}

std::expected<bool, MongoError> MongoConnectAwaitable::tryParseFromRingBuffer()
{
    auto read_iovecs = m_client.m_ring_buffer.getReadIovecs();
    if (read_iovecs.empty()) {
        return false;
    }

    auto decode_view_or_err = prepareDecodeView(read_iovecs, m_client.m_decode_scratch);
    if (!decode_view_or_err) {
        return std::unexpected(decode_view_or_err.error());
    }
    if (!decode_view_or_err->has_value()) {
        return false;
    }

    const DecodeView& view = decode_view_or_err->value();
    auto message =
        protocol::MongoProtocol::decodeMessage(view.data, static_cast<size_t>(view.msg_len));
    if (!message) {
        return std::unexpected(message.error());
    }

    m_client.m_ring_buffer.consume(static_cast<size_t>(view.msg_len));

    MongoReply reply(std::move(message->body));
    if (!reply.ok()) {
        return std::unexpected(MongoError(MONGO_ERROR_SERVER,
                                          reply.errorCode(),
                                          reply.errorMessage().empty()
                                              ? "Mongo connect/auth command failed"
                                              : reply.errorMessage()));
    }

    switch (m_auth_phase) {
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
                                      "Unknown auth phase in MongoConnectAwaitable"));
}

std::expected<bool, MongoError> MongoConnectAwaitable::handleHelloReply(MongoReply&&)
{
    if (!m_auth_enabled) {
        m_client.m_is_closed = false;
        m_lifecycle = Lifecycle::Done;
        MongoLogInfo(m_client.m_logger.get(),
                     "Mongo connected successfully to {}:{}",
                     m_config.host,
                     m_config.port);
        return true;
    }

    auto nonce_or_err = generateClientNonce();
    if (!nonce_or_err) {
        return std::unexpected(nonce_or_err.error());
    }

    m_auth_client_nonce = std::move(nonce_or_err.value());
    m_auth_client_first_bare =
        "n=" + escapeScramUsername(m_config.username) + ",r=" + m_auth_client_nonce;
    const std::string client_first_message = "n,," + m_auth_client_first_bare;

    MongoValue::Binary payload(client_first_message.begin(), client_first_message.end());

    MongoDocument sasl_start;
    sasl_start.append("saslStart", int32_t(1));
    sasl_start.append("mechanism", "SCRAM-SHA-256");
    sasl_start.append("payload", std::move(payload));
    sasl_start.append("autoAuthorize", int32_t(1));
    sasl_start.append("$db", m_auth_db);

    m_encoded_request.clear();
    protocol::MongoProtocol::appendOpMsg(m_encoded_request,
                                         m_client.nextRequestId(),
                                         sasl_start);
    m_sent = 0;
    m_auth_phase = AuthPhase::SaslStartReply;
    return true;
}

std::expected<bool, MongoError> MongoConnectAwaitable::handleSaslStartReply(MongoReply&& reply)
{
    const auto& doc = reply.document();

    auto conversation_id_or_err = readConversationId(doc);
    if (!conversation_id_or_err) {
        return std::unexpected(conversation_id_or_err.error());
    }
    m_auth_conversation_id = conversation_id_or_err.value();

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
    if (server_nonce.rfind(m_auth_client_nonce, 0) != 0) {
        return std::unexpected(MongoError(MONGO_ERROR_AUTH,
                                          "SCRAM server nonce does not include client nonce"));
    }

    int iterations = 0;
    const auto parse_iter_result = std::from_chars(iter_it->second.data(),
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
    const std::string auth_message = m_auth_client_first_bare + "," +
                                     server_first_message + "," +
                                     client_final_without_proof;

    auto salted_password = pbkdf2HmacSha256(m_config.password, salt_or_err.value(), iterations);
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
    m_auth_expected_server_signature = base64Encode(server_signature.value());
    if (m_auth_expected_server_signature.empty()) {
        return std::unexpected(MongoError(MONGO_ERROR_AUTH,
                                          "Failed to encode SCRAM server signature"));
    }

    const std::string client_final_message =
        client_final_without_proof + ",p=" + base64Encode(client_proof);

    MongoValue::Binary continue_payload(client_final_message.begin(), client_final_message.end());
    MongoDocument sasl_continue;
    sasl_continue.append("saslContinue", int32_t(1));
    sasl_continue.append("conversationId", m_auth_conversation_id);
    sasl_continue.append("payload", std::move(continue_payload));
    sasl_continue.append("$db", m_auth_db);

    m_encoded_request.clear();
    protocol::MongoProtocol::appendOpMsg(m_encoded_request,
                                         m_client.nextRequestId(),
                                         sasl_continue);
    m_sent = 0;
    m_auth_phase = AuthPhase::SaslContinueReply;
    return true;
}

std::expected<bool, MongoError> MongoConnectAwaitable::handleSaslContinueReply(MongoReply&& reply)
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

    if (verifier_it->second != m_auth_expected_server_signature) {
        return std::unexpected(MongoError(MONGO_ERROR_AUTH,
                                          "SCRAM server signature mismatch"));
    }

    if (doc.getBool("done", false)) {
        m_client.m_is_closed = false;
        m_lifecycle = Lifecycle::Done;
        MongoLogInfo(m_client.m_logger.get(),
                     "Mongo connected and authenticated successfully to {}:{}",
                     m_config.host,
                     m_config.port);
        return true;
    }

    MongoDocument final_continue;
    final_continue.append("saslContinue", int32_t(1));
    final_continue.append("conversationId", m_auth_conversation_id);
    final_continue.append("payload", MongoValue::Binary{});
    final_continue.append("$db", m_auth_db);

    m_encoded_request.clear();
    protocol::MongoProtocol::appendOpMsg(m_encoded_request,
                                         m_client.nextRequestId(),
                                         final_continue);
    m_sent = 0;
    m_auth_phase = AuthPhase::SaslFinalReply;
    return true;
}

std::expected<bool, MongoError> MongoConnectAwaitable::handleSaslFinalReply(MongoReply&& reply)
{
    const auto& doc = reply.document();
    if (!doc.getBool("done", false)) {
        return std::unexpected(MongoError(MONGO_ERROR_AUTH,
                                          "SCRAM authentication not finished"));
    }

    m_client.m_is_closed = false;
    m_lifecycle = Lifecycle::Done;
    MongoLogInfo(m_client.m_logger.get(),
                 "Mongo connected and authenticated successfully to {}:{}",
                 m_config.host,
                 m_config.port);
    return true;
}

std::expected<bool, MongoError> MongoConnectAwaitable::await_resume()
{
    onCompleted();

    if (m_chain_error.has_value()) {
        auto error = std::move(m_chain_error.value());
        reset();
        return std::unexpected(std::move(error));
    }

    if (m_lifecycle != Lifecycle::Done) {
        reset();
        return std::unexpected(MongoError(MONGO_ERROR_INTERNAL,
                                          "MongoConnectAwaitable resumed before final completion"));
    }

    reset();
    return true;
}

MongoCommandAwaitable::ProtocolFlowAwaitable::ProtocolFlowAwaitable(MongoCommandAwaitable* owner)
    : m_owner(owner)
    , m_send_ctx(nullptr, 0)
    , m_recv_ctx({})
{
}

IOEventType MongoCommandAwaitable::ProtocolFlowAwaitable::type() const
{
    if (m_owner->m_lifecycle != Lifecycle::Running) {
        return IOEventType::INVALID;
    }

    switch (m_owner->m_step) {
    case Step::Sending:
        return IOEventType::SEND;
    case Step::Receiving:
        return IOEventType::RECV;
    }

    return IOEventType::INVALID;
}

bool MongoCommandAwaitable::ProtocolFlowAwaitable::handleSendResult()
{
    if (!m_send_ctx.m_result.has_value()) {
        m_owner->setSendError(m_send_ctx.m_result.error());
        return true;
    }

    const size_t sent_once = m_send_ctx.m_result.value();
    if (sent_once == 0) {
        m_owner->setError(MongoError(MONGO_ERROR_CONNECTION_CLOSED,
                                     "Connection closed during command send"));
        return true;
    }

    m_owner->m_sent += sent_once;
    if (m_owner->m_sent >= m_owner->m_encoded_request.size()) {
        m_owner->m_step = Step::Receiving;
    }
    return false;
}

bool MongoCommandAwaitable::ProtocolFlowAwaitable::prepareReadIovecs()
{
    m_recv_ctx.m_iovecs = m_owner->m_client.m_ring_buffer.getWriteIovecs();
    if (m_recv_ctx.m_iovecs.empty() || m_recv_ctx.m_iovecs.front().iov_len == 0) {
        m_owner->setError(MongoError(MONGO_ERROR_RECV,
                                     "No writable ring buffer space while receiving command reply"));
        return false;
    }
    return true;
}

bool MongoCommandAwaitable::ProtocolFlowAwaitable::parseAndAdvance()
{
    auto parse_result = m_owner->tryParseFromRingBuffer();
    if (!parse_result.has_value()) {
        m_owner->setError(std::move(parse_result.error()));
        return true;
    }
    return parse_result.value();
}

bool MongoCommandAwaitable::ProtocolFlowAwaitable::handleReadResult()
{
    if (!m_recv_ctx.m_result.has_value()) {
        m_owner->setRecvError(m_recv_ctx.m_result.error());
        return true;
    }

    const size_t n = m_recv_ctx.m_result.value();
    if (n == 0) {
        m_owner->setError(MongoError(MONGO_ERROR_CONNECTION_CLOSED,
                                     "Connection closed while receiving command reply"));
        return true;
    }

    m_owner->m_client.m_ring_buffer.produce(n);
    return parseAndAdvance();
}

#ifdef USE_IOURING
bool MongoCommandAwaitable::ProtocolFlowAwaitable::handleComplete(struct io_uring_cqe* cqe,
                                                                  GHandle handle)
{
    if (m_owner->m_lifecycle != Lifecycle::Running) {
        return true;
    }

    if (cqe == nullptr) {
        return false;
    }

    switch (m_owner->m_step) {
    case Step::Sending:
        if (m_owner->m_sent >= m_owner->m_encoded_request.size()) {
            m_owner->m_step = Step::Receiving;
            return false;
        }
        m_send_ctx.m_buffer = m_owner->m_encoded_request.data() + m_owner->m_sent;
        m_send_ctx.m_length = m_owner->m_encoded_request.size() - m_owner->m_sent;
        if (!m_send_ctx.handleComplete(cqe, handle)) {
            return false;
        }
        return handleSendResult();

    case Step::Receiving:
        if (parseAndAdvance()) {
            return true;
        }
        if (!prepareReadIovecs()) {
            return true;
        }
        if (!m_recv_ctx.handleComplete(cqe, handle)) {
            return false;
        }
        return handleReadResult();
    }

    return true;
}
#else
bool MongoCommandAwaitable::ProtocolFlowAwaitable::handleComplete(GHandle handle)
{
    while (m_owner->m_lifecycle == Lifecycle::Running) {
        switch (m_owner->m_step) {
        case Step::Sending:
            if (m_owner->m_sent >= m_owner->m_encoded_request.size()) {
                m_owner->m_step = Step::Receiving;
                break;
            }
            m_send_ctx.m_buffer = m_owner->m_encoded_request.data() + m_owner->m_sent;
            m_send_ctx.m_length = m_owner->m_encoded_request.size() - m_owner->m_sent;
            if (!m_send_ctx.handleComplete(handle)) {
                return false;
            }
            if (handleSendResult()) {
                return true;
            }
            break;

        case Step::Receiving:
            if (parseAndAdvance()) {
                return true;
            }
            if (!prepareReadIovecs()) {
                return true;
            }
            if (!m_recv_ctx.handleComplete(handle)) {
                return false;
            }
            if (handleReadResult()) {
                return true;
            }
            break;
        }
    }

    return true;
}
#endif

MongoCommandAwaitable::MongoCommandAwaitable(AsyncMongoClient& client,
                                             std::string database,
                                             MongoDocument command)
    : MongoCommandAwaitable(client)
{
    arm(std::move(database), std::move(command));
}

MongoCommandAwaitable::MongoCommandAwaitable(AsyncMongoClient& client)
    : CustomAwaitable(client.m_socket.controller())
    , m_client(client)
    , m_flow_awaitable(this)
{
}

void MongoCommandAwaitable::reset() noexcept
{
    m_lifecycle = Lifecycle::Invalid;
    m_step = Step::Sending;
    m_encoded_request.clear();
    m_sent = 0;
    m_reply.reset();
    m_chain_error.reset();
}

void MongoCommandAwaitable::arm(std::string database, MongoDocument command)
{
    m_lifecycle = Lifecycle::Running;
    m_step = Step::Sending;
    m_sent = 0;
    m_reply.reset();
    m_chain_error.reset();

    if (!command.has("$db")) {
        command.append("$db", database);
    }
    if (isSimplePingCommand(command, database)) {
        if (m_ping_encoded_template.empty() || m_ping_template_db != database) {
            m_ping_template_db = database;
            m_ping_encoded_template.clear();
            protocol::MongoProtocol::appendOpMsg(m_ping_encoded_template, 0, command);
        }
        m_encoded_request = m_ping_encoded_template;
        m_request_id = m_client.nextRequestId();
        patchRequestId(m_encoded_request, m_request_id);
    } else {
        m_encoded_request.clear();
        m_request_id = m_client.nextRequestId();
        protocol::MongoProtocol::appendOpMsg(m_encoded_request,
                                             m_request_id,
                                             command);
    }

    m_tasks.clear();
    m_cursor = 0;
    addTask(IOEventType::SEND, &m_flow_awaitable);
}

void MongoCommandAwaitable::armPing(std::string database)
{
    m_lifecycle = Lifecycle::Running;
    m_step = Step::Sending;
    m_sent = 0;
    m_reply.reset();
    m_chain_error.reset();

    if (m_ping_encoded_template.empty() || m_ping_template_db != database) {
        MongoDocument ping_doc;
        ping_doc.append("ping", int32_t(1));
        ping_doc.append("$db", database);
        m_ping_template_db = database;
        m_ping_encoded_template.clear();
        protocol::MongoProtocol::appendOpMsg(m_ping_encoded_template, 0, ping_doc);
    }

    m_encoded_request = m_ping_encoded_template;
    m_request_id = m_client.nextRequestId();
    patchRequestId(m_encoded_request, m_request_id);

    m_tasks.clear();
    m_cursor = 0;
    addTask(IOEventType::SEND, &m_flow_awaitable);
}

void MongoCommandAwaitable::setError(MongoError error) noexcept
{
    m_chain_error = std::move(error);
    m_lifecycle = Lifecycle::Invalid;
}

void MongoCommandAwaitable::setSendError(const IOError& io_error) noexcept
{
    setError(mapIoError(io_error, MONGO_ERROR_SEND));
}

void MongoCommandAwaitable::setRecvError(const IOError& io_error) noexcept
{
    setError(mapIoError(io_error, MONGO_ERROR_RECV));
}

std::expected<bool, MongoError> MongoCommandAwaitable::tryParseFromRingBuffer()
{
    auto read_iovecs = m_client.m_ring_buffer.getReadIovecs();
    if (read_iovecs.empty()) {
        return false;
    }

    auto decode_view_or_err = prepareDecodeView(read_iovecs, m_client.m_decode_scratch);
    if (!decode_view_or_err) {
        return std::unexpected(decode_view_or_err.error());
    }
    if (!decode_view_or_err->has_value()) {
        return false;
    }

    const DecodeView& view = decode_view_or_err->value();
    auto message =
        protocol::MongoProtocol::decodeMessage(view.data, static_cast<size_t>(view.msg_len));
    if (!message) {
        return std::unexpected(message.error());
    }

    if (message->header.response_to != m_request_id) {
        return std::unexpected(MongoError(MONGO_ERROR_PROTOCOL,
                                          "Response responseTo does not match sent requestId"));
    }

    m_client.m_ring_buffer.consume(static_cast<size_t>(view.msg_len));

    MongoReply reply(std::move(message->body));
    if (!reply.ok()) {
        return std::unexpected(MongoError(MONGO_ERROR_SERVER,
                                          reply.errorCode(),
                                          reply.errorMessage().empty()
                                              ? "Mongo command failed"
                                              : reply.errorMessage()));
    }

    m_reply = std::move(reply);
    m_lifecycle = Lifecycle::Done;
    return true;
}

std::expected<MongoReply, MongoError> MongoCommandAwaitable::await_resume()
{
    onCompleted();

    if (m_chain_error.has_value()) {
        auto error = std::move(m_chain_error.value());
        reset();
        return std::unexpected(std::move(error));
    }

    if (m_lifecycle != Lifecycle::Done || !m_reply.has_value()) {
        reset();
        return std::unexpected(MongoError(MONGO_ERROR_INTERNAL,
                                          "MongoCommandAwaitable resumed before final completion"));
    }

    MongoReply reply = std::move(m_reply.value());
    reset();
    return reply;
}

MongoPipelineAwaitable::ProtocolFlowAwaitable::ProtocolFlowAwaitable(MongoPipelineAwaitable* owner)
    : m_owner(owner)
    , m_send_ctx(nullptr, 0)
    , m_recv_ctx({})
{
}

IOEventType MongoPipelineAwaitable::ProtocolFlowAwaitable::type() const
{
    if (m_owner->m_lifecycle != Lifecycle::Running) {
        return IOEventType::INVALID;
    }

    switch (m_owner->m_step) {
    case Step::Sending:
        return IOEventType::SEND;
    case Step::Receiving:
        return IOEventType::RECV;
    }

    return IOEventType::INVALID;
}

bool MongoPipelineAwaitable::ProtocolFlowAwaitable::handleSendResult()
{
    if (!m_send_ctx.m_result.has_value()) {
        m_owner->setSendError(m_send_ctx.m_result.error());
        return true;
    }

    const size_t sent_once = m_send_ctx.m_result.value();
    if (sent_once == 0) {
        m_owner->setError(MongoError(MONGO_ERROR_CONNECTION_CLOSED,
                                     "Connection closed during pipeline send"));
        return true;
    }

    m_owner->m_sent += sent_once;
    if (m_owner->m_sent >= m_owner->m_encoded_batch.size()) {
        m_owner->m_step = Step::Receiving;
    }
    return false;
}

bool MongoPipelineAwaitable::ProtocolFlowAwaitable::prepareReadIovecs()
{
    m_recv_ctx.m_iovecs = m_owner->m_client.m_ring_buffer.getWriteIovecs();
    if (m_recv_ctx.m_iovecs.empty() || m_recv_ctx.m_iovecs.front().iov_len == 0) {
        m_owner->setError(MongoError(MONGO_ERROR_RECV,
                                     "No writable ring buffer space while receiving pipeline replies"));
        return false;
    }
    return true;
}

bool MongoPipelineAwaitable::ProtocolFlowAwaitable::parseAndAdvance()
{
    auto parse_result = m_owner->tryParseFromRingBuffer();
    if (!parse_result.has_value()) {
        m_owner->setError(std::move(parse_result.error()));
        return true;
    }
    return parse_result.value();
}

bool MongoPipelineAwaitable::ProtocolFlowAwaitable::handleReadResult()
{
    if (!m_recv_ctx.m_result.has_value()) {
        m_owner->setRecvError(m_recv_ctx.m_result.error());
        return true;
    }

    const size_t n = m_recv_ctx.m_result.value();
    if (n == 0) {
        m_owner->setError(MongoError(MONGO_ERROR_CONNECTION_CLOSED,
                                     "Connection closed while receiving pipeline replies"));
        return true;
    }

    m_owner->m_client.m_ring_buffer.produce(n);
    return parseAndAdvance();
}

#ifdef USE_IOURING
bool MongoPipelineAwaitable::ProtocolFlowAwaitable::handleComplete(struct io_uring_cqe* cqe,
                                                                   GHandle handle)
{
    if (m_owner->m_lifecycle != Lifecycle::Running) {
        return true;
    }

    if (cqe == nullptr) {
        return false;
    }

    switch (m_owner->m_step) {
    case Step::Sending:
        if (m_owner->m_sent >= m_owner->m_encoded_batch.size()) {
            m_owner->m_step = Step::Receiving;
            return false;
        }
        m_send_ctx.m_buffer = m_owner->m_encoded_batch.data() + m_owner->m_sent;
        m_send_ctx.m_length = m_owner->m_encoded_batch.size() - m_owner->m_sent;
        if (!m_send_ctx.handleComplete(cqe, handle)) {
            return false;
        }
        return handleSendResult();

    case Step::Receiving:
        if (parseAndAdvance()) {
            return true;
        }
        if (!prepareReadIovecs()) {
            return true;
        }
        if (!m_recv_ctx.handleComplete(cqe, handle)) {
            return false;
        }
        return handleReadResult();
    }

    return true;
}
#else
bool MongoPipelineAwaitable::ProtocolFlowAwaitable::handleComplete(GHandle handle)
{
    while (m_owner->m_lifecycle == Lifecycle::Running) {
        switch (m_owner->m_step) {
        case Step::Sending:
            if (m_owner->m_sent >= m_owner->m_encoded_batch.size()) {
                m_owner->m_step = Step::Receiving;
                break;
            }
            m_send_ctx.m_buffer = m_owner->m_encoded_batch.data() + m_owner->m_sent;
            m_send_ctx.m_length = m_owner->m_encoded_batch.size() - m_owner->m_sent;
            if (!m_send_ctx.handleComplete(handle)) {
                return false;
            }
            if (handleSendResult()) {
                return true;
            }
            break;

        case Step::Receiving:
            if (parseAndAdvance()) {
                return true;
            }
            if (!prepareReadIovecs()) {
                return true;
            }
            if (!m_recv_ctx.handleComplete(handle)) {
                return false;
            }
            if (handleReadResult()) {
                return true;
            }
            break;
        }
    }

    return true;
}
#endif

MongoPipelineAwaitable::MongoPipelineAwaitable(AsyncMongoClient& client,
                                               std::string database,
                                               std::vector<MongoDocument> commands)
    : CustomAwaitable(client.m_socket.controller())
    , m_client(client)
    , m_flow_awaitable(this)
{
    arm(std::move(database), std::move(commands));
}

void MongoPipelineAwaitable::reset() noexcept
{
    m_lifecycle = Lifecycle::Invalid;
    m_step = Step::Sending;
    m_tasks.clear();
    m_cursor = 0;
    m_encoded_batch.clear();
    m_sent = 0;
    m_received = 0;
    m_first_request_id = 0;
    m_responses.clear();
    m_chain_error.reset();
}

void MongoPipelineAwaitable::arm(std::string database, std::vector<MongoDocument> commands)
{
    m_lifecycle = Lifecycle::Running;
    m_step = Step::Sending;
    m_tasks.clear();
    m_cursor = 0;
    m_sent = 0;
    m_received = 0;
    m_first_request_id = 0;
    m_responses.clear();
    m_chain_error.reset();

    if (commands.empty()) {
        setError(MongoError(MONGO_ERROR_INVALID_PARAM, "Pipeline commands must not be empty"));
        return;
    }
    if (commands.size() > static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
        setError(MongoError(MONGO_ERROR_INVALID_PARAM, "Pipeline commands exceed supported size"));
        return;
    }

    m_responses.resize(commands.size());
    m_encoded_batch.clear();
    m_encoded_batch.reserve(m_client.m_pipeline_reserve_per_command * commands.size());

    const int32_t first_request_id = m_client.reserveRequestIdBlock(commands.size());
    m_first_request_id = first_request_id;

    for (size_t i = 0; i < commands.size(); ++i) {
        auto& command = commands[i];
        if (!command.has("$db")) {
            command.append("$db", database);
        }

        const int32_t request_id =
            static_cast<int32_t>(static_cast<int64_t>(first_request_id) + static_cast<int64_t>(i));
        m_responses[i].request_id = request_id;
        protocol::MongoProtocol::appendOpMsg(m_encoded_batch, request_id, command);
    }

    addTask(IOEventType::SEND, &m_flow_awaitable);
}

void MongoPipelineAwaitable::setError(MongoError error) noexcept
{
    m_chain_error = std::move(error);
    m_lifecycle = Lifecycle::Invalid;
}

void MongoPipelineAwaitable::setSendError(const IOError& io_error) noexcept
{
    setError(mapIoError(io_error, MONGO_ERROR_SEND));
}

void MongoPipelineAwaitable::setRecvError(const IOError& io_error) noexcept
{
    setError(mapIoError(io_error, MONGO_ERROR_RECV));
}

std::expected<bool, MongoError> MongoPipelineAwaitable::tryParseFromRingBuffer()
{
    while (m_received < m_responses.size()) {
        auto read_iovecs = m_client.m_ring_buffer.getReadIovecs();
        if (read_iovecs.empty()) {
            return false;
        }

        auto decode_view_or_err = prepareDecodeView(read_iovecs, m_client.m_decode_scratch);
        if (!decode_view_or_err) {
            return std::unexpected(decode_view_or_err.error());
        }
        if (!decode_view_or_err->has_value()) {
            return false;
        }

        const DecodeView& view = decode_view_or_err->value();
        auto message =
            protocol::MongoProtocol::decodeMessage(view.data, static_cast<size_t>(view.msg_len));
        if (!message) {
            return std::unexpected(message.error());
        }

        m_client.m_ring_buffer.consume(static_cast<size_t>(view.msg_len));

        const int32_t response_to = message->header.response_to;
        if (response_to <= 0) {
            return std::unexpected(MongoError(MONGO_ERROR_PROTOCOL,
                                              "Pipeline response has invalid responseTo"));
        }

        const int64_t first_request_id = static_cast<int64_t>(m_first_request_id);
        const int64_t response_to_i64 = static_cast<int64_t>(response_to);
        const int64_t index_i64 = response_to_i64 - first_request_id;
        if (index_i64 < 0 || index_i64 >= static_cast<int64_t>(m_responses.size())) {
            return std::unexpected(MongoError(MONGO_ERROR_PROTOCOL,
                                              "Pipeline responseTo does not match any in-flight requestId"));
        }
        const size_t index = static_cast<size_t>(index_i64);
        auto& slot = m_responses[index];
        if (slot.request_id != response_to) {
            return std::unexpected(MongoError(MONGO_ERROR_PROTOCOL,
                                              "Pipeline responseTo does not map to expected requestId"));
        }
        if (slot.reply.has_value() || slot.error.has_value()) {
            return std::unexpected(MongoError(MONGO_ERROR_PROTOCOL,
                                              "Pipeline received duplicate response for the same requestId"));
        }

        MongoReply reply(std::move(message->body));
        if (reply.ok()) {
            slot.reply = std::move(reply);
        } else {
            slot.error = MongoError(MONGO_ERROR_SERVER,
                                    reply.errorCode(),
                                    reply.errorMessage().empty()
                                        ? "Mongo pipeline command failed"
                                        : reply.errorMessage());
        }

        ++m_received;
    }

    m_lifecycle = Lifecycle::Done;
    return true;
}

std::expected<std::vector<MongoPipelineResponse>, MongoError> MongoPipelineAwaitable::await_resume()
{
    onCompleted();

    if (m_chain_error.has_value()) {
        auto error = std::move(m_chain_error.value());
        reset();
        return std::unexpected(std::move(error));
    }

    if (m_lifecycle != Lifecycle::Done || m_received != m_responses.size()) {
        reset();
        return std::unexpected(MongoError(MONGO_ERROR_INTERNAL,
                                          "MongoPipelineAwaitable resumed before final completion"));
    }

    auto responses = std::move(m_responses);
    reset();
    return responses;
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

AsyncMongoClient::AsyncMongoClient(IOScheduler* scheduler, AsyncMongoConfig config)
    : m_ring_buffer(config.buffer_size > 0 ? config.buffer_size : RingBuffer::kDefaultCapacity)
    , m_pipeline_reserve_per_command(std::max<size_t>(32, config.pipeline_reserve_per_command))
{
    (void)scheduler;
    if (config.logger_name.empty()) {
        m_logger.ensure("MongoClientLogger");
    } else {
        m_logger.ensure(config.logger_name);
    }
}

AsyncMongoClient::AsyncMongoClient(AsyncMongoClient&& other) noexcept
    : m_is_closed(other.m_is_closed)
    , m_socket(std::move(other.m_socket))
    , m_ring_buffer(std::move(other.m_ring_buffer))
    , m_decode_scratch(std::move(other.m_decode_scratch))
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
        m_socket = std::move(other.m_socket);
        m_ring_buffer = std::move(other.m_ring_buffer);
        m_decode_scratch = std::move(other.m_decode_scratch);
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
    MongoCommandAwaitable awaitable(*this);
    if (awaitable.isInvalid()) {
        awaitable.arm(std::move(database), std::move(command));
    }
    return awaitable;
}

MongoCommandAwaitable AsyncMongoClient::ping(std::string database)
{
    MongoCommandAwaitable awaitable(*this);
    if (awaitable.isInvalid()) {
        awaitable.armPing(std::move(database));
    }
    return awaitable;
}

MongoPipelineAwaitable AsyncMongoClient::pipeline(std::string database,
                                                  std::vector<MongoDocument> commands)
{
    return MongoPipelineAwaitable(*this, std::move(database), std::move(commands));
}

} // namespace galay::mongo
