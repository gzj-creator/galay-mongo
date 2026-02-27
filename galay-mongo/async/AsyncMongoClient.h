#ifndef GALAY_MONGO_ASYNC_CLIENT_H
#define GALAY_MONGO_ASYNC_CLIENT_H

#include <galay-kernel/async/TcpSocket.h>
#include <galay-kernel/common/Buffer.h>
#include <galay-kernel/common/Error.h>
#include <galay-kernel/common/Host.hpp>
#include <galay-kernel/kernel/Coroutine.h>
#include <galay-kernel/kernel/IOScheduler.hpp>

#include <coroutine>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "AsyncMongoConfig.h"
#include "galay-mongo/base/MongoConfig.h"
#include "galay-mongo/base/MongoError.h"
#include "galay-mongo/base/MongoLog.h"
#include "galay-mongo/base/MongoValue.h"
#include "galay-mongo/protocol/MongoProtocol.h"

namespace galay::mongo
{

using galay::async::TcpSocket;
using galay::kernel::ConnectIOContext;
using galay::kernel::CustomAwaitable;
using galay::kernel::Host;
using galay::kernel::IOContextBase;
using galay::kernel::IOError;
using galay::kernel::IOScheduler;
using galay::kernel::IPType;
using galay::kernel::ReadvIOContext;
using galay::kernel::RingBuffer;
using galay::kernel::SendIOContext;

class AsyncMongoClient;

/// 异步连接 awaitable，处理 TCP 连接 + hello 握手 + SCRAM-SHA-256 认证的完整流程
/// co_await 后返回 std::expected<bool, MongoError>，true 表示连接成功
class MongoConnectAwaitable : public CustomAwaitable
{
public:
    class ProtocolFlowAwaitable : public IOContextBase
    {
    public:
        explicit ProtocolFlowAwaitable(MongoConnectAwaitable* owner);

        IOEventType type() const override;

#ifdef USE_IOURING
        bool handleComplete(struct io_uring_cqe* cqe, GHandle handle) override;
#else
        bool handleComplete(GHandle handle) override;
#endif

    private:
        bool handleConnectResult();
        bool handleSendResult();
        bool prepareReadIovecs();
        bool parseAndAdvance();
        bool handleReadResult();

        MongoConnectAwaitable* m_owner;
        ConnectIOContext m_connect_ctx;
        SendIOContext m_send_ctx;
        ReadvIOContext m_recv_ctx;
    };

    MongoConnectAwaitable(AsyncMongoClient& client, MongoConfig config);

    bool await_ready() const noexcept { return false; }
    using CustomAwaitable::await_suspend;
    std::expected<bool, MongoError> await_resume();

    bool isInvalid() const { return m_lifecycle == Lifecycle::Invalid; }

private:
    enum class Lifecycle {
        Invalid,
        Running,
        Done
    };

    enum class AuthPhase {
        HelloReply,
        SaslStartReply,
        SaslContinueReply,
        SaslFinalReply,
    };
    enum class Step {
        Connecting,
        Sending,
        Receiving,
    };

    void reset() noexcept;
    void setError(MongoError error) noexcept;
    void setConnectError(const IOError& io_error) noexcept;
    void setSendError(const IOError& io_error) noexcept;
    void setRecvError(const IOError& io_error) noexcept;
    std::expected<bool, MongoError> tryParseFromRingBuffer();
    std::expected<bool, MongoError> handleHelloReply(MongoReply&& reply);
    std::expected<bool, MongoError> handleSaslStartReply(MongoReply&& reply);
    std::expected<bool, MongoError> handleSaslContinueReply(MongoReply&& reply);
    std::expected<bool, MongoError> handleSaslFinalReply(MongoReply&& reply);

    AsyncMongoClient& m_client;
    MongoConfig m_config;
    std::string m_encoded_request;
    size_t m_sent = 0;
    bool m_auth_enabled = false;
    AuthPhase m_auth_phase = AuthPhase::HelloReply;
    std::string m_auth_db;
    int32_t m_auth_conversation_id = 0;
    std::string m_auth_client_nonce;
    std::string m_auth_client_first_bare;
    std::string m_auth_expected_server_signature;
    Lifecycle m_lifecycle = Lifecycle::Invalid;
    Step m_step = Step::Connecting;

    ProtocolFlowAwaitable m_flow_awaitable;
    std::optional<MongoError> m_chain_error;
};

/// 异步命令 awaitable，发送单条命令并等待响应
/// co_await 后返回 std::expected<MongoReply, MongoError>
class MongoCommandAwaitable : public CustomAwaitable
{
public:
    class ProtocolFlowAwaitable : public IOContextBase
    {
    public:
        explicit ProtocolFlowAwaitable(MongoCommandAwaitable* owner);

        IOEventType type() const override;

#ifdef USE_IOURING
        bool handleComplete(struct io_uring_cqe* cqe, GHandle handle) override;
#else
        bool handleComplete(GHandle handle) override;
#endif

    private:
        bool handleSendResult();
        bool prepareReadIovecs();
        bool parseAndAdvance();
        bool handleReadResult();

        MongoCommandAwaitable* m_owner;
        SendIOContext m_send_ctx;
        ReadvIOContext m_recv_ctx;
    };

    MongoCommandAwaitable(AsyncMongoClient& client,
                          std::string database,
                          MongoDocument command);
    explicit MongoCommandAwaitable(AsyncMongoClient& client);

    bool await_ready() const noexcept { return false; }
    using CustomAwaitable::await_suspend;
    std::expected<MongoReply, MongoError> await_resume();

    bool isInvalid() const { return m_lifecycle == Lifecycle::Invalid; }

private:
    friend class AsyncMongoClient;

    enum class Lifecycle {
        Invalid,
        Running,
        Done
    };
    enum class Step {
        Sending,
        Receiving,
    };

    void reset() noexcept;
    void arm(std::string database, MongoDocument command);
    void armPing(std::string database);
    void setError(MongoError error) noexcept;
    void setSendError(const IOError& io_error) noexcept;
    void setRecvError(const IOError& io_error) noexcept;
    std::expected<bool, MongoError> tryParseFromRingBuffer();

    AsyncMongoClient& m_client;
    std::string m_encoded_request;
    size_t m_sent = 0;
    int32_t m_request_id = 0;
    Lifecycle m_lifecycle = Lifecycle::Invalid;
    Step m_step = Step::Sending;
    std::optional<MongoReply> m_reply;
    std::string m_ping_template_db;
    std::string m_ping_encoded_template;

    ProtocolFlowAwaitable m_flow_awaitable;
    std::optional<MongoError> m_chain_error;
};

/// 管线化响应，包含请求 ID 和对应的响应或错误
struct MongoPipelineResponse
{
    int32_t request_id = 0;                  ///< 对应的请求 ID
    std::optional<MongoReply> reply;         ///< 成功时的响应
    std::optional<MongoError> error;         ///< 失败时的错误

    /// 判断该请求是否成功
    bool ok() const { return reply.has_value(); }
};

/// 异步管线化 awaitable，批量发送多条命令并收集所有响应
/// co_await 后返回 std::expected<std::vector<MongoPipelineResponse>, MongoError>
class MongoPipelineAwaitable : public CustomAwaitable
{
public:
    class ProtocolFlowAwaitable : public IOContextBase
    {
    public:
        explicit ProtocolFlowAwaitable(MongoPipelineAwaitable* owner);

        IOEventType type() const override;

#ifdef USE_IOURING
        bool handleComplete(struct io_uring_cqe* cqe, GHandle handle) override;
#else
        bool handleComplete(GHandle handle) override;
#endif

    private:
        bool handleSendResult();
        bool prepareReadIovecs();
        bool parseAndAdvance();
        bool handleReadResult();

        MongoPipelineAwaitable* m_owner;
        SendIOContext m_send_ctx;
        ReadvIOContext m_recv_ctx;
    };

    MongoPipelineAwaitable(AsyncMongoClient& client,
                           std::string database,
                           std::vector<MongoDocument> commands);

    bool await_ready() const noexcept { return false; }
    using CustomAwaitable::await_suspend;
    std::expected<std::vector<MongoPipelineResponse>, MongoError> await_resume();

    bool isInvalid() const { return m_lifecycle == Lifecycle::Invalid; }

private:
    friend class AsyncMongoClient;

    enum class Lifecycle {
        Invalid,
        Running,
        Done
    };
    enum class Step {
        Sending,
        Receiving,
    };

    void reset() noexcept;
    void arm(std::string database, std::vector<MongoDocument> commands);
    void setError(MongoError error) noexcept;
    void setSendError(const IOError& io_error) noexcept;
    void setRecvError(const IOError& io_error) noexcept;
    std::expected<bool, MongoError> tryParseFromRingBuffer();

    AsyncMongoClient& m_client;
    std::string m_encoded_batch;
    size_t m_sent = 0;
    size_t m_received = 0;
    int32_t m_first_request_id = 0;
    Lifecycle m_lifecycle = Lifecycle::Invalid;
    Step m_step = Step::Sending;
    std::vector<MongoPipelineResponse> m_responses;

    ProtocolFlowAwaitable m_flow_awaitable;
    std::optional<MongoError> m_chain_error;
};

class AsyncMongoClient
{
public:
    AsyncMongoClient(IOScheduler* scheduler,
                AsyncMongoConfig config = AsyncMongoConfig::noTimeout());

    AsyncMongoClient(AsyncMongoClient&& other) noexcept;
    AsyncMongoClient& operator=(AsyncMongoClient&& other) noexcept;

    AsyncMongoClient(const AsyncMongoClient&) = delete;
    AsyncMongoClient& operator=(const AsyncMongoClient&) = delete;

    ~AsyncMongoClient() = default;

    MongoConnectAwaitable connect(MongoConfig config);
    MongoConnectAwaitable connect(std::string_view host,
                                  uint16_t port,
                                  std::string_view database = "admin");

    MongoCommandAwaitable command(std::string database, MongoDocument command);
    MongoCommandAwaitable ping(std::string database = "admin");
    MongoPipelineAwaitable pipeline(std::string database,
                                    std::vector<MongoDocument> commands);

    auto close()
    {
        m_is_closed = true;
        return m_socket.close();
    }
    bool isClosed() const { return m_is_closed; }

    TcpSocket& socket() { return m_socket; }
    RingBuffer& ringBuffer() { return m_ring_buffer; }
    int32_t nextRequestId();
    MongoLogger& logger() { return m_logger; }
    const MongoLogger& logger() const { return m_logger; }
    void setLogger(MongoLoggerPtr logger)
    {
        m_logger.set(std::move(logger));
    }

private:
    friend class MongoConnectAwaitable;
    friend class MongoCommandAwaitable;
    friend class MongoPipelineAwaitable;

    int32_t reserveRequestIdBlock(size_t count);

    bool m_is_closed = true;
    TcpSocket m_socket;
    RingBuffer m_ring_buffer;
    std::string m_decode_scratch;
    size_t m_pipeline_reserve_per_command = 96;
    int32_t m_next_request_id = 1;

    MongoLogger m_logger;
};

} // namespace galay::mongo

#endif // GALAY_MONGO_ASYNC_CLIENT_H
