#ifndef GALAY_MONGO_ASYNC_CLIENT_H
#define GALAY_MONGO_ASYNC_CLIENT_H

#include <galay-kernel/async/TcpSocket.h>
#include <galay-kernel/common/Error.h>
#include <galay-kernel/common/Host.hpp>
#include <galay-kernel/kernel/Awaitable.h>
#include <galay-kernel/kernel/IOScheduler.hpp>
#include <galay-kernel/kernel/Task.h>

#include <array>
#include <chrono>
#include <coroutine>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <sys/uio.h>
#include <utility>
#include <vector>

#include "AsyncMongoConfig.h"
#include "MongoBufferProvider.h"
#include "galay-mongo/base/MongoConfig.h"
#include "galay-mongo/base/MongoError.h"
#include "galay-mongo/base/MongoLog.h"
#include "galay-mongo/base/MongoValue.h"
#include "galay-mongo/protocol/MongoProtocol.h"

namespace galay::mongo
{

using galay::async::TcpSocket;
using galay::kernel::IOError;
using galay::kernel::IOScheduler;
using galay::kernel::Task;

class AsyncMongoClient;
struct AsyncMongoClientInternals;

class AsyncMongoClientBuilder
{
public:
    AsyncMongoClientBuilder& scheduler(IOScheduler* scheduler)
    {
        m_scheduler = scheduler;
        return *this;
    }

    AsyncMongoClientBuilder& config(AsyncMongoConfig config)
    {
        m_config = std::move(config);
        return *this;
    }

    AsyncMongoClientBuilder& bufferSize(size_t size)
    {
        m_config.buffer_size = size;
        return *this;
    }

    AsyncMongoClientBuilder& bufferProvider(std::shared_ptr<MongoBufferProvider> provider)
    {
        m_buffer_provider = std::move(provider);
        return *this;
    }

    AsyncMongoClientBuilder& pipelineReservePerCommand(size_t reserve)
    {
        m_config.pipeline_reserve_per_command = reserve;
        return *this;
    }

    AsyncMongoClientBuilder& loggerName(std::string logger_name)
    {
        m_config.logger_name = std::move(logger_name);
        return *this;
    }

    AsyncMongoClient build() const;

    AsyncMongoConfig buildConfig() const
    {
        return m_config;
    }

private:
    IOScheduler* m_scheduler = nullptr;
    AsyncMongoConfig m_config = AsyncMongoConfig::noTimeout();
    std::shared_ptr<MongoBufferProvider> m_buffer_provider;
};

struct MongoPipelineResponse
{
    int32_t request_id = 0;
    std::optional<MongoReply> reply;
    std::optional<MongoError> error;

    bool ok() const { return reply.has_value(); }
};

class MongoConnectAwaitable
{
public:
    using Result = std::expected<bool, MongoError>;

    MongoConnectAwaitable(AsyncMongoClient& client, MongoConfig config);
    MongoConnectAwaitable(MongoConnectAwaitable&&) noexcept = default;
    MongoConnectAwaitable& operator=(MongoConnectAwaitable&&) noexcept = default;
    MongoConnectAwaitable(const MongoConnectAwaitable&) = delete;
    MongoConnectAwaitable& operator=(const MongoConnectAwaitable&) = delete;

    bool await_ready() { return m_inner.await_ready(); }
    template <typename Promise>
    bool await_suspend(std::coroutine_handle<Promise> handle)
    {
        return m_inner.await_suspend(handle);
    }
    Result await_resume() { return m_inner.await_resume(); }

    auto timeout(std::chrono::milliseconds timeout) &&
    {
        return std::move(m_inner).timeout(timeout);
    }

    auto timeout(std::chrono::milliseconds timeout) &
    {
        return m_inner.timeout(timeout);
    }

    bool isInvalid() const;

private:
    enum class Phase {
        Invalid,
        Connect,
        SendRequest,
        RecvReply,
        HandleReply,
        Done
    };

    struct SharedState;
    struct Machine {
        using result_type = Result;
        static constexpr galay::kernel::SequenceOwnerDomain kSequenceOwnerDomain =
            galay::kernel::SequenceOwnerDomain::ReadWrite;

        explicit Machine(std::shared_ptr<SharedState> state);

        galay::kernel::MachineAction<result_type> advance();
        void onConnect(std::expected<void, galay::kernel::IOError> result);
        void onRead(std::expected<size_t, galay::kernel::IOError> result);
        void onWrite(std::expected<size_t, galay::kernel::IOError> result);

    private:
        galay::kernel::MachineAction<result_type> advanceSendRequest();
        galay::kernel::MachineAction<result_type> advanceRecvReply();
        galay::kernel::MachineAction<result_type> advanceHandleReply();

        std::shared_ptr<SharedState> m_state;
    };
    using InnerAwaitable = galay::kernel::StateMachineAwaitable<Machine>;

    std::shared_ptr<SharedState> m_state;
    InnerAwaitable m_inner;
};

class MongoCommandAwaitable
{
public:
    using Result = std::expected<MongoReply, MongoError>;

    MongoCommandAwaitable(AsyncMongoClient& client,
                          std::string database,
                          MongoDocument command);
    MongoCommandAwaitable(MongoCommandAwaitable&&) noexcept = default;
    MongoCommandAwaitable& operator=(MongoCommandAwaitable&&) noexcept = default;
    MongoCommandAwaitable(const MongoCommandAwaitable&) = delete;
    MongoCommandAwaitable& operator=(const MongoCommandAwaitable&) = delete;

    bool await_ready() { return m_inner.await_ready(); }
    template <typename Promise>
    bool await_suspend(std::coroutine_handle<Promise> handle)
    {
        return m_inner.await_suspend(handle);
    }
    Result await_resume() { return m_inner.await_resume(); }

    auto timeout(std::chrono::milliseconds timeout) &&
    {
        return std::move(m_inner).timeout(timeout);
    }

    auto timeout(std::chrono::milliseconds timeout) &
    {
        return m_inner.timeout(timeout);
    }

    bool isInvalid() const;

private:
    enum class Phase {
        Invalid,
        SendCommand,
        RecvReply,
        Done
    };

    struct SharedState;
    struct Machine {
        using result_type = Result;
        static constexpr galay::kernel::SequenceOwnerDomain kSequenceOwnerDomain =
            galay::kernel::SequenceOwnerDomain::ReadWrite;

        explicit Machine(std::shared_ptr<SharedState> state);

        galay::kernel::MachineAction<result_type> advance();
        void onRead(std::expected<size_t, galay::kernel::IOError> result);
        void onWrite(std::expected<size_t, galay::kernel::IOError> result);

    private:
        galay::kernel::MachineAction<result_type> advanceSendCommand();
        galay::kernel::MachineAction<result_type> advanceRecvReply();
        void finishWithMessage(protocol::MongoMessage message);
        void setError(MongoError error) noexcept;

        std::shared_ptr<SharedState> m_state;
    };
    using InnerAwaitable = galay::kernel::StateMachineAwaitable<Machine>;

    std::shared_ptr<SharedState> m_state;
    InnerAwaitable m_inner;
};

class MongoPipelineAwaitable
{
public:
    using Result = std::expected<std::vector<MongoPipelineResponse>, MongoError>;

    MongoPipelineAwaitable(AsyncMongoClient& client,
                           std::string database,
                           std::span<const MongoDocument> commands);
    MongoPipelineAwaitable(MongoPipelineAwaitable&&) noexcept = default;
    MongoPipelineAwaitable& operator=(MongoPipelineAwaitable&&) noexcept = default;
    MongoPipelineAwaitable(const MongoPipelineAwaitable&) = delete;
    MongoPipelineAwaitable& operator=(const MongoPipelineAwaitable&) = delete;

    bool await_ready() { return m_inner.await_ready(); }
    template <typename Promise>
    bool await_suspend(std::coroutine_handle<Promise> handle)
    {
        return m_inner.await_suspend(handle);
    }
    Result await_resume() { return m_inner.await_resume(); }

    auto timeout(std::chrono::milliseconds timeout) &&
    {
        return std::move(m_inner).timeout(timeout);
    }

    auto timeout(std::chrono::milliseconds timeout) &
    {
        return m_inner.timeout(timeout);
    }

    bool isInvalid() const;

private:
    enum class Phase {
        Invalid,
        SendCommands,
        RecvReplies,
        Done
    };

    struct SharedState;
    struct Machine {
        using result_type = Result;
        static constexpr galay::kernel::SequenceOwnerDomain kSequenceOwnerDomain =
            galay::kernel::SequenceOwnerDomain::ReadWrite;

        explicit Machine(std::shared_ptr<SharedState> state);

        galay::kernel::MachineAction<result_type> advance();
        void onRead(std::expected<size_t, galay::kernel::IOError> result);
        void onWrite(std::expected<size_t, galay::kernel::IOError> result);

    private:
        galay::kernel::MachineAction<result_type> advanceSendCommands();
        galay::kernel::MachineAction<result_type> advanceRecvReplies();
        bool storeResponse(protocol::MongoMessage message);
        void setError(MongoError error) noexcept;

        std::shared_ptr<SharedState> m_state;
    };
    using InnerAwaitable = galay::kernel::StateMachineAwaitable<Machine>;

    std::shared_ptr<SharedState> m_state;
    InnerAwaitable m_inner;
};

class AsyncMongoClient
{
public:
    AsyncMongoClient(IOScheduler* scheduler,
                     AsyncMongoConfig config = AsyncMongoConfig::noTimeout(),
                     std::shared_ptr<MongoBufferProvider> buffer_provider = nullptr);

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
                                    std::span<const MongoDocument> commands);

    auto close()
    {
        m_is_closed = true;
        return m_socket.close();
    }

    bool isClosed() const { return m_is_closed; }

    TcpSocket& socket() { return m_socket; }
    MongoBufferHandle& ringBuffer() { return m_ring_buffer; }
    MongoBufferProvider& bufferProvider() { return m_ring_buffer.provider(); }
    const MongoBufferProvider& bufferProvider() const { return m_ring_buffer.provider(); }
    int32_t nextRequestId();
    MongoLogger& logger() { return m_logger; }
    const MongoLogger& logger() const { return m_logger; }

    void setLogger(MongoLoggerPtr logger)
    {
        m_logger.set(std::move(logger));
    }

private:
    friend struct AsyncMongoClientInternals;
    friend class MongoCommandAwaitable;
    friend class MongoPipelineAwaitable;

    int32_t reserveRequestIdBlock(size_t count);

    bool m_is_closed = true;
    AsyncMongoConfig m_config = AsyncMongoConfig::noTimeout();
    TcpSocket m_socket;
    MongoBufferHandle m_ring_buffer;
    std::string m_decode_scratch;
    std::string m_ping_template_db;
    std::string m_ping_encoded_template;
    size_t m_pipeline_reserve_per_command = 96;
    int32_t m_next_request_id = 1;
    MongoLogger m_logger;
};

inline AsyncMongoClient AsyncMongoClientBuilder::build() const
{
    return AsyncMongoClient(m_scheduler, m_config, m_buffer_provider);
}

} // namespace galay::mongo

#endif // GALAY_MONGO_ASYNC_CLIENT_H
