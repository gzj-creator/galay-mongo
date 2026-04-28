#ifndef GALAY_MONGO_ASYNC_CLIENT_H
#define GALAY_MONGO_ASYNC_CLIENT_H

#include <galay-kernel/async/tcp_socket.h>
#include <galay-kernel/common/error.h>
#include <galay-kernel/common/host.hpp>
#include <galay-kernel/kernel/io_scheduler.hpp>
#include <galay-kernel/kernel/task.h>

#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "config.h"
#include "buf_provider.h"
#include "galay-mongo/base/mongo_config.h"
#include "galay-mongo/base/mongo_error.h"
#include "galay-mongo/base/mongo_log.h"
#include "galay-mongo/base/mongo_value.h"
#include "galay-mongo/protocol/mongo_protocol.h"

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

    AsyncMongoClientBuilder& sendTimeout(std::chrono::milliseconds timeout)
    {
        m_config.send_timeout = timeout;
        return *this;
    }

    AsyncMongoClientBuilder& recvTimeout(std::chrono::milliseconds timeout)
    {
        m_config.recv_timeout = timeout;
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

using MongoConnectAwaitable = Task<std::expected<bool, MongoError>>;
using MongoCommandAwaitable = Task<std::expected<MongoReply, MongoError>>;
using MongoPipelineAwaitable =
    Task<std::expected<std::vector<MongoPipelineResponse>, MongoError>>;

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
