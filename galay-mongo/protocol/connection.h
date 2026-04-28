#ifndef GALAY_MONGO_PROTOCOL_CONNECTION_H
#define GALAY_MONGO_PROTOCOL_CONNECTION_H

#include "mongo_protocol.h"
#include "galay-mongo/base/mongo_error.h"
#include <galay-kernel/common/buffer.h>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>

namespace galay::mongo
{
struct MongoConfig;
}

namespace galay::mongo::protocol
{

/// 同步 TCP 连接，负责与 MongoDB 服务端的底层通信
/// 不可拷贝，支持移动语义
class Connection
{
public:
    struct ConnectOptions
    {
        ConnectOptions();

        std::string host;
        uint16_t port;
        uint32_t timeout_ms;
        uint32_t socket_timeout_ms;
        bool tcp_nodelay;
        size_t recv_buffer_size;

        static ConnectOptions fromMongoConfig(const ::galay::mongo::MongoConfig& config);
    };

    Connection();
    ~Connection();

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    Connection(Connection&& other) noexcept;
    Connection& operator=(Connection&& other) noexcept;

    /// 建立到 MongoDB 服务端的 TCP 连接
    /// @param options 连接参数
    std::expected<void, MongoError> connect(const ConnectOptions& options);

    /// 断开连接并关闭 socket
    void disconnect();

    /// 判断当前是否已连接
    bool isConnected() const { return m_connected; }

    /// 发送原始数据
    std::expected<void, MongoError> send(const std::string& data);

    /// 接收指定长度的原始字节
    std::expected<std::string, MongoError> recvBytes(size_t expected_len);
    /// 接收一条完整 MongoDB 消息的原始字节
    std::expected<std::string, MongoError> recvMessageRaw();
    /// 接收并解码一条完整 MongoDB 消息
    std::expected<MongoMessage, MongoError> recvMessage();

    /// 返回底层 socket 文件描述符
    int fd() const { return m_socket_fd; }

private:
    std::expected<void, MongoError> ensureData(size_t n);
    std::expected<void, MongoError> recvExact(char* buffer, size_t n);
    void copyReadable(size_t offset, char* dst, size_t len) const;
    std::string consumeToString(size_t len);

    int m_socket_fd;
    bool m_connected;
    galay::kernel::RingBuffer m_recv_ring;
    std::string m_decode_buffer;

    static constexpr size_t kDefaultBufferSize = 16384;        ///< 默认接收缓冲区大小
    static constexpr size_t kMaxMessageSize = 128 * 1024 * 1024; ///< 最大消息长度（128 MB）
};

} // namespace galay::mongo::protocol

#endif // GALAY_MONGO_PROTOCOL_CONNECTION_H
