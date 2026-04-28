#ifndef GALAY_MONGO_ASYNC_CONFIG_H
#define GALAY_MONGO_ASYNC_CONFIG_H

#include <chrono>
#include <cstddef>
#include <string>

namespace galay::mongo
{

/// 异步客户端配置，控制发送/接收超时和缓冲区大小
struct AsyncMongoConfig
{
    std::chrono::milliseconds send_timeout = std::chrono::milliseconds(-1);  ///< 发送超时（负值表示不限时）
    std::chrono::milliseconds recv_timeout = std::chrono::milliseconds(-1);  ///< 接收超时（负值表示不限时）
    size_t buffer_size = 16384;                                              ///< 接收环形缓冲区大小
    size_t pipeline_reserve_per_command = 96;                                 ///< pipeline 每条命令的预留编码字节估算
    std::string logger_name = "MongoClientLogger";                           ///< 默认 logger 名称

    /// 判断发送超时是否启用
    bool isSendTimeoutEnabled() const
    {
        return send_timeout >= std::chrono::milliseconds(0);
    }

    /// 判断接收超时是否启用
    bool isRecvTimeoutEnabled() const
    {
        return recv_timeout >= std::chrono::milliseconds(0);
    }

    /// 创建指定超时的配置
    static AsyncMongoConfig withTimeout(std::chrono::milliseconds send,
                                        std::chrono::milliseconds recv)
    {
        AsyncMongoConfig config;
        config.send_timeout = send;
        config.recv_timeout = recv;
        return config;
    }

    /// 创建无超时限制的默认配置
    static AsyncMongoConfig noTimeout()
    {
        return {};
    }
};

} // namespace galay::mongo

#endif // GALAY_MONGO_ASYNC_CONFIG_H
