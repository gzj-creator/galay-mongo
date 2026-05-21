/**
 * @file config.h
 * @brief MongoDB 异步客户端配置
 * @author galay-mongo
 * @version 1.0.0
 *
 * @details 定义 AsyncMongoConfig 结构体，控制异步客户端的发送/接收超时、
 * 缓冲区大小以及 pipeline 编码预留字节等参数。
 */

#ifndef GALAY_MONGO_ASYNC_CONFIG_H
#define GALAY_MONGO_ASYNC_CONFIG_H

#include <chrono>
#include <cstddef>
#include <string>

namespace galay::mongo
{

/**
 * @brief 异步客户端配置，控制发送/接收超时和缓冲区大小
 * @details 提供工厂方法创建带超时或不带超时的配置实例
 */
struct AsyncMongoConfig
{
    std::chrono::milliseconds send_timeout = std::chrono::milliseconds(-1);  ///< 发送超时（负值表示不限时）
    std::chrono::milliseconds recv_timeout = std::chrono::milliseconds(-1);  ///< 接收超时（负值表示不限时）
    size_t buffer_size = 16384;                                              ///< 接收环形缓冲区大小
    size_t pipeline_reserve_per_command = 96;                                 ///< pipeline 每条命令的预留编码字节估算

    /**
     * @brief 判断发送超时是否启用
     * @return 超时值非负时返回 true
     */
    bool isSendTimeoutEnabled() const
    {
        return send_timeout >= std::chrono::milliseconds(0);
    }

    /**
     * @brief 判断接收超时是否启用
     * @return 超时值非负时返回 true
     */
    bool isRecvTimeoutEnabled() const
    {
        return recv_timeout >= std::chrono::milliseconds(0);
    }

    /**
     * @brief 创建指定超时的配置
     * @param send 发送超时
     * @param recv 接收超时
     * @return 配置好的 AsyncMongoConfig 实例
     */
    static AsyncMongoConfig withTimeout(std::chrono::milliseconds send,
                                        std::chrono::milliseconds recv)
    {
        AsyncMongoConfig config;
        config.send_timeout = send;
        config.recv_timeout = recv;
        return config;
    }

    /**
     * @brief 创建无超时限制的默认配置
     * @return 所有超时均为负值（不限时）的配置
     */
    static AsyncMongoConfig noTimeout()
    {
        return {};
    }
};

} // namespace galay::mongo

#endif // GALAY_MONGO_ASYNC_CONFIG_H
