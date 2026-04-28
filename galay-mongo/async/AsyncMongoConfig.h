#ifndef GALAY_MONGO_ASYNC_CONFIG_H
#define GALAY_MONGO_ASYNC_CONFIG_H

#include <cstddef>
#include <string>

namespace galay
{
namespace mongo
{

/// 异步客户端配置，控制缓冲区与日志相关选项
struct AsyncMongoConfig
{
    size_t buffer_size = 16384;                                               ///< 接收环形缓冲区大小
    size_t pipeline_reserve_per_command = 96;                                 ///< pipeline 每条命令的预留编码字节估算
    std::string logger_name = "MongoClientLogger";                           ///< 默认 logger 名称

    /// 创建默认配置
    static AsyncMongoConfig noTimeout()
    {
        return {};
    }
};

} // namespace mongo
} // namespace galay

#endif // GALAY_MONGO_ASYNC_CONFIG_H
