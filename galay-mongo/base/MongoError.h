#ifndef GALAY_MONGO_ERROR_H
#define GALAY_MONGO_ERROR_H

#include <cstdint>
#include <string>

namespace galay::mongo
{

/// 错误类型枚举，标识错误发生的阶段或原因
enum MongoErrorType
{
    MONGO_ERROR_SUCCESS,            ///< 无错误
    MONGO_ERROR_CONNECTION,         ///< TCP 连接失败
    MONGO_ERROR_AUTH,               ///< SCRAM 认证失败
    MONGO_ERROR_COMMAND,            ///< 命令执行失败
    MONGO_ERROR_PROTOCOL,           ///< 协议解析错误
    MONGO_ERROR_TIMEOUT,            ///< 操作超时
    MONGO_ERROR_SEND,               ///< 数据发送失败
    MONGO_ERROR_RECV,               ///< 数据接收失败
    MONGO_ERROR_CONNECTION_CLOSED,  ///< 连接已关闭
    MONGO_ERROR_SERVER,             ///< 服务端返回错误
    MONGO_ERROR_INTERNAL,           ///< 内部逻辑错误
    MONGO_ERROR_BUFFER_OVERFLOW,    ///< 缓冲区溢出
    MONGO_ERROR_INVALID_PARAM,      ///< 参数无效
    MONGO_ERROR_UNSUPPORTED,        ///< 不支持的操作
};

/// MongoDB 错误信息，包含错误类型、服务端错误码和描述消息
class MongoError
{
public:
    /// 仅指定错误类型
    explicit MongoError(MongoErrorType type);
    /// 指定错误类型和附加描述
    MongoError(MongoErrorType type, std::string extra_msg);
    /// 指定错误类型、服务端错误码和服务端消息
    MongoError(MongoErrorType type, int32_t server_code, std::string server_msg);

    /// 返回错误类型
    MongoErrorType type() const;
    /// 返回服务端错误码（非服务端错误时为 0）
    int32_t serverCode() const;
    /// 返回可读的错误描述字符串
    std::string message() const;

private:
    MongoErrorType m_type;
    int32_t m_server_code = 0;
    std::string m_extra_msg;
};

} // namespace galay::mongo

#endif // GALAY_MONGO_ERROR_H
