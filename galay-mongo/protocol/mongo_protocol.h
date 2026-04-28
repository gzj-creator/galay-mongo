#ifndef GALAY_MONGO_PROTOCOL_H
#define GALAY_MONGO_PROTOCOL_H

#include "bson.h"
#include "galay-mongo/base/mongo_error.h"
#include "galay-mongo/base/mongo_value.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

namespace galay::mongo::protocol
{

constexpr int32_t kMongoOpReply = 1;          ///< OP_REPLY（旧版响应，已弃用）
constexpr int32_t kMongoOpCompressed = 2012;  ///< OP_COMPRESSED 压缩消息
constexpr int32_t kMongoOpMsg = 2013;         ///< OP_MSG 标准消息格式

/// MongoDB 消息头（16 字节）
struct MongoMessageHeader
{
    int32_t message_length = 0;  ///< 消息总长度（含头部）
    int32_t request_id = 0;      ///< 请求 ID
    int32_t response_to = 0;     ///< 对应的请求 ID（响应时使用）
    int32_t op_code = 0;         ///< 操作码
};

/// 解码后的 MongoDB 消息
struct MongoMessage
{
    MongoMessageHeader header;   ///< 消息头
    int32_t flags = 0;           ///< OP_MSG 标志位
    MongoDocument body;          ///< 消息体（Section Kind 0）
};

/// MongoDB OP_MSG 协议编解码及命令构造工具
class MongoProtocol
{
public:
    /// 将命令文档编码为 OP_MSG 二进制数据
    /// @param request_id 请求 ID
    /// @param body       命令文档
    /// @param flags      OP_MSG 标志位，默认 0
    static std::string encodeOpMsg(int32_t request_id,
                                   const MongoDocument& body,
                                   int32_t flags = 0);

    /// 将命令文档追加编码到已有字符串缓冲区尾部，减少临时字符串分配
    static void appendOpMsg(std::string& out,
                            int32_t request_id,
                            const MongoDocument& body,
                            int32_t flags = 0);

    /// 将命令文档追加编码为 OP_MSG；若命令缺少 `$db` 字段则按需补齐
    static void appendOpMsgWithDatabase(std::string& out,
                                        int32_t request_id,
                                        const MongoDocument& body,
                                        std::string_view database,
                                        int32_t flags = 0);

    /// 从完整消息二进制数据解码为 MongoMessage
    static std::expected<MongoMessage, MongoError> decodeMessage(const char* data, size_t len);

    /// 从数据流中提取一条完整消息（带消费字节数输出）
    /// @param data     数据指针
    /// @param len      可用数据长度
    /// @param consumed [out] 实际消费的字节数
    static std::expected<MongoMessage, MongoError> extractMessage(const char* data,
                                                                  size_t len,
                                                                  size_t& consumed);

    /// 构造 MongoDB 命令文档
    /// @param db            目标数据库名
    /// @param command_name  命令名称（如 "find", "insert"）
    /// @param command_value 命令值（通常为集合名）
    /// @param arguments     附加参数
    static MongoDocument makeCommand(std::string db,
                                     std::string command_name,
                                     MongoValue command_value,
                                     MongoDocument arguments = {});
};

} // namespace galay::mongo::protocol

#endif // GALAY_MONGO_PROTOCOL_H
