#ifndef GALAY_MONGO_BSON_H
#define GALAY_MONGO_BSON_H

#include "galay-mongo/base/MongoValue.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string_view>
#include <string>

namespace galay::mongo::protocol
{

/// BSON 元素类型标识（对应 BSON 规范中的 type byte）
enum class BsonType : uint8_t
{
    Double = 0x01,      ///< 64 位浮点数
    String = 0x02,      ///< UTF-8 字符串
    Document = 0x03,    ///< 嵌套文档
    Array = 0x04,       ///< 数组
    Binary = 0x05,      ///< 二进制数据
    ObjectId = 0x07,    ///< 12 字节 ObjectId
    Bool = 0x08,        ///< 布尔值
    DateTime = 0x09,    ///< UTC 日期时间（毫秒时间戳）
    Null = 0x0A,        ///< 空值
    Int32 = 0x10,       ///< 32 位整数
    Timestamp = 0x11,   ///< MongoDB 内部时间戳
    Int64 = 0x12,       ///< 64 位整数
};

/// BSON 编解码器，负责 MongoDocument 与 BSON 二进制格式之间的转换
class BsonCodec
{
public:
    /// 将 MongoDocument 编码为 BSON 二进制数据
    static std::string encodeDocument(const MongoDocument& document);
    /// 将 MongoDocument 直接追加编码到现有缓冲区尾部，避免中间临时字符串
    static void appendDocument(std::string& out, const MongoDocument& document);
    /// 将 MongoDocument 追加编码到缓冲区；若原文档缺少 `$db` 字段则按需补齐
    static void appendDocumentWithDatabase(std::string& out,
                                           const MongoDocument& document,
                                           std::string_view database);

    /// 从 BSON 二进制数据解码为 MongoDocument
    /// @param data 数据指针
    /// @param len  数据长度
    /// @return 解码后的文档，或错误描述
    static std::expected<MongoDocument, std::string> decodeDocument(const char* data, size_t len);

    /// 从 BSON 二进制数据解码为 MongoDocument（带消费字节数输出）
    /// @param data     数据指针
    /// @param len      数据长度
    /// @param consumed [out] 实际消费的字节数
    static std::expected<MongoDocument, std::string> decodeDocument(const char* data,
                                                                    size_t len,
                                                                    size_t& consumed);

private:
    static void writeInt32(std::string& out, int32_t value);
    static void writeInt64(std::string& out, int64_t value);
    static void writeDouble(std::string& out, double value);
    static void writeCString(std::string& out, std::string_view value);

    static std::expected<int32_t, std::string> readInt32(const char* data, size_t len, size_t pos);
    static std::expected<int64_t, std::string> readInt64(const char* data, size_t len, size_t pos);
    static std::expected<double, std::string> readDouble(const char* data, size_t len, size_t pos);
    static std::expected<std::string, std::string> readCString(const char* data, size_t len, size_t& pos);

    static void encodeElement(std::string& out, std::string_view key, const MongoValue& value);
    static std::expected<MongoValue, std::string> decodeElementValue(BsonType type,
                                                                      const char* data,
                                                                      size_t len,
                                                                      size_t& pos);
};

} // namespace galay::mongo::protocol

#endif // GALAY_MONGO_BSON_H
