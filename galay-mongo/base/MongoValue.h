#ifndef GALAY_MONGO_VALUE_H
#define GALAY_MONGO_VALUE_H

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace galay::mongo
{

class MongoDocument;
class MongoArray;

/// BSON 值类型枚举
enum class MongoValueType : uint8_t
{
    Null,       ///< 空值
    Bool,       ///< 布尔值
    Int32,      ///< 32 位整数
    Int64,      ///< 64 位整数
    Double,     ///< 双精度浮点数
    String,     ///< UTF-8 字符串
    Binary,     ///< 二进制数据
    Document,   ///< 嵌套文档
    Array,      ///< 数组
};

/// BSON 值的通用容器，支持 Null/Bool/Int32/Int64/Double/String/Binary/Document/Array
/// 通过隐式构造函数可直接从 C++ 原生类型转换
class MongoValue
{
public:
    using Binary = std::vector<uint8_t>;

    MongoValue();                       ///< 构造 Null 值
    MongoValue(std::nullptr_t);         ///< 构造 Null 值
    MongoValue(bool value);             ///< 构造 Bool 值
    MongoValue(int32_t value);          ///< 构造 Int32 值
    MongoValue(int64_t value);          ///< 构造 Int64 值
    MongoValue(double value);           ///< 构造 Double 值
    MongoValue(std::string value);      ///< 构造 String 值
    MongoValue(const char* value);      ///< 构造 String 值（从 C 字符串）
    MongoValue(Binary value);           ///< 构造 Binary 值
    MongoValue(MongoDocument value);    ///< 构造嵌套 Document 值
    MongoValue(MongoArray value);       ///< 构造 Array 值

    /// 返回当前值的类型
    MongoValueType type() const;

    /// @name 类型判断
    /// @{
    bool isNull() const;
    bool isBool() const;
    bool isInt32() const;
    bool isInt64() const;
    bool isDouble() const;
    bool isString() const;
    bool isBinary() const;
    bool isDocument() const;
    bool isArray() const;
    /// @}

    /// @name 值提取（类型不匹配时返回默认值或空引用）
    /// @{
    bool toBool(bool default_value = false) const;
    int32_t toInt32(int32_t default_value = 0) const;
    int64_t toInt64(int64_t default_value = 0) const;
    double toDouble(double default_value = 0.0) const;
    const std::string& toString() const;
    const Binary& toBinary() const;
    const MongoDocument& toDocument() const;
    const MongoArray& toArray() const;
    /// @}

    /// @name 可变引用访问（类型不匹配时行为未定义）
    /// @{
    MongoDocument& asDocument();
    MongoArray& asArray();
    /// @}

private:
    using DocumentPtr = std::shared_ptr<MongoDocument>;
    using ArrayPtr = std::shared_ptr<MongoArray>;
    using Storage = std::variant<std::nullptr_t,
                                 bool,
                                 int32_t,
                                 int64_t,
                                 double,
                                 std::string,
                                 Binary,
                                 DocumentPtr,
                                 ArrayPtr>;

    Storage m_storage;

    static const std::string kEmptyString;
    static const Binary kEmptyBinary;
};

/// BSON 数组，有序的 MongoValue 集合
class MongoArray
{
public:
    MongoArray() = default;
    /// 从已有值列表构造
    explicit MongoArray(std::vector<MongoValue> values);

    /// 追加一个元素
    void append(MongoValue value);
    /// 预分配容量
    void reserve(size_t n);

    /// 返回元素数量
    size_t size() const;
    /// 判断是否为空
    bool empty() const;

    /// 按索引访问（越界时抛出 std::out_of_range）
    const MongoValue& at(size_t index) const;
    /// 按索引访问（不做边界检查）
    const MongoValue& operator[](size_t index) const;

    /// 获取底层值列表的只读引用
    const std::vector<MongoValue>& values() const;
    /// 获取底层值列表的可变引用
    std::vector<MongoValue>& values();

private:
    std::vector<MongoValue> m_values;
};

/// BSON 文档，保持字段插入顺序的键值对集合
class MongoDocument
{
public:
    using Field = std::pair<std::string, MongoValue>;

    MongoDocument() = default;
    /// 从已有字段列表构造
    explicit MongoDocument(std::vector<Field> fields);

    /// 追加字段（不检查重复键）
    void append(std::string key, MongoValue value);
    /// 设置字段（已存在则更新，否则追加）
    void set(std::string key, MongoValue value);

    /// 判断是否存在指定键
    bool has(const std::string& key) const;
    /// 查找指定键，未找到返回 nullptr
    const MongoValue* find(const std::string& key) const;
    /// 查找指定键（可变版本），未找到返回 nullptr
    MongoValue* find(const std::string& key);

    /// 按键访问（未找到时抛出 std::out_of_range）
    const MongoValue& at(const std::string& key) const;

    /// @name 便捷取值方法（键不存在或类型不匹配时返回默认值）
    /// @{
    std::string getString(const std::string& key, std::string default_value = "") const;
    int32_t getInt32(const std::string& key, int32_t default_value = 0) const;
    int64_t getInt64(const std::string& key, int64_t default_value = 0) const;
    double getDouble(const std::string& key, double default_value = 0.0) const;
    bool getBool(const std::string& key, bool default_value = false) const;
    /// @}

    /// 返回字段数量
    size_t size() const;
    /// 判断是否为空
    bool empty() const;

    /// 获取底层字段列表的只读引用
    const std::vector<Field>& fields() const;
    /// 获取底层字段列表的可变引用
    std::vector<Field>& fields();

private:
    std::vector<Field> m_fields;
};

/// MongoDB 服务端响应的封装，提供 ok/error 状态判断
class MongoReply
{
public:
    MongoReply() = default;
    /// 从原始响应文档构造
    explicit MongoReply(MongoDocument document);

    /// 获取原始响应文档
    const MongoDocument& document() const;
    /// 获取原始响应文档（可变）
    MongoDocument& document();

    /// 判断响应是否成功（ok == 1）
    bool ok() const;
    /// 判断响应中是否包含命令错误
    bool hasCommandError() const;
    /// 返回服务端错误码
    int32_t errorCode() const;
    /// 返回服务端错误消息
    std::string errorMessage() const;

private:
    MongoDocument m_document;
};

} // namespace galay::mongo

#endif // GALAY_MONGO_VALUE_H
