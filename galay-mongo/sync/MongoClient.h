#ifndef GALAY_MONGO_SYNC_CLIENT_H
#define GALAY_MONGO_SYNC_CLIENT_H

#include "galay-mongo/base/MongoConfig.h"
#include "galay-mongo/base/MongoError.h"
#include "galay-mongo/base/MongoValue.h"
#include "galay-mongo/protocol/Connection.h"

#include <cstdint>
#include <expected>
#include <string>
#include <unordered_map>
#include <vector>

namespace galay::mongo
{

/// 命令执行结果类型别名
using MongoResult = std::expected<MongoReply, MongoError>;
/// 无返回值的操作结果类型别名
using MongoVoidResult = std::expected<void, MongoError>;

/// 同步 MongoDB 客户端会话
/// 提供阻塞式的连接、命令执行和 CRUD 操作
/// 不可拷贝，支持移动语义
class MongoClient
{
public:
    MongoClient();
    ~MongoClient();

    MongoClient(const MongoClient&) = delete;
    MongoClient& operator=(const MongoClient&) = delete;

    MongoClient(MongoClient&& other) noexcept;
    MongoClient& operator=(MongoClient&& other) noexcept;

    /// 使用完整配置连接到 MongoDB（含认证）
    MongoVoidResult connect(const MongoConfig& config);
    /// 使用地址和端口快速连接（无认证）
    MongoVoidResult connect(const std::string& host,
                            uint16_t port,
                            const std::string& database = "admin");

    /// 执行任意 MongoDB 命令
    /// @param database 目标数据库
    /// @param command  命令文档
    MongoResult command(const std::string& database, const MongoDocument& command);

    /// 发送 ping 命令检测连接是否存活
    MongoResult ping(const std::string& database = "admin");

    /// 查询单条文档
    /// @param database   目标数据库
    /// @param collection 集合名
    /// @param filter     查询条件（默认空 = 匹配全部）
    /// @param projection 字段投影（默认空 = 返回全部字段）
    MongoResult findOne(const std::string& database,
                        const std::string& collection,
                        const MongoDocument& filter = {},
                        const MongoDocument& projection = {});

    /// 插入单条文档
    /// @param database   目标数据库
    /// @param collection 集合名
    /// @param document   待插入的文档
    MongoResult insertOne(const std::string& database,
                          const std::string& collection,
                          const MongoDocument& document);

    /// 更新单条文档
    /// @param database   目标数据库
    /// @param collection 集合名
    /// @param filter     匹配条件
    /// @param update     更新操作（如 $set）
    /// @param upsert     未匹配时是否插入，默认 false
    MongoResult updateOne(const std::string& database,
                          const std::string& collection,
                          const MongoDocument& filter,
                          const MongoDocument& update,
                          bool upsert = false);

    /// 删除单条文档
    /// @param database   目标数据库
    /// @param collection 集合名
    /// @param filter     匹配条件
    MongoResult deleteOne(const std::string& database,
                          const std::string& collection,
                          const MongoDocument& filter);

    /// 关闭连接
    void close();
    /// 判断当前是否已连接
    bool isConnected() const { return m_connection.isConnected(); }

private:
    MongoResult executeCommand(const std::string& database,
                               const MongoDocument& command,
                               bool check_ok);

    MongoVoidResult authenticateIfNeeded(const MongoConfig& config);
    MongoVoidResult authenticateScramSha256(const MongoConfig& config);

    static std::string escapeScramUsername(const std::string& username);

    static std::unordered_map<std::string, std::string>
    parseScramPayload(const std::string& payload);

    static std::string base64Encode(const std::vector<uint8_t>& bytes);
    static std::expected<std::vector<uint8_t>, MongoError> base64Decode(const std::string& text);

    static std::expected<std::vector<uint8_t>, MongoError>
    pbkdf2HmacSha256(const std::string& password,
                    const std::vector<uint8_t>& salt,
                    int iterations);

    static std::expected<std::vector<uint8_t>, MongoError>
    hmacSha256(const std::vector<uint8_t>& key, const std::string& data);

    static std::expected<std::vector<uint8_t>, MongoError>
    sha256(const std::vector<uint8_t>& data);

    static std::vector<uint8_t> xorBytes(const std::vector<uint8_t>& a,
                                         const std::vector<uint8_t>& b);

    static std::expected<std::string, MongoError> generateClientNonce();

private:
    protocol::Connection m_connection;
    MongoConfig m_config;
    std::string m_encoded_request_buffer;
    int32_t m_next_request_id = 1;
};

} // namespace galay::mongo

#endif // GALAY_MONGO_SYNC_CLIENT_H
