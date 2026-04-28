#ifndef GALAY_MONGO_CONFIG_H
#define GALAY_MONGO_CONFIG_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace galay::mongo
{

/// MongoDB 连接配置，包含地址、认证、超时等参数
struct MongoConfig
{
    static constexpr const char* kDefaultHost = "127.0.0.1";
    static constexpr uint16_t kDefaultPort = 27017;
    static constexpr const char* kDefaultDatabase = "admin";
    static constexpr const char* kDefaultAuthDatabase = "admin";
    static constexpr const char* kDefaultHelloDatabase = "admin";
    static constexpr const char* kDefaultAppName = "galay-mongo";
    static constexpr bool kDefaultTcpNoDelay = true;
    static constexpr uint32_t kDefaultConnectTimeoutMs = 5000;
    static constexpr uint32_t kDefaultSocketTimeoutMs = 5000;
    static constexpr size_t kDefaultRecvBufferSize = 16384;

    std::string host = kDefaultHost;  ///< 服务器地址
    uint16_t port = kDefaultPort;     ///< 服务器端口

    std::string username;             ///< 认证用户名（为空则跳过认证）
    std::string password;             ///< 认证密码

    std::string database = kDefaultDatabase;           ///< 默认业务库
    std::string auth_database = kDefaultAuthDatabase;  ///< SCRAM 认证库，默认 admin
    std::string hello_database = kDefaultHelloDatabase; ///< hello 握手使用的数据库，默认 admin

    std::string app_name = kDefaultAppName; ///< 客户端应用名称，用于 hello 握手

    bool tcp_nodelay = kDefaultTcpNoDelay;                  ///< 是否启用 TCP_NODELAY
    uint32_t connect_timeout_ms = kDefaultConnectTimeoutMs; ///< TCP 连接超时（毫秒）
    uint32_t socket_timeout_ms = kDefaultSocketTimeoutMs;   ///< Socket 读写超时（毫秒）
    size_t recv_buffer_size = kDefaultRecvBufferSize;       ///< 同步连接接收缓冲区大小（字节）

    /// 返回全部使用默认值的配置
    static MongoConfig defaultConfig()
    {
        return {};
    }

    /// 快速创建指定地址和端口的配置
    /// @param host     服务器地址
    /// @param port     服务器端口
    /// @param database 默认业务库，默认 "admin"
    static MongoConfig create(const std::string& host,
                              uint16_t port,
                              const std::string& database = "admin")
    {
        MongoConfig config;
        config.host = host;
        config.port = port;
        config.database = database;
        if (config.auth_database.empty()) {
            config.auth_database = database;
        }
        return config;
    }
};

} // namespace galay::mongo

#endif // GALAY_MONGO_CONFIG_H
