#ifndef GALAY_MONGO_EXAMPLE_CONFIG_H
#define GALAY_MONGO_EXAMPLE_CONFIG_H

#include "galay-mongo/async/AsyncMongoConfig.h"
#include "galay-mongo/base/MongoConfig.h"

#include <chrono>
#include <cstdlib>
#include <limits>
#include <string>

namespace mongo_example
{

inline std::string envOrDefault(const char* key, std::string fallback)
{
    const char* value = std::getenv(key);
    return value != nullptr ? std::string(value) : std::move(fallback);
}

inline uint16_t envPortOrDefault(const char* key, uint16_t fallback)
{
    const char* value = std::getenv(key);
    if (value == nullptr) {
        return fallback;
    }

    try {
        const int parsed = std::stoi(value);
        if (parsed <= 0 || parsed > 65535) {
            return fallback;
        }
        return static_cast<uint16_t>(parsed);
    } catch (...) {
        return fallback;
    }
}

inline galay::mongo::MongoConfig loadMongoConfigFromEnv()
{
    galay::mongo::MongoConfig cfg;
    cfg.host = envOrDefault("GALAY_MONGO_HOST", cfg.host);
    cfg.port = envPortOrDefault("GALAY_MONGO_PORT", cfg.port);
    cfg.database = envOrDefault("GALAY_MONGO_DB", cfg.database);
    cfg.username = envOrDefault("GALAY_MONGO_USER", "");
    cfg.password = envOrDefault("GALAY_MONGO_PASSWORD", "");
    cfg.auth_database = envOrDefault("GALAY_MONGO_AUTH_DB", cfg.auth_database);
    cfg.hello_database = envOrDefault("GALAY_MONGO_HELLO_DB", cfg.hello_database);
    cfg.tcp_nodelay = envOrDefault("GALAY_MONGO_TCP_NODELAY", "1") != "0";

    const char* recv_buffer_env = std::getenv("GALAY_MONGO_RECV_BUFFER_SIZE");
    if (recv_buffer_env != nullptr) {
        try {
            const unsigned long long parsed = std::stoull(recv_buffer_env);
            if (parsed > 0 &&
                parsed <= static_cast<unsigned long long>(std::numeric_limits<size_t>::max())) {
                cfg.recv_buffer_size = static_cast<size_t>(parsed);
            }
        } catch (...) {
        }
    }

    return cfg;
}

struct AsyncMongoOperationTimeout
{
    bool enabled = false;
    std::chrono::milliseconds value{0};
};

inline AsyncMongoOperationTimeout loadAsyncMongoOperationTimeoutFromEnv()
{
    const char* timeout_env = std::getenv("GALAY_MONGO_ASYNC_TIMEOUT_MS");
    if (timeout_env == nullptr) {
        return {};
    }

    try {
        return AsyncMongoOperationTimeout{true, std::chrono::milliseconds(std::stoi(timeout_env))};
    } catch (...) {
        return {};
    }
}

inline galay::mongo::AsyncMongoConfig loadAsyncMongoConfigFromEnv()
{
    galay::mongo::AsyncMongoConfig cfg = galay::mongo::AsyncMongoConfig::noTimeout();

    const char* buffer_size_env = std::getenv("GALAY_MONGO_ASYNC_BUFFER_SIZE");
    if (buffer_size_env != nullptr) {
        try {
            const unsigned long long parsed = std::stoull(buffer_size_env);
            if (parsed > 0 &&
                parsed <= static_cast<unsigned long long>(std::numeric_limits<size_t>::max())) {
                cfg.buffer_size = static_cast<size_t>(parsed);
            }
        } catch (...) {
        }
    }

    const char* reserve_env = std::getenv("GALAY_MONGO_ASYNC_PIPELINE_RESERVE");
    if (reserve_env != nullptr) {
        try {
            const unsigned long long parsed = std::stoull(reserve_env);
            if (parsed > 0 &&
                parsed <= static_cast<unsigned long long>(std::numeric_limits<size_t>::max())) {
                cfg.pipeline_reserve_per_command = static_cast<size_t>(parsed);
            }
        } catch (...) {
        }
    }

    cfg.logger_name = envOrDefault("GALAY_MONGO_LOGGER_NAME", cfg.logger_name);
    return cfg;
}

} // namespace mongo_example

#endif // GALAY_MONGO_EXAMPLE_CONFIG_H
