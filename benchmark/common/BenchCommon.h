#ifndef GALAY_MONGO_BENCH_COMMON_H
#define GALAY_MONGO_BENCH_COMMON_H

#include "galay-mongo/base/MongoConfig.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace mongo_bench
{

struct BenchConfig
{
    std::string host = "127.0.0.1";
    uint16_t port = 27017;
    std::string database = "admin";
    std::string username;
    std::string password;
    std::string auth_database = "admin";

    size_t total_requests = 1000;
    size_t concurrency = 20;
};

inline std::string envOrDefault(const char* key, std::string fallback)
{
    const char* value = std::getenv(key);
    return value == nullptr ? std::move(fallback) : std::string(value);
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

inline size_t envSizeOrDefault(const char* key, size_t fallback)
{
    const char* value = std::getenv(key);
    if (value == nullptr) {
        return fallback;
    }

    try {
        const unsigned long long parsed = std::stoull(value);
        if (parsed == 0ULL) {
            return fallback;
        }
        return static_cast<size_t>(parsed);
    } catch (...) {
        return fallback;
    }
}

inline size_t argSizeOrDefault(int argc, char** argv, int index, size_t fallback)
{
    if (index >= argc) {
        return fallback;
    }

    try {
        const unsigned long long parsed = std::stoull(argv[index]);
        if (parsed == 0ULL) {
            return fallback;
        }
        return static_cast<size_t>(parsed);
    } catch (...) {
        return fallback;
    }
}

inline uint16_t argPortOrDefault(int argc, char** argv, int index, uint16_t fallback)
{
    if (index >= argc) {
        return fallback;
    }

    try {
        const int parsed = std::stoi(argv[index]);
        if (parsed <= 0 || parsed > 65535) {
            return fallback;
        }
        return static_cast<uint16_t>(parsed);
    } catch (...) {
        return fallback;
    }
}

inline std::string argStringOrDefault(int argc, char** argv, int index, std::string fallback)
{
    if (index >= argc) {
        return fallback;
    }
    return std::string(argv[index]);
}

inline BenchConfig loadBenchConfig(int argc, char** argv)
{
    BenchConfig cfg;

    cfg.host = envOrDefault("GALAY_MONGO_HOST", cfg.host);
    cfg.port = envPortOrDefault("GALAY_MONGO_PORT", cfg.port);
    cfg.database = envOrDefault("GALAY_MONGO_DB", cfg.database);
    cfg.username = envOrDefault("GALAY_MONGO_USER", cfg.username);
    cfg.password = envOrDefault("GALAY_MONGO_PASSWORD", cfg.password);
    cfg.auth_database = envOrDefault("GALAY_MONGO_AUTH_DB", cfg.auth_database);

    cfg.total_requests = envSizeOrDefault("GALAY_MONGO_BENCH_TOTAL", cfg.total_requests);
    cfg.concurrency = envSizeOrDefault("GALAY_MONGO_BENCH_CONCURRENCY", cfg.concurrency);

    // Args priority over env:
    // [1]=total [2]=concurrency [3]=host [4]=port [5]=db [6]=user [7]=password [8]=auth_db
    cfg.total_requests = argSizeOrDefault(argc, argv, 1, cfg.total_requests);
    cfg.concurrency = argSizeOrDefault(argc, argv, 2, cfg.concurrency);
    cfg.host = argStringOrDefault(argc, argv, 3, cfg.host);
    cfg.port = argPortOrDefault(argc, argv, 4, cfg.port);
    cfg.database = argStringOrDefault(argc, argv, 5, cfg.database);
    cfg.username = argStringOrDefault(argc, argv, 6, cfg.username);
    cfg.password = argStringOrDefault(argc, argv, 7, cfg.password);
    cfg.auth_database = argStringOrDefault(argc, argv, 8, cfg.auth_database);

    if (cfg.concurrency == 0) {
        cfg.concurrency = 1;
    }
    if (cfg.total_requests == 0) {
        cfg.total_requests = 1;
    }

    return cfg;
}

inline galay::mongo::MongoConfig toMongoConfig(const BenchConfig& cfg)
{
    galay::mongo::MongoConfig mongo_cfg;
    mongo_cfg.host = cfg.host;
    mongo_cfg.port = cfg.port;
    mongo_cfg.database = cfg.database;
    mongo_cfg.username = cfg.username;
    mongo_cfg.password = cfg.password;
    mongo_cfg.auth_database = cfg.auth_database;
    mongo_cfg.app_name = "galay-mongo-benchmark";
    return mongo_cfg;
}

inline void printBenchConfig(const std::string& bench_name, const BenchConfig& cfg)
{
    std::cout << "[" << bench_name << "]"
              << " host=" << cfg.host
              << " port=" << cfg.port
              << " db=" << cfg.database
              << " user=" << (cfg.username.empty() ? "<empty>" : cfg.username)
              << " total=" << cfg.total_requests
              << " concurrency=" << cfg.concurrency
              << std::endl;
}

inline double percentile(std::vector<double> values, double p)
{
    if (values.empty()) {
        return 0.0;
    }

    if (p <= 0.0) {
        p = 0.0;
    }
    if (p >= 1.0) {
        p = 1.0;
    }

    std::sort(values.begin(), values.end());
    const double idx = p * static_cast<double>(values.size() - 1);
    const size_t lo = static_cast<size_t>(std::floor(idx));
    const size_t hi = static_cast<size_t>(std::ceil(idx));

    if (lo == hi) {
        return values[lo];
    }

    const double weight = idx - static_cast<double>(lo);
    return values[lo] * (1.0 - weight) + values[hi] * weight;
}

inline void printBenchReport(size_t total,
                             size_t ok,
                             size_t error,
                             long long duration_ms,
                             const std::vector<double>& latencies_ms)
{
    const double seconds = static_cast<double>(duration_ms) / 1000.0;
    const double rps = seconds <= 0.0 ? 0.0 : static_cast<double>(ok) / seconds;

    std::cout << "Total requests: " << total << "\n"
              << "Success: " << ok << "\n"
              << "Errors: " << error << "\n"
              << "Duration(ms): " << duration_ms << "\n"
              << "Requests/sec: " << rps << "\n"
              << "Latency p50(ms): " << percentile(latencies_ms, 0.50) << "\n"
              << "Latency p95(ms): " << percentile(latencies_ms, 0.95) << "\n"
              << "Latency p99(ms): " << percentile(latencies_ms, 0.99) << std::endl;
}

inline void printUsage(const char* prog)
{
    std::cout
        << "Usage: " << prog << " [total] [concurrency] [host] [port] [db] [user] [password] [auth_db]\n"
        << "Example: " << prog << " 20000 100 140.143.142.251 27017 admin\n"
        << "Env override: GALAY_MONGO_HOST GALAY_MONGO_PORT GALAY_MONGO_DB\n"
        << "              GALAY_MONGO_USER GALAY_MONGO_PASSWORD GALAY_MONGO_AUTH_DB\n"
        << "              GALAY_MONGO_BENCH_TOTAL GALAY_MONGO_BENCH_CONCURRENCY\n";
}

} // namespace mongo_bench

#endif // GALAY_MONGO_BENCH_COMMON_H
