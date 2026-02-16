#include "benchmark/common/BenchCommon.h"
#include "galay-mongo/sync/MongoSession.h"

#include <atomic>
#include <chrono>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

using namespace galay::mongo;

int main(int argc, char** argv)
{
    if (argc > 1 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help")) {
        mongo_bench::printUsage(argv[0]);
        return 0;
    }

    const auto cfg = mongo_bench::loadBenchConfig(argc, argv);
    mongo_bench::printBenchConfig("B1-SyncPingBench", cfg);

    std::vector<std::unique_ptr<MongoSession>> sessions;
    sessions.reserve(cfg.concurrency);

    const auto mongo_cfg = mongo_bench::toMongoConfig(cfg);
    for (size_t i = 0; i < cfg.concurrency; ++i) {
        auto session = std::make_unique<MongoSession>();
        auto conn = session->connect(mongo_cfg);
        if (!conn) {
            std::cerr << "connect failed (worker " << i << "): "
                      << conn.error().message() << std::endl;
            return 1;
        }
        sessions.push_back(std::move(session));
    }

    std::atomic<size_t> next{0};
    std::atomic<size_t> ok{0};
    std::atomic<size_t> error{0};
    std::mutex lat_mutex;
    std::vector<double> latencies_ms;
    latencies_ms.reserve(cfg.total_requests);

    const auto start = std::chrono::steady_clock::now();

    std::vector<std::thread> workers;
    workers.reserve(cfg.concurrency);

    for (size_t i = 0; i < cfg.concurrency; ++i) {
        workers.emplace_back([&, i]() {
            std::vector<double> local_lat;
            local_lat.reserve((cfg.total_requests / cfg.concurrency) + 8);
            size_t local_ok = 0;
            size_t local_error = 0;

            MongoSession& session = *sessions[i];
            while (true) {
                const size_t index = next.fetch_add(1, std::memory_order_relaxed);
                if (index >= cfg.total_requests) {
                    break;
                }

                const auto t0 = std::chrono::steady_clock::now();
                const auto result = session.ping(cfg.database);
                const auto t1 = std::chrono::steady_clock::now();

                const double latency =
                    std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(t1 - t0)
                        .count();
                local_lat.push_back(latency);

                if (result) {
                    ++local_ok;
                } else {
                    ++local_error;
                }
            }

            ok.fetch_add(local_ok, std::memory_order_relaxed);
            error.fetch_add(local_error, std::memory_order_relaxed);

            std::lock_guard<std::mutex> lock(lat_mutex);
            latencies_ms.insert(latencies_ms.end(), local_lat.begin(), local_lat.end());
        });
    }

    for (auto& worker : workers) {
        worker.join();
    }

    const auto end = std::chrono::steady_clock::now();
    const auto duration_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    for (auto& session : sessions) {
        session->close();
    }

    const size_t ok_count = ok.load(std::memory_order_relaxed);
    const size_t err_count = error.load(std::memory_order_relaxed);

    mongo_bench::printBenchReport(cfg.total_requests,
                                  ok_count,
                                  err_count,
                                  duration_ms,
                                  latencies_ms);

    return err_count == 0 ? 0 : 1;
}
