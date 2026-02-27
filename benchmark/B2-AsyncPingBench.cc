#include "benchmark/common/BenchCommon.h"
#include "galay-mongo/async/AsyncMongoClient.h"

#include <galay-kernel/kernel/Runtime.h>

#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <spdlog/spdlog.h>
#include <string>
#include <thread>
#include <vector>

using namespace galay::kernel;
using namespace galay::mongo;

namespace
{

size_t parsePositiveSize(const char* text, size_t fallback)
{
    if (text == nullptr) {
        return fallback;
    }
    try {
        const unsigned long long parsed = std::stoull(text);
        return parsed == 0ULL ? fallback : static_cast<size_t>(parsed);
    } catch (...) {
        return fallback;
    }
}

size_t loadAsyncFanout(int argc, char** argv)
{
    size_t fanout = 1;
    fanout = parsePositiveSize(std::getenv("GALAY_MONGO_BENCH_ASYNC_FANOUT"), fanout);

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        constexpr std::string_view prefix = "--fanout=";
        if (arg.rfind(prefix, 0) == 0) {
            fanout = parsePositiveSize(arg.substr(prefix.size()).data(), fanout);
        }
    }

    if (argc > 9 && argv[9] != nullptr && argv[9][0] != '\0') {
        fanout = parsePositiveSize(argv[9], fanout);
    }
    return fanout;
}

bool isFanoutArg(const char* arg)
{
    if (arg == nullptr) {
        return false;
    }
    return std::string_view(arg).rfind("--fanout=", 0) == 0;
}

} // namespace

struct AsyncBenchState
{
    std::atomic<size_t> next{0};
    std::atomic<size_t> attempted{0};
    std::atomic<size_t> ok{0};
    std::atomic<size_t> error{0};
    std::atomic<size_t> done_workers{0};

    std::mutex latency_mutex;
    std::vector<double> latencies_ms;

    std::mutex error_mutex;
    std::string first_error;

    void setFirstError(std::string message)
    {
        std::lock_guard<std::mutex> lock(error_mutex);
        if (first_error.empty()) {
            first_error = std::move(message);
        }
    }
};

Coroutine runWorker(IOScheduler* scheduler,
                    AsyncBenchState* state,
                    mongo_bench::BenchConfig cfg,
                    size_t worker_count)
{
    auto client = AsyncMongoClientBuilder().scheduler(scheduler).build();
    if (auto logger = client.logger().get()) {
        logger->set_level(spdlog::level::err);
    }

    std::vector<double> local_lat;
    local_lat.reserve((cfg.total_requests / worker_count) + 8);

    const std::expected<bool, MongoError> conn_result =
        co_await client.connect(mongo_bench::toMongoConfig(cfg));
    if (!conn_result) {
        state->error.fetch_add(1, std::memory_order_relaxed);
        state->setFirstError("connect failed: " + conn_result.error().message());
        state->done_workers.fetch_add(1, std::memory_order_release);
        co_return;
    }

    size_t local_attempted = 0;
    size_t local_ok = 0;
    size_t local_error = 0;

    while (true) {
        const size_t index = state->next.fetch_add(1, std::memory_order_relaxed);
        if (index >= cfg.total_requests) {
            break;
        }

        ++local_attempted;

        const auto t0 = std::chrono::steady_clock::now();
        const std::expected<MongoReply, MongoError> cmd_result = co_await client.ping(cfg.database);

        const auto t1 = std::chrono::steady_clock::now();
        const double latency =
            std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(t1 - t0).count();
        local_lat.push_back(latency);

        if (!cmd_result) {
            ++local_error;
            state->setFirstError("command failed: " + cmd_result.error().message());
        } else {
            ++local_ok;
        }
    }

    state->attempted.fetch_add(local_attempted, std::memory_order_relaxed);
    state->ok.fetch_add(local_ok, std::memory_order_relaxed);
    state->error.fetch_add(local_error, std::memory_order_relaxed);

    co_await client.close();

    {
        std::lock_guard<std::mutex> lock(state->latency_mutex);
        state->latencies_ms.insert(state->latencies_ms.end(), local_lat.begin(), local_lat.end());
    }

    state->done_workers.fetch_add(1, std::memory_order_release);
}

int main(int argc, char** argv)
{
    if (argc > 1 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help")) {
        mongo_bench::printUsage(argv[0]);
        std::cout << "Async extra: --fanout=N or argv[9] or env GALAY_MONGO_BENCH_ASYNC_FANOUT "
                     "(default 1)\n";
        return 0;
    }

    std::vector<char*> filtered_argv;
    filtered_argv.reserve(static_cast<size_t>(argc));
    filtered_argv.push_back(argv[0]);
    for (int i = 1; i < argc; ++i) {
        if (isFanoutArg(argv[i])) {
            continue;
        }
        filtered_argv.push_back(argv[i]);
    }

    const auto cfg = mongo_bench::loadBenchConfig(static_cast<int>(filtered_argv.size()),
                                                  filtered_argv.data());
    mongo_bench::printBenchConfig("B2-AsyncPingBench", cfg);
    const size_t async_fanout = loadAsyncFanout(argc, argv);
    const size_t worker_count = cfg.concurrency * async_fanout;
    std::cout << "[B2-AsyncPingBench]"
              << " async_fanout=" << async_fanout
              << " worker_count=" << worker_count
              << std::endl;

    Runtime runtime;
    runtime.start();

    AsyncBenchState state;
    state.latencies_ms.reserve(cfg.total_requests);

    const auto start = std::chrono::steady_clock::now();

    for (size_t i = 0; i < worker_count; ++i) {
        IOScheduler* scheduler = runtime.getNextIOScheduler();
        if (!scheduler) {
            runtime.stop();
            std::cerr << "failed to get IO scheduler" << std::endl;
            return 1;
        }
        scheduler->spawn(runWorker(scheduler, &state, cfg, worker_count));
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::minutes(10);
    while (state.done_workers.load(std::memory_order_acquire) < worker_count &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    const bool timeout = state.done_workers.load(std::memory_order_acquire) < worker_count;
    const auto end = std::chrono::steady_clock::now();
    const auto duration_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    runtime.stop();

    const size_t ok_count = state.ok.load(std::memory_order_relaxed);
    const size_t err_count = state.error.load(std::memory_order_relaxed);
    const size_t attempted = state.attempted.load(std::memory_order_relaxed);

    mongo_bench::printBenchReport(attempted,
                                  ok_count,
                                  err_count,
                                  duration_ms,
                                  state.latencies_ms);

    if (!state.first_error.empty()) {
        std::cout << "First error: " << state.first_error << std::endl;
    }

    if (timeout) {
        std::cerr << "benchmark timeout" << std::endl;
        return 2;
    }

    return err_count == 0 ? 0 : 1;
}
