# galay-mongo

基于 `galay-kernel` 的 C++23 MongoDB 客户端库，提供同步会话和协程异步 API。

## 特性

- 支持 MongoDB `OP_MSG` 协议（命令请求/响应）
- 内置 BSON 编解码（常用类型：`null/bool/int32/int64/double/string/binary/document/array`）
- 同步 API：`connect/command/ping/findOne/insertOne/updateOne/deleteOne`
- 同步认证：`SCRAM-SHA-256`（`saslStart/saslContinue`）
- 异步 API：`connect/command/ping`（支持 `SCRAM-SHA-256`）
- 异步 `ping` 快路径（模板缓存 + requestId 就地替换）
- 异步 pipeline：单连接多 in-flight（按 `requestId/responseTo` 关联响应）
- 统一 `std::expected` 错误模型

## 文档导航

建议从 `docs/03-使用指南.md` 开始：

1. [架构设计](docs/01-架构设计.md)
2. [API参考](docs/02-API参考.md)
3. [使用指南](docs/03-使用指南.md)
4. [性能测试](docs/04-性能测试.md)

## 依赖

- C++23 编译器（推荐 GCC 13+/Clang 16+）
- CMake 3.20+
- OpenSSL
- spdlog
- Galay 内部依赖（统一联调推荐）：
  - `galay-kernel`（构建必需）
  - `galay-utils`（推荐）
  - `galay-http`（推荐）

## 依赖安装（macOS / Homebrew）

```bash
brew install cmake spdlog openssl
```

## 依赖安装（Ubuntu / Debian）

```bash
sudo apt-get update
sudo apt-get install -y cmake g++ libspdlog-dev libssl-dev
```

## 拉取源码（统一联调推荐）

```bash
git clone https://github.com/gzj-creator/galay-kernel.git
git clone https://github.com/gzj-creator/galay-utils.git
git clone https://github.com/gzj-creator/galay-http.git
git clone https://github.com/gzj-creator/galay-mongo.git
```

仅单独构建 `galay-mongo` 时，最小内部依赖为 `galay-kernel`。

## 构建

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

常用开关：

- `-DGALAY_MONGO_BUILD_TESTS=ON/OFF`
- `-DGALAY_MONGO_BUILD_EXAMPLES=ON/OFF`
- `-DGALAY_MONGO_BUILD_BENCHMARKS=ON/OFF`
- `-DGALAY_MONGO_BUILD_SHARED_LIBS=ON/OFF`
- `-DGALAY_MONGO_ENABLE_IMPORT_COMPILATION=ON/OFF`
- `-DGALAY_MONGO_BUILD_MODULE_EXAMPLES=ON/OFF`

## 快速示例（同步）

```cpp
#include "galay-mongo/sync/MongoClient.h"
using namespace galay::mongo;

int main() {
    MongoClient session;

    MongoConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 27017;
    cfg.database = "test";

    auto ok = session.connect(cfg);
    if (!ok) return 1;

    auto ping = session.ping("test");
    if (!ping) return 1;

    session.close();
    return 0;
}
```

## 认证说明

- 同步 `MongoClient` 支持 `SCRAM-SHA-256`。
- 异步 `AsyncMongoClient` 支持 `SCRAM-SHA-256`（`connect(config)` 时配置 `username/password/auth_database`）。

## 测试

```bash
cmake -S . -B build -DGALAY_MONGO_BUILD_TESTS=ON
cmake --build build --parallel

# 协议单测
./build/test/T1-BsonProtocol

# 需要本地可访问 MongoDB
./build/test/T2-SyncMongoClient
./build/test/T3-AsyncMongoPipeline
./build/test/T4-SyncMongoFunctional
./build/test/T5-AsyncMongoFunctional
./build/test/T7-SyncLargeMessageBridge

# 可选：仅在设置用户名/密码时执行（否则自动 skip）
./build/test/T6-AuthCompatibility
```

可选环境变量：

- `GALAY_MONGO_HOST`
- `GALAY_MONGO_PORT`
- `GALAY_MONGO_DB`
- `GALAY_MONGO_USER`
- `GALAY_MONGO_PASSWORD`
- `GALAY_MONGO_AUTH_DB`
- `GALAY_MONGO_HELLO_DB`
- `GALAY_MONGO_TCP_NODELAY`（`1/0`）
- `GALAY_MONGO_RECV_BUFFER_SIZE`
- `GALAY_MONGO_ASYNC_SEND_TIMEOUT_MS`
- `GALAY_MONGO_ASYNC_RECV_TIMEOUT_MS`
- `GALAY_MONGO_ASYNC_BUFFER_SIZE`
- `GALAY_MONGO_ASYNC_PIPELINE_RESERVE`
- `GALAY_MONGO_LOGGER_NAME`

## Examples

构建：

```bash
cmake -S . -B build -DGALAY_MONGO_BUILD_EXAMPLES=ON
cmake --build build --parallel
```

常用 include 示例：

```bash
./build/example/E1-SyncPing-Include
./build/example/E2-AsyncPing-Include
./build/example/E3-SyncCrud-Include
./build/example/E4-AsyncPipeline-Include
./build/example/E5-AsyncCommandCrud-Include
```

模块 import 示例（仅在 `GALAY_MONGO_BUILD_MODULE_EXAMPLES_EFFECTIVE=ON` 时生成）：

```bash
./build/example/E1-SyncPing-Import
./build/example/E2-AsyncPing-Import
./build/example/E3-SyncCrud-Import
./build/example/E4-AsyncPipeline-Import
./build/example/E5-AsyncCommandCrud-Import
```

## Benchmark

项目提供 `benchmark/` 目录与两个压测程序：

- `B1-SyncPingBench`（同步会话 + 多线程）
- `B2-AsyncPingBench`（异步客户端 + 协程并发）

构建：

```bash
cmake -S . -B build -DGALAY_MONGO_BUILD_BENCHMARKS=ON
cmake --build build --parallel
```

运行（参数顺序）：

`[total] [concurrency] [host] [port] [db] [user] [password] [auth_db]`

示例：

```bash
./build/benchmark/B1-SyncPingBench 20000 100 140.143.142.251 27017 admin
./build/benchmark/B2-AsyncPingBench 20000 100 140.143.142.251 27017 admin
./build/benchmark/B2-AsyncPingBench 20000 100 140.143.142.251 27017 admin --fanout=2
```

也可用环境变量：

- `GALAY_MONGO_HOST`
- `GALAY_MONGO_PORT`
- `GALAY_MONGO_DB`
- `GALAY_MONGO_USER`
- `GALAY_MONGO_PASSWORD`
- `GALAY_MONGO_AUTH_DB`
- `GALAY_MONGO_BENCH_TOTAL`
- `GALAY_MONGO_BENCH_CONCURRENCY`
- `GALAY_MONGO_BENCH_ASYNC_FANOUT`（仅 `B2`，默认 `1`）

## 模块接口

- `galay-mongo/module/galay.mongo.cppm`
- `galay-mongo/module/ModulePrelude.hpp`

支持模块的编译器可使用：

```cpp
import galay.mongo;
```
