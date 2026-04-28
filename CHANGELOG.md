# Changelog

本文件记录 `galay-mongo` 的发布变化。

- 版本号遵循语义化版本：大改动升主版本，新功能升次版本，修复与兼容性调整升修订版本。
- 每次提交前先更新本文件；未发版内容先写入 `## [Unreleased]`。
- 已发版内容使用 `## [vX.Y.Z] - YYYY-MM-DD` 标题，并按主线归纳关键变化。
- 仅记录对使用者有意义的代码、配置、兼容性与文档变化，不罗列完整 diff。

## [Unreleased]

## [v1.2.0] - 2026-04-27

### Added

- 为 `AsyncMongoClient` 的公开 awaitable（`connect` / `command` / `ping` / `pipeline`）补齐调用点 `.timeout(...)` 能力，统一异步 Mongo API 与 `galay-http` 的 whole-operation timeout 用法。

### Changed

- 将 Mongo 异步客户端整体重构为状态机 awaitable 风格，补齐 `connect` 与 pipeline/command 路径的一致状态机实现，统一与 `galay-http` 的异步交互模型。
- 移除 `AsyncMongoConfig` 中旧的 send/recv split timeout 配置，改为由调用方在单次操作上显式附着 whole timeout，并同步更新 builder、测试配置与示例配置模型。
- 同步迁移 include/import 两套异步示例与 `T3` / `T5` / `T6` 测试，全部改用单次操作 timeout 入口，避免重复 await 带来的重复执行副作用。

### Fixed

- 修正 whole-timeout 迁移过程中的 pipeline/CRUD 错误处理细节，保证超时与服务端错误继续统一映射为 Mongo 侧错误结果，并通过真实 Mongo 实例验证成功路径与超时路径行为。

## [v1.1.2] - 2026-04-23

### Changed

- 将源码仓库中的包配置模板重命名为统一的小写 kebab-case `galay-mongo-config.cmake.in`，收敛 `galay-*` 子项目之间的文件命名风格。
- 同步更新 `configure_package_config_file(...)` 的模板路径，继续输出兼容现有消费者的 `galay-mongo-config.cmake` 与版本文件。

## [v1.1.1] - 2026-04-22

### Changed

- 适配 `galay-kernel v3.4.4`，将异步客户端切换到新的 `Task` 任务模型与协程接口。
- 将异步示例、测试与基准中的调度入口统一为 `scheduleTask(...)`，与新内核调度器保持一致。
- 调整 CMake 打包配置，优先查找系统安装的 `galay-kernel`，并补齐导出包版本元数据。

### Fixed

- 修正安装后的包配置命名，导出 `galay-mongo-config.cmake` 与版本文件，确保下游 `find_package(galay-mongo CONFIG REQUIRED)` 可用。

### Docs

- 新增发布记录与变更日志，保证发布文档与 Git tag 注解一致。

## [v1.1.0] - 2026-03-08

### Added

- 新增协议构建辅助能力与 `T8-protocol_builder` 测试。
- 新增 `MongoBufferProvider`，补充异步处理链路支撑。

### Changed

- 重构异步客户端与 BSON 协议相关实现，统一协议构建入口。
- 统一 benchmark、examples、test 文件命名风格。

## [v1.0.0] - 2026-03-02

### Fixed

- 在 `SocketOptions.h` 中补充 `netinet/in.h` 头文件，修复 `IPPROTO_TCP` 在部分环境下未定义的问题。
