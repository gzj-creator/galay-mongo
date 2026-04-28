# Release Notes

## v1.0.0 - 2026-03-02

- 版本级别: 小版本
- Git 提交消息: `fix: add netinet/in.h to fix IPPROTO_TCP undefined error`
- Git tag: `v1.0.0`
- 变更摘要:
  - 在 `SocketOptions.h` 中补充 `netinet/in.h`，修复部分环境下 `IPPROTO_TCP` 未定义的问题。

## v1.1.0 - 2026-03-08

- 版本级别: 中版本
- Git 提交消息: `重构(mongo): 引入协议构建辅助并统一文件命名`
- Git tag: `v1.1.0`
- 变更摘要:
  - 引入协议构建辅助能力与 `T8-protocol_builder` 测试，补强 Mongo 协议构建路径。
  - 重构异步客户端与 BSON 协议处理流程，并新增 `MongoBufferProvider` 支撑异步链路。
  - 统一 benchmark、examples、test 文件命名风格，收敛工程结构。

## v1.1.1 - 2026-04-22

- 版本级别: 小版本
- Git 提交消息: `fix(mongo): 兼容 galay-kernel v3.4.4 并补齐发布包配置`
- Git tag: `v1.1.1`
- 变更摘要:
  - 适配 `galay-kernel v3.4.4`，将异步客户端迁移到 `Task` 任务模型与新的协程接口。
  - 将异步示例、测试与基准中的调度入口统一为 `scheduleTask(...)`，与新内核调度器保持一致。
  - 调整安装与导出配置，支持系统 `galay-kernel` 查找，并补齐 `galay-mongo-config.cmake` 与版本文件供下游消费。
  - 补充 `CHANGELOG.md` 与发布记录，使文档、提交与 Git tag 注解一致。

## v1.1.2 - 2026-04-23

- 版本级别: 小版本
- Git 提交消息: `chore: 发布 v1.1.2`
- Git tag: `v1.1.2`
- 变更摘要:
  - 将源码仓库中的包配置模板重命名为小写 kebab-case `galay-mongo-config.cmake.in`，统一 `galay-*` 子项目的模板文件风格。
  - 同步调整 `configure_package_config_file(...)` 的模板输入路径，同时保持安装导出的 `galay-mongo-config.cmake` 与版本文件名兼容不变。

## v1.2.0 - 2026-04-27

- 版本级别: 中版本
- Git 提交消息: `feat: 将异步 Mongo 客户端统一为状态机 whole-timeout 语义`
- Git tag: `v1.2.0`
- 变更摘要:
  - 将 `AsyncMongoClient` 公开异步接口统一到状态机 awaitable 风格，补齐 `connect` 与 command/pipeline 路径的一致实现方式，和 `galay-http` 保持同一套异步交互模型。
  - 为 `connect`、`command`、`ping`、`pipeline` 的公开 awaitable 补齐调用点 `.timeout(...)` 能力，并将 timeout 语义收敛为覆盖整个逻辑操作的 whole timeout。
  - 移除 `AsyncMongoConfig` 中旧的 send/recv split timeout 配置，同步更新 builder、测试配置、include/import 示例与 `T3`/`T5`/`T6` 测试用法。
  - 通过真实 Mongo 实例验证成功路径与超时路径，确认 connect/auth 流程与 pipeline/CRUD 操作都按 Mongo 侧 timeout 语义稳定返回。
