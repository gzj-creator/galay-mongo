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
