# Release Notes

## v1.0.0 - 2026-03-02

- 版本级别: 小版本
- Git 提交消息: `fix: add netinet/in.h to fix IPPROTO_TCP undefined error`
- Git tag: `v1.0.0`
- 变更摘要:
  - 在 `socket_options.h` 中补充 `netinet/in.h`，修复部分环境下 `IPPROTO_TCP` 未定义的问题。

## v1.1.0 - 2026-03-08

- 版本级别: 中版本
- Git 提交消息: `重构(mongo): 引入协议构建辅助并统一文件命名`
- Git tag: `v1.1.0`
- 变更摘要:
  - 引入协议构建辅助能力与 `t8_builder` 测试，补强 Mongo 协议构建路径。
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

## v2.0.0 - 2026-04-29

- 版本级别：大版本（major）
- Git 提交消息：`refactor: 统一源码文件命名规范`
- Git Tag：`v2.0.0`
- 自述摘要：
  - 将源码、头文件、测试、示例与 benchmark 文件统一重命名为 lower_snake_case，编号前缀同步改为小写下划线形式。
  - 同步更新 CMake/Bazel 构建描述、模块入口、README/docs、脚本和所有项目内 include 路径引用。
  - 移除项目内相对 include，统一使用基于公开 include 根或模块根的非相对路径。
