# Changelog

本文件记录 `galay-mongo` 的发布变化。

- 版本号遵循语义化版本：大改动升主版本，新功能升次版本，修复与兼容性调整升修订版本。
- 每次提交前先更新本文件；未发版内容先写入 `## [Unreleased]`。
- 已发版内容使用 `## [vX.Y.Z] - YYYY-MM-DD` 标题，并按主线归纳关键变化。
- 仅记录对使用者有意义的代码、配置、兼容性与文档变化，不罗列完整 diff。

## [Unreleased]

- 暂无未发版变更。

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
