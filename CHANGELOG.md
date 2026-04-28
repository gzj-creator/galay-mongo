# CHANGELOG

维护说明：
- 未打 tag 的改动先写入 `

## [Unreleased]

## [v2.0.0] - 2026-04-29

### Changed
- 统一源码、头文件、测试、示例与 benchmark 文件命名为 `lower_snake_case`，编号前缀同步使用 `t<number>_`、`e<number>_` 与 `b<number>_` 风格。
- 同步更新构建脚本、模块入口、示例、测试、文档与脚本中的文件路径引用。
- 将项目内头文件包含调整为基于公开 include 根或模块根的非相对路径。

### Release
- 按大版本发布要求提升版本到 `v2.0.0`。

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

- 新增协议构建辅助能力与 `t8_builder` 测试。
- 新增 `MongoBufferProvider`，补充异步处理链路支撑。

### Changed

- 重构异步客户端与 BSON 协议相关实现，统一协议构建入口。
- 统一 benchmark、examples、test 文件命名风格。

## [v1.0.0] - 2026-03-02

### Fixed

- 在 `socket_options.h` 中补充 `netinet/in.h` 头文件，修复 `IPPROTO_TCP` 在部分环境下未定义的问题。
