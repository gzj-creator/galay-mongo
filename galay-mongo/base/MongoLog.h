#ifndef GALAY_MONGO_LOG_H
#define GALAY_MONGO_LOG_H

#include <memory>
#include <string>

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

namespace galay::mongo
{

/// 日志管理器，封装 spdlog::logger 的懒初始化和访问
class MongoLogger
{
public:
    MongoLogger() = default;
    /// 使用已有的 spdlog logger 构造
    explicit MongoLogger(std::shared_ptr<spdlog::logger> logger)
        : m_logger(std::move(logger))
    {
    }

    /// 确保 logger 已初始化；若未设置则按名称查找或创建 stdout 彩色 logger
    void ensure(const std::string& logger_name)
    {
        if (m_logger) {
            return;
        }

        try {
            m_logger = spdlog::get(logger_name);
            if (!m_logger) {
                m_logger = spdlog::stdout_color_mt(logger_name);
            }
        } catch (const spdlog::spdlog_ex&) {
            m_logger = spdlog::get(logger_name);
        }
    }

    /// 替换当前 logger
    void set(std::shared_ptr<spdlog::logger> logger)
    {
        m_logger = std::move(logger);
    }

    /// 获取底层 spdlog logger（可能为空）
    std::shared_ptr<spdlog::logger> get() const
    {
        return m_logger;
    }

    /// 判断 logger 是否已初始化
    bool valid() const
    {
        return static_cast<bool>(m_logger);
    }

private:
    std::shared_ptr<spdlog::logger> m_logger;
};

} // namespace galay::mongo

/// @name 日志宏（logger 为空时自动跳过）
/// @{
#define MongoLogTrace(logger, ...) \
    do { if (logger) SPDLOG_LOGGER_TRACE(logger, __VA_ARGS__); } while(0)

#define MongoLogDebug(logger, ...) \
    do { if (logger) SPDLOG_LOGGER_DEBUG(logger, __VA_ARGS__); } while(0)

#define MongoLogInfo(logger, ...) \
    do { if (logger) SPDLOG_LOGGER_INFO(logger, __VA_ARGS__); } while(0)

#define MongoLogWarn(logger, ...) \
    do { if (logger) SPDLOG_LOGGER_WARN(logger, __VA_ARGS__); } while(0)

#define MongoLogError(logger, ...) \
    do { if (logger) SPDLOG_LOGGER_ERROR(logger, __VA_ARGS__); } while(0)
/// @}

#endif // GALAY_MONGO_LOG_H
