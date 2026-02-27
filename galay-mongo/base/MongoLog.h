#ifndef GALAY_MONGO_LOG_H
#define GALAY_MONGO_LOG_H

#include <memory>
#include <mutex>
#include <string>

#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

namespace galay::mongo
{

using MongoLoggerPtr = std::shared_ptr<spdlog::logger>;

class MongoLog
{
public:
    static MongoLog* getInstance()
    {
        static MongoLog instance;
        return &instance;
    }

    static void enable()
    {
        console();
    }

    static void console()
    {
        console("MongoLogger");
    }

    static void console(const std::string& logger_name)
    {
        auto instance = getInstance();
        std::lock_guard<std::mutex> lock(instance->m_mutex);
        try {
            auto logger = spdlog::get(logger_name);
            if (!logger) {
                logger = spdlog::stdout_color_mt(logger_name);
            }
            applyDefault(logger);
            instance->m_logger = std::move(logger);
        } catch (const spdlog::spdlog_ex&) {
            instance->m_logger = spdlog::get(logger_name);
        }
    }

    static void file(const std::string& log_file_path = "galay-mongo.log",
                     const std::string& logger_name = "MongoLogger",
                     bool truncate = false)
    {
        auto instance = getInstance();
        std::lock_guard<std::mutex> lock(instance->m_mutex);
        auto logger = std::make_shared<spdlog::logger>(
            logger_name,
            std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file_path, !truncate));
        applyDefault(logger);
        instance->m_logger = std::move(logger);
    }

    static void disable()
    {
        auto instance = getInstance();
        std::lock_guard<std::mutex> lock(instance->m_mutex);
        if (instance->m_logger) {
            instance->m_logger->set_level(spdlog::level::off);
        }
        instance->m_logger.reset();
    }

    static void setLogger(MongoLoggerPtr logger)
    {
        auto instance = getInstance();
        std::lock_guard<std::mutex> lock(instance->m_mutex);
        instance->m_logger = std::move(logger);
    }

    MongoLoggerPtr getLogger() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_logger;
    }

private:
    static void applyDefault(const MongoLoggerPtr& logger)
    {
        if (!logger) {
            return;
        }
        logger->set_pattern("[%Y-%m-%d %T.%e] [%^%L%$] [%s:%#] %v");
#ifdef ENABLE_DEBUG
        logger->set_level(spdlog::level::debug);
#else
        logger->set_level(spdlog::level::info);
#endif
    }

private:
    mutable std::mutex m_mutex;
    MongoLoggerPtr m_logger;
};

class MongoLogger
{
public:
    MongoLogger() = default;
    explicit MongoLogger(MongoLoggerPtr logger)
        : m_logger(std::move(logger))
    {
    }

    void ensure(const std::string& logger_name)
    {
        if (m_logger) {
            return;
        }

        m_logger = MongoLog::getInstance()->getLogger();
        if (m_logger) {
            return;
        }

        try {
            m_logger = spdlog::get(logger_name);
        } catch (const spdlog::spdlog_ex&) {
            m_logger = nullptr;
        }
    }

    void set(MongoLoggerPtr logger)
    {
        m_logger = std::move(logger);
    }

    MongoLoggerPtr get() const
    {
        return m_logger;
    }

    bool valid() const
    {
        return static_cast<bool>(m_logger);
    }

private:
    MongoLoggerPtr m_logger;
};

namespace detail
{
inline MongoLoggerPtr resolveLogger(const MongoLoggerPtr& logger)
{
    if (logger) {
        return logger;
    }
    return MongoLog::getInstance()->getLogger();
}
} // namespace detail

} // namespace galay::mongo

/// @name 日志宏（logger 为空时自动尝试全局 logger）.
/// @{
#define MongoLogTrace(logger, ...) \
    do { auto _logger = ::galay::mongo::detail::resolveLogger((logger)); if (_logger) SPDLOG_LOGGER_TRACE(_logger, __VA_ARGS__); } while (0)

#define MongoLogDebug(logger, ...) \
    do { auto _logger = ::galay::mongo::detail::resolveLogger((logger)); if (_logger) SPDLOG_LOGGER_DEBUG(_logger, __VA_ARGS__); } while (0)

#define MongoLogInfo(logger, ...) \
    do { auto _logger = ::galay::mongo::detail::resolveLogger((logger)); if (_logger) SPDLOG_LOGGER_INFO(_logger, __VA_ARGS__); } while (0)

#define MongoLogWarn(logger, ...) \
    do { auto _logger = ::galay::mongo::detail::resolveLogger((logger)); if (_logger) SPDLOG_LOGGER_WARN(_logger, __VA_ARGS__); } while (0)

#define MongoLogError(logger, ...) \
    do { auto _logger = ::galay::mongo::detail::resolveLogger((logger)); if (_logger) SPDLOG_LOGGER_ERROR(_logger, __VA_ARGS__); } while (0)
/// @}

#endif // GALAY_MONGO_LOG_H
