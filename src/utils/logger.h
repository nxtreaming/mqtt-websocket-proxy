#pragma once

#include "common/types.h"
#include <string>
#include <memory>
#include <fstream>
#include <mutex>
#include <sstream>

namespace xiaozhi {

/**
 * @brief Simple logging system
 */
class Logger {
public:
    /**
     * @brief Constructor
     */
    Logger();

    /**
     * @brief Destructor
     */
    ~Logger();

    /**
     * @brief Initialize logging system
     * @param level Log level
     * @param file_path Log file path (empty string means console output only)
     * @return Whether successful
     */
    bool Initialize(LogLevel level, const std::string& file_path = "");

    /**
     * @brief Set log level
     * @param level Log level
     */
    void SetLevel(LogLevel level);

    /**
     * @brief Get log level
     * @return Current log level
     */
    LogLevel GetLevel() const;

    /**
     * @brief Log a message
     * @param level Log level
     * @param message Log message
     * @param file Source file name
     * @param line Source file line number
     * @param function Function name
     */
    void Log(LogLevel level, const std::string& message,
             const char* file = nullptr, int line = 0, const char* function = nullptr);

    /**
     * @brief Flush log buffer
     */
    void Flush();

    /**
     * @brief Close logging system
     */
    void Close();

    /**
     * @brief Get global logger instance
     * @return Global logger instance
     */
    static Logger& GetInstance();

private:
    /**
     * @brief Format log message
     * @param level Log level
     * @param message Original message
     * @param file Source file name
     * @param line Source file line number
     * @param function Function name
     * @return Formatted message
     */
    std::string FormatMessage(LogLevel level, const std::string& message,
                             const char* file, int line, const char* function);

    /**
     * @brief Get log level string
     * @param level Log level
     * @return Log level string
     */
    const char* GetLevelString(LogLevel level);

    /**
     * @brief Get current time string
     * @return Time string
     */
    std::string GetTimeString();

private:
    LogLevel level_;
    std::string file_path_;
    std::unique_ptr<std::ofstream> file_stream_;
    mutable std::mutex mutex_;
    bool initialized_;
};

} // namespace xiaozhi

// Log macro definitions
#define LOG_TRACE(msg) \
    xiaozhi::Logger::GetInstance().Log(xiaozhi::LogLevel::TRACE, msg, __FILE__, __LINE__, __FUNCTION__)

#define LOG_DEBUG(msg) \
    xiaozhi::Logger::GetInstance().Log(xiaozhi::LogLevel::DEBUG, msg, __FILE__, __LINE__, __FUNCTION__)

#define LOG_INFO(msg) \
    xiaozhi::Logger::GetInstance().Log(xiaozhi::LogLevel::INFO, msg, __FILE__, __LINE__, __FUNCTION__)

#define LOG_WARN(msg) \
    xiaozhi::Logger::GetInstance().Log(xiaozhi::LogLevel::WARN, msg, __FILE__, __LINE__, __FUNCTION__)

#define LOG_ERROR(msg) \
    xiaozhi::Logger::GetInstance().Log(xiaozhi::LogLevel::ERROR, msg, __FILE__, __LINE__, __FUNCTION__)

#define LOG_FATAL(msg) \
    xiaozhi::Logger::GetInstance().Log(xiaozhi::LogLevel::FATAL, msg, __FILE__, __LINE__, __FUNCTION__)

// Formatted log macros
#define LOG_TRACE_F(fmt, ...) \
    do { \
        std::ostringstream oss; \
        oss << fmt; \
        LOG_TRACE(oss.str()); \
    } while(0)

#define LOG_DEBUG_F(fmt, ...) \
    do { \
        std::ostringstream oss; \
        oss << fmt; \
        LOG_DEBUG(oss.str()); \
    } while(0)

#define LOG_INFO_F(fmt, ...) \
    do { \
        std::ostringstream oss; \
        oss << fmt; \
        LOG_INFO(oss.str()); \
    } while(0)

#define LOG_WARN_F(fmt, ...) \
    do { \
        std::ostringstream oss; \
        oss << fmt; \
        LOG_WARN(oss.str()); \
    } while(0)

#define LOG_ERROR_F(fmt, ...) \
    do { \
        std::ostringstream oss; \
        oss << fmt; \
        LOG_ERROR(oss.str()); \
    } while(0)

#define LOG_FATAL_F(fmt, ...) \
    do { \
        std::ostringstream oss; \
        oss << fmt; \
        LOG_FATAL(oss.str()); \
    } while(0)
