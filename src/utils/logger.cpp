#include "utils/logger.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>

namespace xiaozhi {

Logger::Logger() 
    : level_(LogLevel::INFO)
    , initialized_(false) {
}

Logger::~Logger() {
    Close();
}

bool Logger::Initialize(LogLevel level, const std::string& file_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    level_ = level;
    file_path_ = file_path;
    
    if (!file_path_.empty()) {
        file_stream_ = std::make_unique<std::ofstream>(file_path_, std::ios::app);
        if (!file_stream_->is_open()) {
            std::cerr << "Failed to open log file: " << file_path_ << std::endl;
            return false;
        }
    }
    
    initialized_ = true;
    return true;
}

void Logger::SetLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    level_ = level;
}

LogLevel Logger::GetLevel() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return level_;
}

void Logger::Log(LogLevel level, const std::string& message, 
                 const char* file, int line, const char* function) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_ || level < level_) {
        return;
    }
    
    std::string formatted_message = FormatMessage(level, message, file, line, function);
    
    // Output to console
    std::cout << formatted_message << std::endl;
    
    // Output to file if available
    if (file_stream_ && file_stream_->is_open()) {
        *file_stream_ << formatted_message << std::endl;
        file_stream_->flush();
    }
}

void Logger::Flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::cout.flush();
    if (file_stream_ && file_stream_->is_open()) {
        file_stream_->flush();
    }
}

void Logger::Close() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (file_stream_ && file_stream_->is_open()) {
        file_stream_->close();
    }
    file_stream_.reset();
    initialized_ = false;
}

Logger& Logger::GetInstance() {
    static Logger instance;
    return instance;
}

std::string Logger::FormatMessage(LogLevel level, const std::string& message,
                                 const char* file, int line, const char* function) {
    std::ostringstream oss;
    
    // Timestamp
    oss << "[" << GetTimeString() << "] ";
    
    // Log level
    oss << "[" << GetLevelString(level) << "] ";
    
    // Message
    oss << message;
    
    // Source location (only for debug builds or trace/debug levels)
    if (file && line > 0 && (level <= LogLevel::DEBUG)) {
        oss << " (" << file << ":" << line;
        if (function) {
            oss << " in " << function;
        }
        oss << ")";
    }
    
    return oss.str();
}

const char* Logger::GetLevelString(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO ";
        case LogLevel::WARN:  return "WARN ";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

std::string Logger::GetTimeString() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << ms.count();
    
    return oss.str();
}

} // namespace xiaozhi
