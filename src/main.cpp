// Windows headers must be included first to avoid conflicts
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_   // Prevent winsock.h from being included
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>
// Undefine Windows macros that conflict with our code
#ifdef ERROR
#undef ERROR
#endif
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

#include "server/gateway_server.h"
#include "utils/logger.h"
#include "common/constants.h"
#include "common/error_codes.h"

#include <iostream>
#include <string>
#include <cstdlib>
#include <csignal>
#include <fstream>

using namespace xiaozhi;

// Global server instance
static std::unique_ptr<GatewayServer> g_server;

/**
 * @brief Signal handler function
 * @param signal Signal number
 */
void SignalHandler(int signal) {
    switch (signal) {
        case SIGINT:
            LOG_INFO("Received SIGINT signal, starting server shutdown...");
            break;
        case SIGTERM:
            LOG_INFO("Received SIGTERM signal, starting server shutdown...");
            break;
        default:
            LOG_WARN("Received unknown signal: " + std::to_string(signal));
            return;
    }

    if (g_server) {
        g_server->Stop();
    }
}

/**
 * @brief Setup signal handlers
 */
void SetupSignalHandlers() {
    std::signal(SIGINT, SignalHandler);
    std::signal(SIGTERM, SignalHandler);

#ifdef _WIN32
    // Windows-specific signal handling
    SetConsoleCtrlHandler([](DWORD dwCtrlType) -> BOOL {
        switch (dwCtrlType) {
            case CTRL_C_EVENT:
            case CTRL_BREAK_EVENT:
            case CTRL_CLOSE_EVENT:
            case CTRL_SHUTDOWN_EVENT:
                SignalHandler(SIGINT);
                return TRUE;
            default:
                return FALSE;
        }
    }, TRUE);
#endif
}

/**
 * @brief Print version information
 */
void PrintVersion() {
    std::cout << "xiaozhi-mqtt-gateway " << constants::VERSION_STRING << std::endl;
    std::cout << "Build Date: " << constants::BUILD_DATE << " " << constants::BUILD_TIME << std::endl;
    std::cout << "Copyright (c) 2024 Xiaozhi Team" << std::endl;
}

/**
 * @brief Print help information
 * @param program_name Program name
 */
void PrintHelp(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -c, --config FILE    Specify configuration file path (default: " << constants::DEFAULT_CONFIG_FILE << ")" << std::endl;
    std::cout << "  -d, --daemon         Run as daemon process" << std::endl;
    std::cout << "  -p, --pid FILE       Specify PID file path (default: " << constants::DEFAULT_PID_FILE << ")" << std::endl;
    std::cout << "  -l, --log-level LVL  Set log level (trace|debug|info|warn|error|fatal)" << std::endl;
    std::cout << "  -v, --version        Show version information" << std::endl;
    std::cout << "  -h, --help           Show this help information" << std::endl;
    std::cout << std::endl;
    std::cout << "Environment Variables:" << std::endl;
    std::cout << "  " << constants::ENV_MQTT_PORT << "      MQTT server port (default: " << constants::MQTT_DEFAULT_PORT << ")" << std::endl;
    std::cout << "  " << constants::ENV_UDP_PORT << "       UDP server port (default: " << constants::UDP_DEFAULT_PORT << ")" << std::endl;
    std::cout << "  " << constants::ENV_PUBLIC_IP << "     Server public IP (default: " << constants::DEFAULT_PUBLIC_IP << ")" << std::endl;
    std::cout << "  " << constants::ENV_CONFIG_FILE << "   Configuration file path" << std::endl;
    std::cout << "  " << constants::ENV_LOG_LEVEL << "    Log level" << std::endl;
    std::cout << "  " << constants::ENV_DEBUG << "         Debug mode (true|false)" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << program_name << "                           # Run with default configuration" << std::endl;
    std::cout << "  " << program_name << " -c /etc/gateway.json      # Specify configuration file" << std::endl;
    std::cout << "  " << program_name << " -d -p /var/run/gateway.pid # Daemon mode" << std::endl;
    std::cout << "  " << program_name << " -l debug                  # Debug mode" << std::endl;
}

/**
 * @brief Create daemon process (Unix/Linux only)
 * @return Error code, 0 indicates success
 */
int CreateDaemon() {
#ifdef _WIN32
    std::cerr << "Error: Windows does not support daemon mode" << std::endl;
    return error::NOT_IMPLEMENTED;
#else
    // First fork
    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "Error: First fork failed" << std::endl;
        return error::OPERATION_FAILED;
    }
    if (pid > 0) {
        // Parent process exits
        exit(0);
    }

    // Create new session
    if (setsid() < 0) {
        std::cerr << "Error: setsid failed" << std::endl;
        return error::OPERATION_FAILED;
    }

    // Second fork
    pid = fork();
    if (pid < 0) {
        std::cerr << "Error: Second fork failed" << std::endl;
        return error::OPERATION_FAILED;
    }
    if (pid > 0) {
        // Parent process exits
        exit(0);
    }

    // Set file permission mask
    umask(0);

    // Change working directory to root
    if (chdir("/") < 0) {
        std::cerr << "Error: Failed to change working directory" << std::endl;
        return error::OPERATION_FAILED;
    }

    // Close standard input/output
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    return error::SUCCESS;
#endif
}

/**
 * @brief Write PID file
 * @param pid_file PID file path
 * @return Error code, 0 indicates success
 */
int WritePidFile(const std::string& pid_file) {
#ifdef _WIN32
    (void)pid_file;
    // PID file is not needed on Windows
    return error::SUCCESS;
#else
    std::ofstream file(pid_file);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot create PID file: " << pid_file << std::endl;
        return error::FILE_CREATE_ERROR;
    }

    file << getpid() << std::endl;
    file.close();

    return error::SUCCESS;
#endif
}

/**
 * @brief Parse log level string
 * @param level_str Log level string
 * @return Log level
 */
LogLevel ParseLogLevel(const std::string& level_str) {
    if (level_str == "trace") return LogLevel::TRACE;
    if (level_str == "debug") return LogLevel::DEBUG;
    if (level_str == "info") return LogLevel::INFO;
    if (level_str == "warn") return LogLevel::WARN;
    if (level_str == "error") return LogLevel::ERROR;
    if (level_str == "fatal") return LogLevel::FATAL;

    std::cerr << "Warning: Unknown log level '" << level_str << "', using default level 'info'" << std::endl;
    return LogLevel::INFO;
}

/**
 * @brief Main function
 * @param argc Number of arguments
 * @param argv Argument array
 * @return Exit code
 */
int main(int argc, char* argv[]) {
    // Default parameters
    std::string config_file = constants::DEFAULT_CONFIG_FILE;
    std::string pid_file = constants::DEFAULT_PID_FILE;
    std::string log_level_str = constants::DEFAULT_LOG_LEVEL;
    bool daemon_mode = false;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                config_file = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "-d" || arg == "--daemon") {
            daemon_mode = true;
        } else if (arg == "-p" || arg == "--pid") {
            if (i + 1 < argc) {
                pid_file = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "-l" || arg == "--log-level") {
            if (i + 1 < argc) {
                log_level_str = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires an argument" << std::endl;
                return 1;
            }
        } else if (arg == "-v" || arg == "--version") {
            PrintVersion();
            return 0;
        } else if (arg == "-h" || arg == "--help") {
            PrintHelp(argv[0]);
            return 0;
        } else {
            std::cerr << "Error: Unknown option " << arg << std::endl;
            PrintHelp(argv[0]);
            return 1;
        }
    }

    // Override configuration from environment variables
    const char* env_config = std::getenv(constants::ENV_CONFIG_FILE);
    if (env_config) {
        config_file = env_config;
    }

    const char* env_log_level = std::getenv(constants::ENV_LOG_LEVEL);
    if (env_log_level) {
        log_level_str = env_log_level;
    }

    // Parse log level
    LogLevel log_level = ParseLogLevel(log_level_str);

    // Initialize logging system
    Logger& logger = Logger::GetInstance();
    if (!logger.Initialize(log_level)) {
        std::cerr << "Error: Failed to initialize logging system" << std::endl;
        return 1;
    }

    LOG_INFO("xiaozhi-mqtt-gateway starting...");
    LOG_INFO("Version: " + std::string(constants::VERSION_STRING));
    LOG_INFO("Configuration file: " + config_file);

    // Create daemon process
    if (daemon_mode) {
        LOG_INFO("Switching to daemon mode...");
        int ret = CreateDaemon();
        if (ret != error::SUCCESS) {
            LOG_ERROR("Failed to create daemon process: " + error::GetErrorMessage(ret));
            return 1;
        }

        // Write PID file
        ret = WritePidFile(pid_file);
        if (ret != error::SUCCESS) {
            LOG_ERROR("Failed to write PID file: " + error::GetErrorMessage(ret));
            return 1;
        }
        LOG_INFO("PID file: " + pid_file);
    }

    // Setup signal handlers
    SetupSignalHandlers();

    // Create and initialize server
    g_server = std::make_unique<GatewayServer>();

    int ret = g_server->Initialize(config_file);
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to initialize server: " + error::GetErrorMessage(ret));
        return 1;
    }

    // Start server
    ret = g_server->Start();
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to start server: " + error::GetErrorMessage(ret));
        return 1;
    }

    LOG_INFO("Server started successfully, running...");

    // Run server main loop
    g_server->Run();

    LOG_INFO("Server stopped");

    // Cleanup resources
    g_server.reset();

    return 0;
}
