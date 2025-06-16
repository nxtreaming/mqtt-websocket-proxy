#pragma once

#include "common/types.h"
#include <string>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/inotify.h>
#include <unistd.h>
#endif

#include <nlohmann/json.hpp>

namespace xiaozhi {

/**
 * @brief Configuration manager with hot reload support (JavaScript version compatible)
 *
 * Responsible for loading, parsing and managing server configuration
 * Supports file watching and automatic configuration reloading
 */
class ConfigManager {
public:
    // Configuration change callback type (JavaScript version: configManager.on('configChanged', callback))
    using ConfigChangedCallback = std::function<void(const ServerConfig& config)>;
    /**
     * @brief Constructor
     */
    ConfigManager();

    /**
     * @brief Destructor
     */
    ~ConfigManager();

    /**
     * @brief Load configuration file
     * @param config_path Configuration file path
     * @return Error code, 0 indicates success
     */
    int LoadConfig(const std::string& config_path);

    /**
     * @brief Reload configuration file
     * @return Error code, 0 indicates success
     */
    int ReloadConfig();

    /**
     * @brief Get configuration
     * @return Server configuration
     */
    const ServerConfig& GetConfig() const;

    /**
     * @brief Validate configuration
     * @return Error code, 0 indicates success
     */
    int ValidateConfig() const;

    /**
     * @brief Get configuration file path
     * @return Configuration file path
     */
    const std::string& GetConfigPath() const;

    /**
     * @brief Check if MAC address is for development environment
     * @param mac_address MAC address
     * @return true if it's development environment
     */
    bool IsDevelopmentMac(const std::string& mac_address) const;

    /**
     * @brief Get WebSocket server list
     * @param is_development Whether it's development environment
     * @return WebSocket server URL list
     */
    const std::vector<std::string>& GetWebSocketServers(bool is_development) const;

    /**
     * @brief Randomly select a WebSocket server
     * @param is_development Whether it's development environment
     * @return WebSocket server URL
     */
    std::string SelectWebSocketServer(bool is_development) const;

    /**
     * @brief Start configuration file watching (JavaScript version: watchConfig)
     * @return Error code, 0 indicates success
     */
    int StartWatching();

    /**
     * @brief Stop configuration file watching
     */
    void StopWatching();

    /**
     * @brief Set configuration changed callback (JavaScript version: configManager.on('configChanged', callback))
     * @param callback Configuration changed callback
     */
    void SetConfigChangedCallback(ConfigChangedCallback callback);

    /**
     * @brief Check if configuration watching is enabled
     * @return true if watching is enabled
     */
    bool IsWatching() const;

private:
    /**
     * @brief Parse JSON configuration
     * @param json_config JSON configuration object
     * @return Error code, 0 indicates success
     */
    int ParseJsonConfig(const nlohmann::json& json_config);

    /**
     * @brief Parse MQTT configuration
     * @param mqtt_json MQTT configuration JSON
     * @return Error code, 0 indicates success
     */
    int ParseMqttConfig(const nlohmann::json& mqtt_json);

    /**
     * @brief Parse UDP configuration
     * @param udp_json UDP configuration JSON
     * @return Error code, 0 indicates success
     */
    int ParseUdpConfig(const nlohmann::json& udp_json);

    /**
     * @brief Parse WebSocket configuration
     * @param ws_json WebSocket configuration JSON
     * @return Error code, 0 indicates success
     */
    int ParseWebSocketConfig(const nlohmann::json& ws_json);

    /**
     * @brief Parse logging configuration
     * @param log_json Logging configuration JSON
     * @return Error code, 0 indicates success
     */
    int ParseLoggingConfig(const nlohmann::json& log_json);

    /**
     * @brief Parse MCP configuration
     * @param mcp_json MCP configuration JSON
     * @return Error code, 0 indicates success
     */
    int ParseMcpConfig(const nlohmann::json& mcp_json);

    /**
     * @brief Set default configuration
     */
    void SetDefaultConfig();

    /**
     * @brief Validate MQTT configuration
     * @return Error code, 0 indicates success
     */
    int ValidateMqttConfig() const;

    /**
     * @brief Validate UDP configuration
     * @return Error code, 0 indicates success
     */
    int ValidateUdpConfig() const;

    /**
     * @brief Validate WebSocket configuration
     * @return Error code, 0 indicates success
     */
    int ValidateWebSocketConfig() const;

    /**
     * @brief Override configuration from environment variables
     */
    void OverrideFromEnvironment();

    /**
     * @brief File watching thread function (JavaScript version: fs.watchFile)
     */
    void WatchingThreadFunction();

    /**
     * @brief Handle configuration file change (JavaScript version: loadConfig with change detection)
     */
    void HandleConfigFileChange();

    /**
     * @brief Check if configuration has changed
     * @param new_config New configuration
     * @return true if configuration has changed
     */
    bool HasConfigChanged(const ServerConfig& new_config) const;

#ifdef _WIN32
    /**
     * @brief Windows file watching implementation
     */
    void WatchFileWindows();
#else
    /**
     * @brief Linux file watching implementation using inotify
     */
    void WatchFileLinux();
#endif

private:
    ServerConfig config_;
    std::string config_path_;
    std::unique_ptr<nlohmann::json> json_config_;
    bool loaded_;

    // Hot reload related (JavaScript version compatible)
    std::atomic<bool> watching_;
    std::atomic<bool> stop_watching_;
    std::unique_ptr<std::thread> watching_thread_;
    std::mutex config_mutex_;
    ConfigChangedCallback config_changed_callback_;
    #ifdef _WIN32
    HANDLE stop_event_;
    #endif

    // Debounce timer (JavaScript version: watchDebounceTimer)
    std::chrono::steady_clock::time_point last_change_time_;
    static constexpr int DEBOUNCE_DELAY_MS = 100;
};

} // namespace xiaozhi
