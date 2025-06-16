#ifdef _WIN32
#include <windows.h>
#endif

#include "utils/config_manager.h"
#include "common/error_codes.h"
#include "common/constants.h"
#include "utils/logger.h"

#include <nlohmann/json.hpp>

#include <fstream>
#include <cstdlib>
#include <random>

namespace xiaozhi {

ConfigManager::ConfigManager()
    : loaded_(false)
    , watching_(false)
    , stop_watching_(false) {
    #ifdef _WIN32
    stop_event_ = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!stop_event_) {
        LOG_ERROR("Failed to create stop event");
    }
    #endif
    SetDefaultConfig();
}

ConfigManager::~ConfigManager() {
    StopWatching();
    #ifdef _WIN32
    if (stop_event_) {
        CloseHandle(stop_event_);
    }
    #endif
}

int ConfigManager::LoadConfig(const std::string& config_path) {
    config_path_ = config_path;
    
    std::ifstream file(config_path_);
    if (!file.is_open()) {
        LOG_ERROR("Failed to open config file: " + config_path_);
        return error::CONFIG_FILE_NOT_FOUND;
    }
    
    try {
        nlohmann::json json_config;
        file >> json_config;
        
        json_config_ = std::make_unique<nlohmann::json>(std::move(json_config));
        
        int ret = ParseJsonConfig(*json_config_);
        if (ret != error::SUCCESS) {
            return ret;
        }
        
        // Override from environment variables
        OverrideFromEnvironment();
        
        // Validate configuration
        ret = ValidateConfig();
        if (ret != error::SUCCESS) {
            return ret;
        }
        
        loaded_ = true;
        LOG_INFO("Configuration loaded successfully from: " + config_path_);
        return error::SUCCESS;
        
    } catch (const nlohmann::json::exception& e) {
        LOG_ERROR("JSON parse error: " + std::string(e.what()));
        return error::CONFIG_PARSE_ERROR;
    } catch (const std::exception& e) {
        LOG_ERROR("Config load error: " + std::string(e.what()));
        return error::CONFIG_ERROR;
    }
}

int ConfigManager::ReloadConfig() {
    if (config_path_.empty()) {
        LOG_ERROR("No config path set for reload");
        return error::CONFIG_ERROR;
    }
    
    return LoadConfig(config_path_);
}

const ServerConfig& ConfigManager::GetConfig() const {
    return config_;
}

int ConfigManager::ValidateConfig() const {
    int ret = ValidateMqttConfig();
    if (ret != error::SUCCESS) return ret;
    
    ret = ValidateUdpConfig();
    if (ret != error::SUCCESS) return ret;
    
    ret = ValidateWebSocketConfig();
    if (ret != error::SUCCESS) return ret;
    
    return error::SUCCESS;
}

const std::string& ConfigManager::GetConfigPath() const {
    return config_path_;
}

bool ConfigManager::IsDevelopmentMac(const std::string& mac_address) const {
    for (const auto& dev_mac : config_.websocket.development_mac_addresses) {
        if (dev_mac == mac_address) {
            return true;
        }
    }
    return false;
}

const std::vector<std::string>& ConfigManager::GetWebSocketServers(bool is_development) const {
    return is_development ? config_.websocket.development_servers 
                          : config_.websocket.production_servers;
}

std::string ConfigManager::SelectWebSocketServer(bool is_development) const {
    const auto& servers = GetWebSocketServers(is_development);
    if (servers.empty()) {
        return constants::DEFAULT_WEBSOCKET_SERVER;
    }
    
    if (servers.size() == 1) {
        return servers[0];
    }
    
    // Random selection
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, (int)servers.size() - 1);
    
    return servers[dis(gen)];
}

int ConfigManager::ParseJsonConfig(const nlohmann::json& json_config) {
    try {
        // Parse MQTT config
        if (json_config.contains("mqtt")) {
            int ret = ParseMqttConfig(json_config["mqtt"]);
            if (ret != error::SUCCESS) return ret;
        }
        
        // Parse UDP config
        if (json_config.contains("udp")) {
            int ret = ParseUdpConfig(json_config["udp"]);
            if (ret != error::SUCCESS) return ret;
        }
        
        // Parse WebSocket config
        if (json_config.contains("websocket")) {
            int ret = ParseWebSocketConfig(json_config["websocket"]);
            if (ret != error::SUCCESS) return ret;
        }
        
        // Parse logging config
        if (json_config.contains("logging")) {
            int ret = ParseLoggingConfig(json_config["logging"]);
            if (ret != error::SUCCESS) return ret;
        }
        
        // Parse MCP config
        if (json_config.contains("mcp")) {
            int ret = ParseMcpConfig(json_config["mcp"]);
            if (ret != error::SUCCESS) return ret;
        }
        
        // Parse debug flag
        if (json_config.contains("debug")) {
            config_.debug = json_config["debug"].get<bool>();
        }
        
        return error::SUCCESS;
        
    } catch (const nlohmann::json::exception& e) {
        LOG_ERROR("JSON config parse error: " + std::string(e.what()));
        return error::CONFIG_PARSE_ERROR;
    }
}

int ConfigManager::ParseMqttConfig(const nlohmann::json& mqtt_json) {
    if (mqtt_json.contains("host")) {
        config_.mqtt.host = mqtt_json["host"].get<std::string>();
    }
    if (mqtt_json.contains("port")) {
        config_.mqtt.port = mqtt_json["port"].get<uint16_t>();
    }
    if (mqtt_json.contains("max_connections")) {
        config_.mqtt.max_connections = mqtt_json["max_connections"].get<uint32_t>();
    }
    if (mqtt_json.contains("max_payload_size")) {
        config_.mqtt.max_payload_size = mqtt_json["max_payload_size"].get<uint32_t>();
    }
    
    return error::SUCCESS;
}

int ConfigManager::ParseUdpConfig(const nlohmann::json& udp_json) {
    if (udp_json.contains("host")) {
        config_.udp.host = udp_json["host"].get<std::string>();
    }
    if (udp_json.contains("port")) {
        config_.udp.port = udp_json["port"].get<uint16_t>();
    }
    if (udp_json.contains("public_ip")) {
        config_.udp.public_ip = udp_json["public_ip"].get<std::string>();
    }
    
    return error::SUCCESS;
}

int ConfigManager::ParseWebSocketConfig(const nlohmann::json& ws_json) {
    if (ws_json.contains("development_servers")) {
        config_.websocket.development_servers = ws_json["development_servers"].get<std::vector<std::string>>();
    }
    if (ws_json.contains("production_servers")) {
        config_.websocket.production_servers = ws_json["production_servers"].get<std::vector<std::string>>();
    }
    if (ws_json.contains("development_mac_addresses")) {
        config_.websocket.development_mac_addresses = ws_json["development_mac_addresses"].get<std::vector<std::string>>();
    }
    
    return error::SUCCESS;
}

int ConfigManager::ParseLoggingConfig(const nlohmann::json& log_json) {
    if (log_json.contains("enabled")) {
        config_.logging.enabled = log_json["enabled"].get<bool>();
    }
    if (log_json.contains("level")) {
        config_.logging.level = log_json["level"].get<std::string>();
    }
    if (log_json.contains("file_path")) {
        config_.logging.file_path = log_json["file_path"].get<std::string>();
    }
    
    return error::SUCCESS;
}

int ConfigManager::ParseMcpConfig(const nlohmann::json& mcp_json) {
    if (mcp_json.contains("enabled")) {
        config_.mcp.enabled = mcp_json["enabled"].get<bool>();
    }
    if (mcp_json.contains("max_tools_count")) {
        config_.mcp.max_tools_count = mcp_json["max_tools_count"].get<uint32_t>();
    }
    
    return error::SUCCESS;
}

void ConfigManager::SetDefaultConfig() {
    // Set default values as defined in types.h
    config_ = ServerConfig{};
}

int ConfigManager::ValidateMqttConfig() const {
    if (config_.mqtt.port == 0 || config_.mqtt.port > 65535) {
        LOG_ERROR("Invalid MQTT port: " + std::to_string(config_.mqtt.port));
        return error::CONFIG_INVALID_VALUE;
    }
    
    if (config_.mqtt.max_connections == 0) {
        LOG_ERROR("Invalid MQTT max_connections: 0");
        return error::CONFIG_INVALID_VALUE;
    }
    
    return error::SUCCESS;
}

int ConfigManager::ValidateUdpConfig() const {
    if (config_.udp.port == 0 || config_.udp.port > 65535) {
        LOG_ERROR("Invalid UDP port: " + std::to_string(config_.udp.port));
        return error::CONFIG_INVALID_VALUE;
    }
    
    if (config_.udp.public_ip.empty()) {
        LOG_ERROR("UDP public_ip cannot be empty");
        return error::CONFIG_INVALID_VALUE;
    }
    
    return error::SUCCESS;
}

int ConfigManager::ValidateWebSocketConfig() const {
    if (config_.websocket.production_servers.empty()) {
        LOG_WARN("No production WebSocket servers configured");
    }
    
    return error::SUCCESS;
}

void ConfigManager::OverrideFromEnvironment() {
    // Override MQTT port
    const char* mqtt_port = std::getenv(constants::ENV_MQTT_PORT);
    if (mqtt_port) {
        config_.mqtt.port = static_cast<uint16_t>(std::atoi(mqtt_port));
    }
    
    // Override UDP port
    const char* udp_port = std::getenv(constants::ENV_UDP_PORT);
    if (udp_port) {
        config_.udp.port = static_cast<uint16_t>(std::atoi(udp_port));
    }
    
    // Override public IP
    const char* public_ip = std::getenv(constants::ENV_PUBLIC_IP);
    if (public_ip) {
        config_.udp.public_ip = public_ip;
    }
    
    // Override log level
    const char* log_level = std::getenv(constants::ENV_LOG_LEVEL);
    if (log_level) {
        config_.logging.level = log_level;
    }
    
    // Override debug mode
    const char* debug = std::getenv(constants::ENV_DEBUG);
    if (debug) {
        config_.debug = (std::string(debug) == "true" || std::string(debug) == "1");
    }
}

int ConfigManager::StartWatching() {
    if (watching_.load()) {
        LOG_WARN("Configuration watching is already started");
        return error::ALREADY_EXISTS;
    }

    if (config_path_.empty()) {
        LOG_ERROR("Configuration path is empty, cannot start watching");
        return error::CONFIG_FILE_NOT_FOUND;
    }

    stop_watching_.store(false);
    watching_.store(true);

    // Start file monitoring thread (JavaScript version: this.watchConfig())
    watching_thread_ = std::make_unique<std::thread>(&ConfigManager::WatchingThreadFunction, this);

    LOG_INFO("Configuration file watching started: " + config_path_);
    return error::SUCCESS;
}

void ConfigManager::StopWatching() {
    if (!watching_.load()) {
        return;
    }

    LOG_INFO("Stopping configuration file watching...");

    stop_watching_.store(true);
    
    #ifdef _WIN32
    if (stop_event_) {
        SetEvent(stop_event_);
    }
    #endif
    
    watching_.store(false);

    if (watching_thread_ && watching_thread_->joinable()) {
        watching_thread_->join();
        watching_thread_.reset();
    }

    LOG_INFO("Configuration file watching stopped");
}

void ConfigManager::SetConfigChangedCallback(ConfigChangedCallback callback) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_changed_callback_ = std::move(callback);
}

bool ConfigManager::IsWatching() const {
    return watching_.load();
}

#ifdef _WIN32
void ConfigManager::WatchFileWindows() {
    std::wstring wpath = std::wstring(config_path_.begin(), config_path_.end());
    HANDLE hDir = CreateFileW(
        wpath.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Failed to open directory for watching: " + config_path_);
        return;
    }

    char buffer[1024];
    DWORD bytesReturned;
    OVERLAPPED overlapped = {0};
    overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    while (!stop_watching_.load()) {
        if (!ReadDirectoryChangesW(
            hDir,
            buffer,
            sizeof(buffer),
            FALSE,  // Watch subdirectories
            FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
            &bytesReturned,
            &overlapped,
            NULL
        )) {
            LOG_ERROR("ReadDirectoryChangesW failed");
            break;
        }

        // Wait for either a change or stop signal
        HANDLE handles[2] = { overlapped.hEvent, stop_event_ };
        DWORD result = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

        if (result == WAIT_OBJECT_0) {
            // File change detected
            PFILE_NOTIFY_INFORMATION notify = (PFILE_NOTIFY_INFORMATION)buffer;
            if (notify->Action == FILE_ACTION_MODIFIED) {
                HandleConfigFileChange();
            }
        } else if (result == WAIT_OBJECT_0 + 1) {
            // Stop event signaled
            break;
        } else {
            // Error occurred
            LOG_ERROR("WaitForMultipleObjects failed");
            break;
        }
    }

    CloseHandle(overlapped.hEvent);
    CloseHandle(hDir);
}
#else
void ConfigManager::WatchFileLinux() {
    int inotify_fd = inotify_init1(IN_NONBLOCK);
    if (inotify_fd == -1) {
        LOG_ERROR("Failed to initialize inotify: " + std::string(strerror(errno)));
        return;
    }

    // Get the directory containing the config file
    std::filesystem::path config_path(config_path_);
    std::string dir_path = config_path.parent_path().string();
    std::string file_name = config_path.filename().string();

    // Add watch for the directory containing the config file
    int watch_fd = inotify_add_watch(inotify_fd, dir_path.c_str(), 
                                   IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF);
    if (watch_fd == -1) {
        LOG_ERROR("Failed to add inotify watch on " + dir_path + ": " + strerror(errno));
        close(inotify_fd);
        return;
    }

    // Buffer for inotify events
    constexpr size_t BUF_LEN = (10 * (sizeof(struct inotify_event) + NAME_MAX + 1));
    char buffer[BUF_LEN];
    
    LOG_DEBUG("Watching for config file changes in: " + dir_path);

    while (!stop_watching_.load()) {
        fd_set fds;
        struct timeval tv;
        
        FD_ZERO(&fds);
        FD_SET(inotify_fd, &fds);
        
        // Set timeout to 1 second
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ret = select(inotify_fd + 1, &fds, NULL, NULL, &tv);
        
        if (ret == -1) {
            if (errno == EINTR) continue; // Interrupted by signal
            LOG_ERROR("select() failed: " + std::string(strerror(errno)));
            break;
        } else if (ret > 0 && FD_ISSET(inotify_fd, &fds)) {
            ssize_t len = read(inotify_fd, buffer, BUF_LEN);
            if (len == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue; // No data available
                }
                LOG_ERROR("read() from inotify fd failed: " + std::string(strerror(errno)));
                break;
            }
            
            // Process all inotify events
            for (char* ptr = buffer; ptr < buffer + len; ) {
                struct inotify_event* event = reinterpret_cast<struct inotify_event*>(ptr);
                
                // Check if the changed file is our config file
                if (event->len > 0 && 
                    (strcmp(event->name, file_name.c_str()) == 0 || 
                     (event->mask & (IN_MOVE_SELF | IN_DELETE_SELF)))) {
                    // Small delay to ensure the file is fully written
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    HandleConfigFileChange();
                    break; // Only handle one event at a time
                }
                
                ptr += sizeof(struct inotify_event) + event->len;
            }
        }
        // else: timeout occurred, check stop_watching_ again
    }
    
    // Cleanup
    inotify_rm_watch(inotify_fd, watch_fd);
    close(inotify_fd);
}
#endif

void ConfigManager::WatchingThreadFunction() {
    LOG_INFO("Configuration watching thread started");

#ifdef _WIN32
    WatchFileWindows();
#else
    WatchFileLinux();
#endif

    LOG_INFO("Configuration watching thread stopped");
}

void ConfigManager::HandleConfigFileChange() {
    // JavaScript version debounce logic: watchDebounceTimer
    auto now = std::chrono::steady_clock::now();
    auto time_since_last_change = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_change_time_).count();

    if (time_since_last_change < DEBOUNCE_DELAY_MS) {
        return; // Debounce: ignore too frequent changes
    }

    last_change_time_ = now;

    LOG_INFO("Configuration file changed, reloading...");

    // Save old configuration for comparison
    ServerConfig old_config;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        old_config = config_;
    }

    // Reload configuration (JavaScript version: this.loadConfig())
    int ret = ReloadConfig();
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to reload configuration: " + error::GetErrorMessage(ret));
        return;
    }

    // Check if configuration actually changed (JavaScript version: JSON.stringify(this.config) !== JSON.stringify(newConfig))
    if (HasConfigChanged(old_config)) {
        LOG_INFO("Configuration has changed, notifying callbacks");

        // Trigger configuration change callback (JavaScript version: this.emit('configChanged', this.config))
        std::lock_guard<std::mutex> lock(config_mutex_);
        if (config_changed_callback_) {
            config_changed_callback_(config_);
        }
    } else {
        LOG_DEBUG("Configuration file changed but content is the same");
    }
}

bool ConfigManager::HasConfigChanged(const ServerConfig& old_config) const {
    // Simplified configuration comparison, can be more detailed in actual applications
    // Note: We don't need to lock here since we're comparing with a copy of the old config

    // Compare key configuration items
    if (old_config.mqtt.port != config_.mqtt.port ||
        old_config.udp.port != config_.udp.port ||
        old_config.debug != config_.debug ||
        old_config.mcp.enabled != config_.mcp.enabled) {
        return true;
    }

    // Compare WebSocket server lists
    if (old_config.websocket.development_servers != config_.websocket.development_servers ||
        old_config.websocket.production_servers != config_.websocket.production_servers) {
        return true;
    }

    return false;
}

} // namespace xiaozhi
