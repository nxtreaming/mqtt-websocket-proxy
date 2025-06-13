#pragma once

#include "common/types.h"
#include "common/constants.h"
#include "common/error_codes.h"
#include "utils/config_manager.h"
#include "utils/logger.h"

#include <uv.h>
#include <memory>
#include <atomic>
#include <thread>

// Forward declarations
namespace xiaozhi {
class MQTTServer;
class UDPServer;
class WebSocketBridge;
}

namespace xiaozhi {

/**
 * @brief Main gateway server class
 *
 * Coordinates the overall operation of MQTT server, UDP server and WebSocket bridging
 */
class GatewayServer {
public:
    /**
     * @brief Constructor
     */
    GatewayServer();

    /**
     * @brief Destructor
     */
    ~GatewayServer();

    /**
     * @brief Initialize the server
     * @param config_path Configuration file path
     * @return Error code, 0 indicates success
     */
    int Initialize(const std::string& config_path = constants::DEFAULT_CONFIG_FILE);

    /**
     * @brief Start the server
     * @return Error code, 0 indicates success
     */
    int Start();

    /**
     * @brief Stop the server
     * @return Error code, 0 indicates success
     */
    int Stop();

    /**
     * @brief Run the server main loop
     *
     * This method will block until the server stops
     */
    void Run();

    /**
     * @brief Check if the server is running
     * @return true if running, false if stopped
     */
    bool IsRunning() const;

    /**
     * @brief Get server statistics
     * @return Server statistics
     */
    ServerStats GetStats() const;

    /**
     * @brief Get configuration information
     * @return Server configuration
     */
    const ServerConfig& GetConfig() const;

    /**
     * @brief Reload configuration
     * @param config_path Configuration file path
     * @return Error code, 0 indicates success
     */
    int ReloadConfig(const std::string& config_path = "");

    /**
     * @brief Handle configuration change (JavaScript version: configManager.on('configChanged', callback))
     * @param new_config New configuration
     */
    void OnConfigChanged(const ServerConfig& new_config);

    /**
     * @brief Get libuv event loop
     * @return libuv event loop pointer
     */
    uv_loop_t* GetEventLoop() const;

private:
    /**
     * @brief Initialize libuv event loop
     * @return Error code, 0 indicates success
     */
    int InitializeEventLoop();

    /**
     * @brief Cleanup libuv event loop
     */
    void CleanupEventLoop();

    /**
     * @brief Initialize logging system
     * @return Error code, 0 indicates success
     */
    int InitializeLogging();

    /**
     * @brief Initialize MQTT server
     * @return Error code, 0 indicates success
     */
    int InitializeMQTTServer();

    /**
     * @brief Initialize UDP server
     * @return Error code, 0 indicates success
     */
    int InitializeUDPServer();

    /**
     * @brief Initialize WebSocket bridge
     * @return Error code, 0 indicates success
     */
    int InitializeWebSocketBridge();

    /**
     * @brief Start statistics timer
     * @return Error code, 0 indicates success
     */
    int StartStatsTimer();

    /**
     * @brief Stop statistics timer
     */
    void StopStatsTimer();

    /**
     * @brief Statistics timer callback
     * @param timer Timer handle
     */
    static void OnStatsTimer(uv_timer_t* timer);

    /**
     * @brief Print statistics information
     */
    void PrintStats();

    /**
     * @brief Validate configuration
     * @return Error code, 0 indicates success
     */
    int ValidateConfig();

    /**
     * @brief Handle MQTT message forwarding
     * @param connection_id Connection ID
     * @param topic MQTT topic
     * @param payload Message payload
     */
    void OnMQTTMessageForward(ConnectionId connection_id, const std::string& topic, const std::string& payload);

    /**
     * @brief Handle MQTT client connected
     * @param connection_id Connection ID
     * @param client_id Client ID
     */
    void OnMQTTClientConnected(ConnectionId connection_id, const std::string& client_id);

    /**
     * @brief Handle MQTT client disconnected
     * @param connection_id Connection ID
     * @param client_id Client ID
     */
    void OnMQTTClientDisconnected(ConnectionId connection_id, const std::string& client_id);

    /**
     * @brief Handle UDP info request
     * @param connection_id Connection ID
     * @return UDP connection info
     */
    UDPConnectionInfo OnUDPInfoRequest(ConnectionId connection_id);

    /**
     * @brief Handle WebSocket message received
     * @param message Received message
     */
    void OnWebSocketMessageReceived(const std::string& message);

    /**
     * @brief Handle WebSocket binary message received (audio data)
     * @param data Binary data (JavaScript compatible format)
     */
    void OnWebSocketBinaryMessageReceived(const std::vector<uint8_t>& data);

    /**
     * @brief Handle WebSocket connected
     * @param server_url Connected server URL
     */
    void OnWebSocketConnected(const std::string& server_url);

    /**
     * @brief Handle WebSocket disconnected
     * @param server_url Disconnected server URL
     * @param reason Disconnect reason
     */
    void OnWebSocketDisconnected(const std::string& server_url, int reason);

    /**
     * @brief Handle UDP audio data received
     * @param session_id Session ID
     * @param audio_data Audio data
     */
    void OnUDPAudioData(const std::string& session_id, const std::vector<uint8_t>& audio_data);

    /**
     * @brief Handle UDP session created
     * @param session_id Session ID
     * @param info Connection info
     */
    void OnUDPSessionCreated(const std::string& session_id, const UDPConnectionInfo& info);

    /**
     * @brief Handle UDP session closed
     * @param session_id Session ID
     */
    void OnUDPSessionClosed(const std::string& session_id);

private:
    // Core components
    std::unique_ptr<uv_loop_t> event_loop_;
    std::unique_ptr<ConfigManager> config_manager_;
    std::unique_ptr<Logger> logger_;
    std::unique_ptr<MQTTServer> mqtt_server_;
    std::unique_ptr<UDPServer> udp_server_;
    std::unique_ptr<WebSocketBridge> websocket_bridge_;

    // Configuration and state
    ServerConfig config_;
    ServerStats stats_;
    std::atomic<bool> running_;
    std::atomic<bool> stopping_;

    // Timers and signals
    std::unique_ptr<uv_timer_t> stats_timer_;
    std::unique_ptr<uv_signal_t> sigint_signal_;
    std::unique_ptr<uv_signal_t> sigterm_signal_;

    // Configuration file path
    std::string config_path_;

    // Start time
    int64_t start_time_;

    // Last statistics time
    int64_t last_stats_time_;
    
    // Current active WebSocket session ID
    std::string active_websocket_session_id_;
    
    // Mutex for protecting access to active_websocket_session_id_
    std::mutex websocket_session_mutex_;

    // Disable copy constructor and assignment
    GatewayServer(const GatewayServer&) = delete;
    GatewayServer& operator=(const GatewayServer&) = delete;
};

} // namespace xiaozhi
