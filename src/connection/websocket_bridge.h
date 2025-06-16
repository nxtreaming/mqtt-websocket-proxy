#pragma once

#include "common/types.h"
#include <uv.h>
#include <memory>
#include <functional>
#include <string>
#include <map>
#include <vector>
#include <atomic>
#include <queue>
#include <mutex>

struct lws_context;
struct lws;
struct lws_protocols;
enum lws_callback_reasons;

namespace xiaozhi {

/**
 * @brief WebSocket bridge client for gateway
 * 
 * Connects to backend WebSocket servers and forwards MQTT messages
 */
class WebSocketBridge {
public:
    // Callback types
    using MessageCallback = std::function<void(const std::string& message)>;
    using BinaryMessageCallback = std::function<void(const std::vector<uint8_t>& data)>;
    using ConnectedCallback = std::function<void(const std::string& server_url)>;
    using DisconnectedCallback = std::function<void(const std::string& server_url, int reason)>;
    using ErrorCallback = std::function<void(const std::string& error_message)>;
    
    /**
     * @brief Constructor
     */
    WebSocketBridge();
    
    /**
     * @brief Destructor
     */
    ~WebSocketBridge();
    
    /**
     * @brief Initialize the WebSocket bridge
     * @param config Server configuration
     * @param loop Event loop for reconnection timer (optional)
     * @return Error code, 0 indicates success
     */
    int Initialize(const ServerConfig& config, uv_loop_t* loop = nullptr);

    /**
     * @brief Update the server configuration
     * @param config New server configuration
     * @return Error code, 0 indicates success
     */
    int UpdateConfig(const ServerConfig& config);

    /**
     * @brief Initialize WebSocket bridge with device info (JavaScript version compatible)
     * @param config Server configuration
     * @param loop Event loop
     * @param mac_address Device MAC address for server selection
     * @param client_uuid Client UUID for proper gateway identification
     * @param protocol_version Protocol version
     * @param user_data User data (optional)
     * @return Error code, 0 indicates success
     */
    int InitializeWithDeviceInfo(const ServerConfig& config, uv_loop_t* loop,
                                const std::string& mac_address, const std::string& client_uuid,
                                int protocol_version = 3, const std::string& user_data = "");

    /**
     * @brief Connect to WebSocket server
     * @param server_url WebSocket server URL
     * @return Error code, 0 indicates success
     */
    int Connect(const std::string& server_url, const std::map<std::string, std::string>& headers);
    
    /**
     * @brief Disconnect from current server
     * @return Error code, 0 indicates success
     */
    int Disconnect();
    
    /**
     * @brief Send message to WebSocket server
     * @param message Message to send
     * @return Error code, 0 indicates success
     */
    int SendMessage(const std::string& message);
    
    /**
     * @brief Send MQTT message as JSON to WebSocket server
     * @param topic MQTT topic
     * @param payload MQTT payload
     * @param client_id Source client ID
     * @return Error code, 0 indicates success
     */
    int SendMQTTMessage(const std::string& topic, const std::string& payload, const std::string& client_id);
    
    
    /**
     * @brief Check if connected to WebSocket server
     * @return true if connected
     */
    bool IsConnected() const;
    
    /**
     * @brief Get current server URL
     * @return Current server URL or empty if not connected
     */
    const std::string& GetCurrentServer() const;
    
    /**
     * @brief Get connection statistics
     * @return Connection statistics
     */
    WebSocketConnectionInfo GetConnectionInfo() const;
    
    /**
     * @brief Enable/disable automatic reconnection
     * @param enable Enable automatic reconnection
     * @param max_attempts Maximum reconnection attempts (0 = infinite)
     * @param initial_delay Initial delay in milliseconds
     * @param max_delay Maximum delay in milliseconds
     * @param backoff_multiplier Backoff multiplier for exponential backoff
     */
    void SetReconnectionPolicy(bool enable, int max_attempts = 0, int initial_delay = 1000,
                              int max_delay = 30000, double backoff_multiplier = 2.0);

    /**
     * @brief Set server list for failover
     * @param servers List of WebSocket server URLs
     */
    void SetServerList(const std::vector<std::string>& servers);

    /**
     * @brief Manually trigger reconnection
     * @return Error code, 0 indicates success
     */
    int Reconnect();

    /**
     * @brief Get current connection status
     * @return Connection status information
     */
    WebSocketConnectionInfo GetConnectionStatus() const;

    /**
     * @brief Set callbacks
     */
    void SetMessageCallback(MessageCallback callback) { message_callback_ = std::move(callback); }
    void SetBinaryMessageCallback(BinaryMessageCallback callback) { binary_message_callback_ = std::move(callback); }
    void SetConnectedCallback(ConnectedCallback callback) { connected_callback_ = std::move(callback); }
    void SetDisconnectedCallback(DisconnectedCallback callback) { disconnected_callback_ = std::move(callback); }
    void SetErrorCallback(ErrorCallback callback) { error_callback_ = std::move(callback); }

    // Static callbacks for libwebsockets (must be public)
    static int WebSocketCallback(struct lws* wsi, enum lws_callback_reasons reason, void* user, void* in, size_t len);

    // Static callback for reconnection timer
    static void OnReconnectionTimerCallback(uv_timer_t* timer);

private:
    static void LwsServiceTimerCallback(uv_timer_t* handle);
    void PerformPeriodicService();

    /**
     * @brief Handle WebSocket connection established
     */
    void OnConnected();
    
    /**
     * @brief Handle WebSocket message received (text)
     * @param message Received message
     */
    void OnMessageReceived(const std::string& message);

    /**
     * @brief Handle WebSocket binary message received
     * @param data Binary data
     */
    void OnBinaryMessageReceived(const std::vector<uint8_t>& data);
    
    /**
     * @brief Handle WebSocket connection closed
     * @param reason Close reason
     */
    void OnDisconnected(int reason);
    
    /**
     * @brief Handle WebSocket error
     * @param error_message Error message
     */
    void OnError(const std::string& error_message);
    
    /**
     * @brief Parse WebSocket URL
     * @param url WebSocket URL
     * @param host Output host
     * @param port Output port
     * @param path Output path
     * @param use_ssl Output SSL flag
     * @return Error code, 0 indicates success
     */
    int ParseWebSocketURL(const std::string& url, std::string& host, int& port, std::string& path, bool& use_ssl);
    
    /**
     * @brief Create JSON message from MQTT data
     * @param topic MQTT topic
     * @param payload MQTT payload
     * @param client_id Source client ID
     * @return JSON message string
     */
    std::string CreateMQTTJSON(const std::string& topic, const std::string& payload, const std::string& client_id);
    
    /**
     * @brief Process send queue
     */
    void ProcessSendQueue();

    /**
     * @brief Start reconnection timer
     */
    void StartReconnectionTimer();

    /**
     * @brief Stop reconnection timer
     */
    void StopReconnectionTimer();

    /**
     * @brief Handle reconnection attempt
     */
    void OnReconnectionTimer();

    /**
     * @brief Try next server in the list
     * @return Error code, 0 indicates success
     */
    int TryNextServer();

    /**
     * @brief Calculate next reconnection delay
     * @return Delay in milliseconds
     */
    int CalculateReconnectionDelay();

    /**
     * @brief Reset reconnection state
     */
    void ResetReconnectionState();

private:
    ServerConfig config_;
    bool servicing_active_;

    std::atomic<bool> connected_;
    std::string current_server_;

    // Device information (JavaScript version compatible)
    std::string mac_address_;
    std::string client_uuid_;
    int protocol_version_;
    std::string user_data_;
    std::string custom_headers_;
    bool device_said_goodbye_;

    // libwebsockets context and connection
    lws_context* context_;
    lws* websocket_;
    std::unique_ptr<lws_protocols[]> protocols_;

    // LWS Service Timer
    static constexpr uint64_t LWS_SERVICE_INTERVAL_MS = 50; // milliseconds
    uv_timer_t service_timer_;

    // Connection info
    WebSocketConnectionInfo connection_info_;

    // Thread-safe message queue for sending
    std::queue<std::string> send_queue_;
    std::mutex send_queue_mutex_;

    // Reconnection management
    bool reconnection_enabled_;
    int max_reconnection_attempts_;
    int initial_reconnection_delay_;
    int max_reconnection_delay_;
    double backoff_multiplier_;

    std::atomic<int> reconnection_attempts_;
    std::atomic<int> current_reconnection_delay_;
    std::atomic<bool> reconnecting_;

    std::vector<std::string> server_list_;
    std::atomic<size_t> current_server_index_;

    // Reconnection timer
    std::unique_ptr<uv_timer_t> reconnection_timer_;

    // Preallocated buffer for sending messages
    std::vector<unsigned char> preallocated_send_buffer_;

    uv_loop_t* event_loop_;

    // Callbacks
    MessageCallback message_callback_;
    BinaryMessageCallback binary_message_callback_;
    ConnectedCallback connected_callback_;
    DisconnectedCallback disconnected_callback_;
    ErrorCallback error_callback_;
    
    // Disable copy
    WebSocketBridge(const WebSocketBridge&) = delete;
    WebSocketBridge& operator=(const WebSocketBridge&) = delete;
};

} // namespace xiaozhi
