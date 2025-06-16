#pragma once

#include "common/types.h"
#include "common/constants.h"

#include <uv.h>
#include <memory>
#include <unordered_map>
#include <functional>
#include <atomic>
namespace xiaozhi {
class MQTTConnection;
}

namespace xiaozhi {

/**
 * @brief MQTT TCP server for gateway
 * 
 * Accepts MQTT client connections and manages them for message forwarding
 */
class MQTTServer {
public:
    // Callback types
    using MessageForwardCallback = std::function<void(ConnectionId connection_id, const std::string& topic, const std::string& payload)>;
    using ClientConnectedCallback = std::function<void(ConnectionId connection_id, const std::string& client_id)>;
    using ClientDisconnectedCallback = std::function<void(ConnectionId connection_id, const std::string& client_id)>;
    using UDPInfoRequestCallback = std::function<UDPConnectionInfo(ConnectionId connection_id)>;
    
    /**
     * @brief Constructor
     * @param loop Event loop
     */
    explicit MQTTServer(uv_loop_t* loop);
    
    /**
     * @brief Destructor
     */
    ~MQTTServer();
    
    /**
     * @brief Initialize the server
     * @param config Server configuration
     * @return Error code, 0 indicates success
     */
    int Initialize(const ServerConfig& config);

    /**
     * @brief Update the server configuration
     * @param config New server configuration
     * @return Error code, 0 indicates success
     */
    int UpdateConfig(const ServerConfig& config);
    
    /**
     * @brief Broadcast a message to all connected MQTT clients
     * @param topic The topic to publish to
     * @param payload The message payload
     * @return Error code, 0 indicates success
     */
    int BroadcastMessage(const std::string& topic, const std::string& payload);
    
    /**
     * @brief Start listening for connections
     * @return Error code, 0 indicates success
     */
    int Start();
    
    /**
     * @brief Stop the server
     * @return Error code, 0 indicates success
     */
    int Stop();
    
    /**
     * @brief Check if server is running
     * @return true if running
     */
    bool IsRunning() const;
    
    /**
     * @brief Get number of active connections
     * @return Number of active connections
     */
    size_t GetConnectionCount() const;
    
    /**
     * @brief Forward message from WebSocket to specific MQTT client
     * @param connection_id Target connection ID
     * @param topic MQTT topic
     * @param payload Message payload
     * @return Error code, 0 indicates success
     */
    int ForwardToClient(ConnectionId connection_id, const std::string& topic, const std::string& payload);
    
    /**
     * @brief Broadcast message to all connected MQTT clients
     * @param topic MQTT topic
     * @param payload Message payload
     * @return Error code, 0 indicates success
     */
    int BroadcastToClients(const std::string& topic, const std::string& payload);
    
    /**
     * @brief Send UDP connection info to specific client
     * @param connection_id Target connection ID
     * @param udp_info UDP connection information
     * @return Error code, 0 indicates success
     */
    int SendUDPInfoToClient(ConnectionId connection_id, const UDPConnectionInfo& udp_info);
    
    /**
     * @brief Get server statistics
     * @return Server statistics
     */
    ServerStats GetStats() const;

    /**
     * @brief Forwards a UDP-originated event as a WebSocket message to the relevant MQTTConnection.
     *
     * This method finds the MQTTConnection associated with the given UDP session ID
     * and instructs it to send the message_payload over its WebSocket bridge.
     *
     * @param udp_session_id The UDP session ID to identify the target MQTTConnection.
     * @param message_payload The raw message string to be sent over WebSocket.
     */
    void ForwardUDPEventToConnection(const std::string& udp_session_id, const std::string& message_payload);
    
    /**
     * @brief Set callbacks
     */
    void SetMessageForwardCallback(MessageForwardCallback callback) { message_forward_callback_ = std::move(callback); }
    void SetClientConnectedCallback(ClientConnectedCallback callback) { client_connected_callback_ = std::move(callback); }
    void SetClientDisconnectedCallback(ClientDisconnectedCallback callback) { client_disconnected_callback_ = std::move(callback); }
    void SetUDPInfoRequestCallback(UDPInfoRequestCallback callback) { udp_info_request_callback_ = std::move(callback); }

private:
    /**
     * @brief Handle new client connection
     * @param status Connection status
     */
    void OnNewConnection(int status);
    
    /**
     * @brief Handle client disconnection
     * @param connection_id Connection ID
     */
    void OnClientDisconnected(ConnectionId connection_id);
    
    /**
     * @brief Handle message from client for forwarding
     * @param connection_id Connection ID
     * @param topic MQTT topic
     * @param payload Message payload
     */
    void OnMessageForward(ConnectionId connection_id, const std::string& topic, const std::string& payload);
    
    /**
     * @brief Handle UDP info request from client
     * @param connection_id Connection ID
     * @param udp_info UDP connection info
     */
    void OnUDPInfoRequest(ConnectionId connection_id, const UDPConnectionInfo& udp_info);
    
    /**
     * @brief Generate unique connection ID
     * @return New connection ID
     */
    ConnectionId GenerateConnectionId();
    
    /**
     * @brief Cleanup inactive connections
     */
    void CleanupConnections();
    
    /**
     * @brief Update server statistics
     */
    void UpdateStats();
    
    // Static callbacks for libuv
    static void OnConnection(uv_stream_t* server, int status);
    static void OnCleanupTimer(uv_timer_t* timer);

private:
    uv_loop_t* loop_;
    std::unique_ptr<uv_tcp_t> tcp_server_;
    std::unique_ptr<uv_timer_t> cleanup_timer_;
    
    ServerConfig config_;
    std::atomic<bool> running_;
    std::atomic<ConnectionId> next_connection_id_;
    
    // Connection management
    std::unordered_map<ConnectionId, std::unique_ptr<MQTTConnection>> connections_;
    std::unordered_map<ConnectionId, std::string> client_ids_; // connection_id -> client_id mapping
    
    // Statistics
    mutable ServerStats stats_;
    
    // Callbacks
    MessageForwardCallback message_forward_callback_;
    ClientConnectedCallback client_connected_callback_;
    ClientDisconnectedCallback client_disconnected_callback_;
    UDPInfoRequestCallback udp_info_request_callback_;
    
    // Disable copy
    MQTTServer(const MQTTServer&) = delete;
    MQTTServer& operator=(const MQTTServer&) = delete;
};

} // namespace xiaozhi
