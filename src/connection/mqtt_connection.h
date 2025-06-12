#pragma once

#include "common/types.h"
#include "protocol/mqtt_protocol.h"
#include "protocol/mqtt_packet.h"
#include "utils/mqtt_auth.h"
#include "utils/mcp_proxy.h"

#include <uv.h>
#include <memory>
#include <functional>

namespace xiaozhi {

// Forward declaration
class WebSocketBridge;

/**
 * @brief MQTT connection handler for gateway forwarding
 * 
 * Handles individual MQTT client connections and forwards messages to WebSocket
 */
class MQTTConnection {
public:
    // Callback types
    using DisconnectCallback = std::function<void(ConnectionId connection_id)>;
    using ForwardMessageCallback = std::function<void(const std::string& topic, const std::string& payload)>;
    using UDPInfoCallback = std::function<void(ConnectionId connection_id, const UDPConnectionInfo& udp_info)>;
    using UDPSendCallback = std::function<void(const std::vector<uint8_t>& packet, const std::string& address, uint16_t port)>;
    
    /**
     * @brief Constructor
     * @param connection_id Unique connection identifier
     * @param tcp_handle TCP handle for this connection
     * @param loop Event loop
     * @param config Server configuration
     */
    MQTTConnection(ConnectionId connection_id, uv_tcp_t* tcp_handle, uv_loop_t* loop, const ServerConfig& config);
    
    /**
     * @brief Destructor
     */
    ~MQTTConnection();
    
    /**
     * @brief Initialize the connection
     * @return Error code, 0 indicates success
     */
    int Initialize();
    
    /**
     * @brief Start reading from the connection
     * @return Error code, 0 indicates success
     */
    int StartReading();
    
    /**
     * @brief Stop the connection
     */
    void Stop();
    
    /**
     * @brief Send data to the client
     * @param data Data to send
     * @param length Data length
     * @return Error code, 0 indicates success
     */
    int SendData(const uint8_t* data, size_t length);
    
    /**
     * @brief Send MQTT packet to the client
     * @param buffer Serialized packet data
     * @return Error code, 0 indicates success
     */
    int SendMQTTPacket(const std::vector<uint8_t>& buffer);
    
    /**
     * @brief Forward message from WebSocket to MQTT client
     * @param topic MQTT topic
     * @param payload Message payload
     * @return Error code, 0 indicates success
     */
    int ForwardFromWebSocket(const std::string& topic, const std::string& payload);
    
    /**
     * @brief Send UDP connection info to client
     * @param udp_info UDP connection information
     * @return Error code, 0 indicates success
     */
    int SendUDPInfo(const UDPConnectionInfo& udp_info);
    
    /**
     * @brief Get connection ID
     * @return Connection ID
     */
    ConnectionId GetConnectionId() const;
    
    /**
     * @brief Get client ID
     * @return Client ID
     */
    const std::string& GetClientId() const;
    
    /**
     * @brief Check if connection is active
     * @return true if active
     */
    bool IsActive() const;
    
    /**
     * @brief Check for keep alive timeout
     * @return true if timed out
     */
    bool IsKeepAliveTimeout() const;
    
    /**
     * @brief Set callbacks
     */
    void SetDisconnectCallback(DisconnectCallback callback) { disconnect_callback_ = std::move(callback); }
    void SetForwardMessageCallback(ForwardMessageCallback callback) { forward_message_callback_ = std::move(callback); }
    void SetUDPInfoCallback(UDPInfoCallback callback) { udp_info_callback_ = std::move(callback); }
    void SetUDPSendCallback(UDPSendCallback callback) { udp_send_callback_ = std::move(callback); }

private:
    /**
     * @brief Handle incoming data
     * @param data Received data
     * @param length Data length
     */
    void OnDataReceived(const uint8_t* data, size_t length);
    
    /**
     * @brief Handle MQTT CONNECT packet
     * @param packet CONNECT packet
     */
    void OnMQTTConnect(const MQTTConnectPacket& packet);
    
    /**
     * @brief Handle MQTT PUBLISH packet
     * @param packet PUBLISH packet
     */
    void OnMQTTPublish(const MQTTPublishPacket& packet);
    
    /**
     * @brief Handle MQTT SUBSCRIBE packet
     * @param packet SUBSCRIBE packet
     */
    void OnMQTTSubscribe(const MQTTSubscribePacket& packet);
    
    /**
     * @brief Handle MQTT PINGREQ packet
     */
    void OnMQTTPingreq();
    
    /**
     * @brief Handle MQTT DISCONNECT packet
     */
    void OnMQTTDisconnect();
    
    /**
     * @brief Handle MQTT protocol error
     * @param error_code Error code
     * @param message Error message
     */
    void OnMQTTError(int error_code, const std::string& message);

    /**
     * @brief Parse hello message (JavaScript version: parseHelloMessage)
     * @param json Hello message JSON
     */
    void ParseHelloMessage(const nlohmann::json& json);

    /**
     * @brief Parse other message types (JavaScript version: parseOtherMessage)
     * @param json Message JSON
     */
    void ParseOtherMessage(const nlohmann::json& json);

    /**
     * @brief Send UDP message (JavaScript version: sendUdpMessage)
     * @param opus_data Opus audio data
     * @param timestamp Audio timestamp
     */
    void SendUdpMessage(const std::vector<uint8_t>& opus_data, uint32_t timestamp);

    /**
     * @brief Send CONNACK response
     * @param return_code Return code (0 = success)
     */
    void SendConnack(uint8_t return_code);
    
    /**
     * @brief Send SUBACK response
     * @param packet_id Packet ID from SUBSCRIBE
     * @param return_code Return code (0 = success)
     */
    void SendSuback(uint16_t packet_id, uint8_t return_code);
    
    /**
     * @brief Send PINGRESP response
     */
    void SendPingresp();
    
    /**
     * @brief Close the connection
     */
    void Close();
    
    // Static callbacks for libuv
    static void OnRead(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
    static void OnWrite(uv_write_t* req, int status);
    static void OnClose(uv_handle_t* handle);
    static void AllocBuffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);

private:
    ConnectionId connection_id_;
    uv_tcp_t* tcp_handle_;
    uv_loop_t* loop_;
    
    std::unique_ptr<MQTTProtocol> mqtt_protocol_;
    std::string client_id_;
    bool active_;
    bool authenticated_;

    // Connection state management (JavaScript version compatible)
    bool device_said_goodbye_;
    bool closing_;

    // Authentication information (compatible with JavaScript version)
    auth::MqttCredentials credentials_;

    // MCP proxy (compatible with JavaScript version)
    std::unique_ptr<mcp::MCPProxy> mcp_proxy_;

    // WebSocket bridge (JavaScript version: this.bridge)
    std::unique_ptr<class WebSocketBridge> websocket_bridge_;

    // UDP connection information (JavaScript version: this.udp)
    UDPConnectionInfo udp_info_;

    // Configuration information (needs to be passed to WebSocket bridge)
    ServerConfig config_;
    
    // Callbacks
    DisconnectCallback disconnect_callback_;
    ForwardMessageCallback forward_message_callback_;
    UDPInfoCallback udp_info_callback_;
    UDPSendCallback udp_send_callback_;
    
    // Buffer for reading
    std::vector<uint8_t> read_buffer_;
    
    // Disable copy
    MQTTConnection(const MQTTConnection&) = delete;
    MQTTConnection& operator=(const MQTTConnection&) = delete;
};

} // namespace xiaozhi
