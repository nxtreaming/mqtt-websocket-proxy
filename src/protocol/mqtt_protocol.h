#pragma once

#include "common/types.h"
#include "protocol/mqtt_packet.h"
#include <vector>
#include <memory>
#include <functional>

namespace xiaozhi {

/**
 * @brief MQTT protocol processor
 *
 * Responsible for MQTT protocol parsing, encapsulation and state management
 */
class MQTTProtocol {
public:
    // Callback function type definitions
    using ConnectCallback = std::function<void(const MQTTConnectPacket&)>;
    using PublishCallback = std::function<void(const MQTTPublishPacket&)>;
    using SubscribeCallback = std::function<void(const MQTTSubscribePacket&)>;
    using PingreqCallback = std::function<void()>;
    using DisconnectCallback = std::function<void()>;
    using ErrorCallback = std::function<void(int error_code, const std::string& message)>;

    /**
     * @brief Constructor
     */
    MQTTProtocol();

    /**
     * @brief Destructor
     */
    ~MQTTProtocol();

    /**
     * @brief Set callback functions
     */
    void SetConnectCallback(ConnectCallback callback) { connect_callback_ = std::move(callback); }
    void SetPublishCallback(PublishCallback callback) { publish_callback_ = std::move(callback); }
    void SetSubscribeCallback(SubscribeCallback callback) { subscribe_callback_ = std::move(callback); }
    void SetPingreqCallback(PingreqCallback callback) { pingreq_callback_ = std::move(callback); }
    void SetDisconnectCallback(DisconnectCallback callback) { disconnect_callback_ = std::move(callback); }
    void SetErrorCallback(ErrorCallback callback) { error_callback_ = std::move(callback); }

    /**
     * @brief Process received data
     * @param data Received data
     * @param length Data length
     * @return Error code, 0 indicates success
     */
    int ProcessData(const uint8_t* data, size_t length);

    /**
     * @brief Create CONNACK packet
     * @param return_code Return code
     * @param session_present Session present flag
     * @param buffer Output buffer
     * @return Error code, 0 indicates success
     */
    int CreateConnackPacket(uint8_t return_code, bool session_present, std::vector<uint8_t>& buffer);

    /**
     * @brief Create PUBLISH packet
     * @param topic Topic
     * @param payload Payload
     * @param qos QoS level
     * @param dup Duplicate flag
     * @param retain Retain flag
     * @param packet_id Packet ID (required when QoS > 0)
     * @param buffer Output buffer
     * @return Error code, 0 indicates success
     */
    int CreatePublishPacket(const std::string& topic, const std::string& payload,
                           uint8_t qos, bool dup, bool retain, uint16_t packet_id,
                           std::vector<uint8_t>& buffer);

    /**
     * @brief Create SUBACK packet
     * @param packet_id Packet ID
     * @param return_code Return code
     * @param buffer Output buffer
     * @return Error code, 0 indicates success
     */
    int CreateSubackPacket(uint16_t packet_id, uint8_t return_code, std::vector<uint8_t>& buffer);

    /**
     * @brief Create PINGRESP packet
     * @param buffer Output buffer
     * @return Error code, 0 indicates success
     */
    int CreatePingrespPacket(std::vector<uint8_t>& buffer);
    
    /**
     * @brief Set connection status
     * @param connected Whether connected
     */
    void SetConnected(bool connected);

    /**
     * @brief Check if connected
     * @return true if connected
     */
    bool IsConnected() const;

    /**
     * @brief Set Keep Alive interval
     * @param interval Keep Alive interval (seconds)
     */
    void SetKeepAliveInterval(uint16_t interval);

    /**
     * @brief Get Keep Alive interval
     * @return Keep Alive interval (seconds)
     */
    uint16_t GetKeepAliveInterval() const;

    /**
     * @brief Update last activity time
     */
    void UpdateLastActivity();

    /**
     * @brief Get last activity time
     * @return Last activity time (millisecond timestamp)
     */
    int64_t GetLastActivity() const;

    /**
     * @brief Check Keep Alive timeout
     * @return true if timeout
     */
    bool IsKeepAliveTimeout() const;

    /**
     * @brief Reset protocol state
     */
    void Reset();

    /**
     * @brief Set maximum payload size
     * @param max_size Maximum payload size
     */
    void SetMaxPayloadSize(uint32_t max_size);

    /**
     * @brief Get maximum payload size
     * @return Maximum payload size
     */
    uint32_t GetMaxPayloadSize() const;

private:
    /**
     * @brief Process packets in buffer
     * @return Error code, 0 indicates success
     */
    int ProcessBuffer();

    /**
     * @brief Parse packet type and remaining length
     * @param offset Starting offset
     * @param packet_type Output packet type
     * @param remaining_length Output remaining length
     * @param header_length Output header length
     * @return Error code, 0 indicates success
     */
    int ParsePacketHeader(size_t offset, MQTTPacketType& packet_type,
                         uint32_t& remaining_length, size_t& header_length);

    /**
     * @brief Handle MQTT packet based on type
     * @param packet_type MQTT packet type
     * @param packet_flags Packet flags
     * @param header_offset Header offset in buffer
     * @param payload_length Payload length
     * @return Error code, 0 indicates success
     */
    int HandlePacket(MQTTPacketType packet_type, uint8_t packet_flags, size_t header_offset, size_t payload_length);

    /**
     * @brief Handle CONNECT packet
     * @param offset Data offset
     * @param length Data length
     * @return Error code, 0 indicates success
     */
    int HandleConnectPacket(size_t offset, size_t length);

    /**
     * @brief Handle PUBLISH packet
     * @param offset Data offset
     * @param length Data length
     * @param packet_type Packet type (including flags)
     * @return Error code, 0 indicates success
     */
    int HandlePublishPacket(size_t offset, size_t length, uint8_t packet_type);

    /**
     * @brief Handle SUBSCRIBE packet
     * @param offset Data offset
     * @param length Data length
     * @return Error code, 0 indicates success
     */
    int HandleSubscribePacket(size_t offset, size_t length);

    /**
     * @brief Handle PINGREQ packet
     * @param offset Data offset
     * @param length Data length
     * @return Error code, 0 indicates success
     */
    int HandlePingreqPacket(size_t offset, size_t length);

    /**
     * @brief Handle DISCONNECT packet
     * @param offset Data offset
     * @param length Data length
     * @return Error code, 0 indicates success
     */
    int HandleDisconnectPacket(size_t offset, size_t length);

    /**
     * @brief Trigger error callback
     * @param error_code Error code
     * @param message Error message
     */
    void TriggerError(int error_code, const std::string& message);

private:
    // Receive buffer
    std::vector<uint8_t> receive_buffer_;

    // Connection state
    bool connected_;
    uint16_t keep_alive_interval_;  // seconds
    int64_t last_activity_;         // millisecond timestamp

    // Configuration
    uint32_t max_payload_size_;

    // Callback functions
    ConnectCallback connect_callback_;
    PublishCallback publish_callback_;
    SubscribeCallback subscribe_callback_;
    PingreqCallback pingreq_callback_;
    DisconnectCallback disconnect_callback_;
    ErrorCallback error_callback_;
};

} // namespace xiaozhi
