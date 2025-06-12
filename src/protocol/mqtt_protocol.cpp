#include "protocol/mqtt_protocol.h"
#include "common/error_codes.h"
#include "utils/logger.h"

#include <chrono>

namespace xiaozhi {

MQTTProtocol::MQTTProtocol() 
    : connected_(false)
    , keep_alive_interval_(60)
    , last_activity_(0)
    , max_payload_size_(8192) {
    UpdateLastActivity();
}

MQTTProtocol::~MQTTProtocol() = default;

int MQTTProtocol::ProcessData(const uint8_t* data, size_t length) {
    if (!data || length == 0) {
        return error::INVALID_PARAMETER;
    }
    
    // Append data to receive buffer
    receive_buffer_.insert(receive_buffer_.end(), data, data + length);
    
    // Update last activity
    UpdateLastActivity();
    
    // Process complete packets in buffer
    return ProcessBuffer();
}

int MQTTProtocol::ProcessBuffer() {
    while (receive_buffer_.size() >= 2) { // Minimum packet size
        size_t offset = 0;
        MQTTPacketType packet_type;
        uint32_t remaining_length;
        size_t header_length;
        
        // Parse packet header
        int ret = ParsePacketHeader(offset, packet_type, remaining_length, header_length);
        if (ret != error::SUCCESS) {
            if (ret == error::MQTT_INVALID_PACKET) {
                // Need more data
                break;
            }
            return ret;
        }
        
        // Check if we have complete packet
        size_t total_packet_size = header_length + remaining_length;
        if (receive_buffer_.size() < total_packet_size) {
            // Need more data
            break;
        }
        
        // Check payload size limit
        if (remaining_length > max_payload_size_) {
            LOG_ERROR("MQTT packet too large: " + std::to_string(remaining_length));
            return error::MQTT_PACKET_TOO_LARGE;
        }
        
        // Process the packet
        uint8_t packet_flags = receive_buffer_[0];
        ret = HandlePacket(packet_type, packet_flags, header_length, remaining_length);
        if (ret != error::SUCCESS) {
            return ret;
        }
        
        // Remove processed packet from buffer
        receive_buffer_.erase(receive_buffer_.begin(), receive_buffer_.begin() + total_packet_size);
    }
    
    return error::SUCCESS;
}

int MQTTProtocol::ParsePacketHeader(size_t offset, MQTTPacketType& packet_type, 
                                  uint32_t& remaining_length, size_t& header_length) {
    if (offset >= receive_buffer_.size()) {
        return error::MQTT_INVALID_PACKET;
    }
    
    // Parse packet type from first byte
    uint8_t first_byte = receive_buffer_[offset];
    packet_type = static_cast<MQTTPacketType>((first_byte >> 4) & 0x0F);
    
    // Parse remaining length
    size_t bytes_read;
    int ret = MQTTPacket::DecodeRemainingLength(receive_buffer_, offset + 1, remaining_length, bytes_read);
    if (ret != error::SUCCESS) {
        return ret;
    }
    
    header_length = 1 + bytes_read;
    return error::SUCCESS;
}

int MQTTProtocol::HandlePacket(MQTTPacketType packet_type, uint8_t packet_flags, 
                             size_t header_offset, size_t payload_length) {
    size_t payload_offset = header_offset;
    
    switch (packet_type) {
        case MQTTPacketType::CONNECT:
            return HandleConnectPacket(payload_offset, payload_length);
            
        case MQTTPacketType::PUBLISH:
            return HandlePublishPacket(payload_offset, payload_length, packet_flags);
            
        case MQTTPacketType::SUBSCRIBE:
            return HandleSubscribePacket(payload_offset, payload_length);
            
        case MQTTPacketType::PINGREQ:
            return HandlePingreqPacket(payload_offset, payload_length);
            
        case MQTTPacketType::DISCONNECT:
            return HandleDisconnectPacket(payload_offset, payload_length);
            
        default:
            LOG_WARN("Unsupported MQTT packet type: " + std::to_string(static_cast<int>(packet_type)));
            return error::MQTT_PROTOCOL_ERROR;
    }
}

int MQTTProtocol::HandleConnectPacket(size_t offset, size_t length) {
    MQTTConnectPacket packet;
    int ret = packet.Deserialize(receive_buffer_, offset, length);
    if (ret != error::SUCCESS) {
        TriggerError(ret, "Failed to parse CONNECT packet");
        return ret;
    }
    
    // Validate protocol
    if (packet.GetProtocolLevel() != 4) {
        LOG_ERROR("Unsupported MQTT protocol level: " + std::to_string(packet.GetProtocolLevel()));
        return error::MQTT_UNSUPPORTED_VERSION;
    }
    
    // Set keep alive interval
    keep_alive_interval_ = packet.GetKeepAlive();
    
    // Mark as connected
    connected_ = true;
    
    LOG_INFO("MQTT client connected: " + packet.GetClientId());
    
    // Trigger callback
    if (connect_callback_) {
        connect_callback_(packet);
    }
    
    return error::SUCCESS;
}

int MQTTProtocol::HandlePublishPacket(size_t offset, size_t length, uint8_t packet_flags) {
    MQTTPublishPacket packet;
    
    // Extract QoS from flags (bits 1-2)
    uint8_t qos = (packet_flags >> 1) & 0x03;
    if (qos != 0) {
        LOG_ERROR("Only QoS 0 is supported, received QoS: " + std::to_string(qos));
        return error::MQTT_QOS_NOT_SUPPORTED;
    }
    
    // Extract DUP and RETAIN flags
    bool dup = (packet_flags & 0x08) != 0;
    bool retain = (packet_flags & 0x01) != 0;
    
    packet.SetQoS(qos);
    packet.SetDup(dup);
    packet.SetRetain(retain);
    
    int ret = packet.Deserialize(receive_buffer_, offset, length);
    if (ret != error::SUCCESS) {
        TriggerError(ret, "Failed to parse PUBLISH packet");
        return ret;
    }
    
    LOG_DEBUG("MQTT PUBLISH received: topic=" + packet.GetTopic() + 
              ", payload_size=" + std::to_string(packet.GetPayload().length()));
    
    // Trigger callback
    if (publish_callback_) {
        publish_callback_(packet);
    }
    
    return error::SUCCESS;
}

int MQTTProtocol::HandleSubscribePacket(size_t offset, size_t length) {
    MQTTSubscribePacket packet;
    int ret = packet.Deserialize(receive_buffer_, offset, length);
    if (ret != error::SUCCESS) {
        TriggerError(ret, "Failed to parse SUBSCRIBE packet");
        return ret;
    }
    
    LOG_DEBUG("MQTT SUBSCRIBE received: topic=" + packet.GetTopic());
    
    // Trigger callback
    if (subscribe_callback_) {
        subscribe_callback_(packet);
    }
    
    return error::SUCCESS;
}

int MQTTProtocol::HandlePingreqPacket(size_t offset, size_t length) {
    LOG_DEBUG("MQTT PINGREQ received");
    
    // Trigger callback
    if (pingreq_callback_) {
        pingreq_callback_();
    }
    
    return error::SUCCESS;
}

int MQTTProtocol::HandleDisconnectPacket(size_t offset, size_t length) {
    LOG_INFO("MQTT DISCONNECT received");
    
    connected_ = false;
    
    // Trigger callback
    if (disconnect_callback_) {
        disconnect_callback_();
    }
    
    return error::SUCCESS;
}

int MQTTProtocol::CreateConnackPacket(uint8_t return_code, bool session_present, std::vector<uint8_t>& buffer) {
    MQTTConnackPacket packet;
    packet.SetReturnCode(return_code);
    packet.SetSessionPresent(session_present);
    
    return packet.Serialize(buffer);
}

int MQTTProtocol::CreatePublishPacket(const std::string& topic, const std::string& payload,
                                    uint8_t qos, bool dup, bool retain, uint16_t packet_id,
                                    std::vector<uint8_t>& buffer) {
    if (qos != 0) {
        LOG_ERROR("Only QoS 0 is supported");
        return error::MQTT_QOS_NOT_SUPPORTED;
    }
    
    MQTTPublishPacket packet;
    packet.SetTopic(topic);
    packet.SetPayload(payload);
    packet.SetQoS(qos);
    packet.SetDup(dup);
    packet.SetRetain(retain);
    // No packet ID for QoS 0
    
    return packet.Serialize(buffer);
}

int MQTTProtocol::CreateSubackPacket(uint16_t packet_id, uint8_t return_code, std::vector<uint8_t>& buffer) {
    MQTTSubackPacket packet;
    packet.SetPacketId(packet_id);
    packet.SetReturnCode(return_code);
    
    return packet.Serialize(buffer);
}

int MQTTProtocol::CreatePingrespPacket(std::vector<uint8_t>& buffer) {
    MQTTPingrespPacket packet;
    return packet.Serialize(buffer);
}

void MQTTProtocol::SetConnected(bool connected) {
    connected_ = connected;
}

bool MQTTProtocol::IsConnected() const {
    return connected_;
}

void MQTTProtocol::SetKeepAliveInterval(uint16_t interval) {
    keep_alive_interval_ = interval;
}

uint16_t MQTTProtocol::GetKeepAliveInterval() const {
    return keep_alive_interval_;
}

void MQTTProtocol::UpdateLastActivity() {
    last_activity_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

int64_t MQTTProtocol::GetLastActivity() const {
    return last_activity_;
}

bool MQTTProtocol::IsKeepAliveTimeout() const {
    if (keep_alive_interval_ == 0) {
        return false; // Keep alive disabled
    }
    
    int64_t current_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    int64_t timeout_ms = keep_alive_interval_ * 1000 * 1.5; // 1.5x keep alive interval
    
    return (current_time - last_activity_) > timeout_ms;
}

void MQTTProtocol::Reset() {
    receive_buffer_.clear();
    connected_ = false;
    keep_alive_interval_ = 60;
    UpdateLastActivity();
}

void MQTTProtocol::SetMaxPayloadSize(uint32_t max_size) {
    max_payload_size_ = max_size;
}

uint32_t MQTTProtocol::GetMaxPayloadSize() const {
    return max_payload_size_;
}

void MQTTProtocol::TriggerError(int error_code, const std::string& message) {
    LOG_ERROR("MQTT Protocol Error: " + message + " (code: " + std::to_string(error_code) + ")");
    
    if (error_callback_) {
        error_callback_(error_code, message);
    }
}

} // namespace xiaozhi
