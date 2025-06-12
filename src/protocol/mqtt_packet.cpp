#include "protocol/mqtt_packet.h"
#include "common/error_codes.h"
#include "utils/logger.h"

namespace xiaozhi {

// ============================================================================
// MQTTPacket Base Class
// ============================================================================

MQTTPacket::MQTTPacket(MQTTPacketType type) : type_(type) {
}

MQTTPacketType MQTTPacket::GetType() const {
    return type_;
}

size_t MQTTPacket::EncodeRemainingLength(uint32_t length, std::vector<uint8_t>& buffer) {
    size_t bytes_written = 0;
    
    do {
        uint8_t byte = length % 128;
        length = length / 128;
        if (length > 0) {
            byte = byte | 128;
        }
        buffer.push_back(byte);
        bytes_written++;
    } while (length > 0);
    
    return bytes_written;
}

int MQTTPacket::DecodeRemainingLength(const std::vector<uint8_t>& buffer, size_t offset, 
                                    uint32_t& length, size_t& bytes_read) {
    length = 0;
    bytes_read = 0;
    uint32_t multiplier = 1;
    
    if (offset >= buffer.size()) {
        return error::MQTT_INVALID_PACKET;
    }
    
    do {
        if (offset + bytes_read >= buffer.size()) {
            return error::MQTT_INVALID_PACKET;
        }
        
        uint8_t byte = buffer[offset + bytes_read];
        length += (byte & 127) * multiplier;
        
        if (multiplier > 128 * 128 * 128) {
            return error::MQTT_MALFORMED_PACKET;
        }
        
        multiplier *= 128;
        bytes_read++;
        
        if ((byte & 128) == 0) {
            break;
        }
    } while (bytes_read < 4);
    
    return error::SUCCESS;
}

void MQTTPacket::EncodeString(const std::string& str, std::vector<uint8_t>& buffer) {
    uint16_t length = static_cast<uint16_t>(str.length());
    buffer.push_back((length >> 8) & 0xFF);
    buffer.push_back(length & 0xFF);
    buffer.insert(buffer.end(), str.begin(), str.end());
}

int MQTTPacket::DecodeString(const std::vector<uint8_t>& buffer, size_t offset, std::string& str) {
    if (offset + 2 > buffer.size()) {
        return -1;
    }
    
    uint16_t length = (buffer[offset] << 8) | buffer[offset + 1];
    
    if (offset + 2 + length > buffer.size()) {
        return -1;
    }
    
    str.assign(buffer.begin() + offset + 2, buffer.begin() + offset + 2 + length);
    return 2 + length;
}

// ============================================================================
// MQTT CONNECT Packet
// ============================================================================

MQTTConnectPacket::MQTTConnectPacket() 
    : MQTTPacket(MQTTPacketType::CONNECT)
    , protocol_name_("MQTT")
    , protocol_level_(4)
    , connect_flags_(0)
    , keep_alive_(60)
    , clean_session_(true) {
}

int MQTTConnectPacket::Serialize(std::vector<uint8_t>& buffer) const {
    std::vector<uint8_t> payload;
    
    // Variable header
    EncodeString(protocol_name_, payload);
    payload.push_back(protocol_level_);
    
    // Connect flags
    uint8_t flags = 0;
    if (clean_session_) flags |= 0x02;
    if (!username_.empty()) flags |= 0x80;
    if (!password_.empty()) flags |= 0x40;
    payload.push_back(flags);
    
    // Keep alive
    payload.push_back((keep_alive_ >> 8) & 0xFF);
    payload.push_back(keep_alive_ & 0xFF);
    
    // Payload
    EncodeString(client_id_, payload);
    if (!username_.empty()) {
        EncodeString(username_, payload);
    }
    if (!password_.empty()) {
        EncodeString(password_, payload);
    }
    
    // Fixed header
    buffer.push_back(static_cast<uint8_t>(MQTTPacketType::CONNECT) << 4);
    EncodeRemainingLength(payload.size(), buffer);
    buffer.insert(buffer.end(), payload.begin(), payload.end());
    
    return error::SUCCESS;
}

int MQTTConnectPacket::Deserialize(const std::vector<uint8_t>& buffer, size_t offset, size_t length) {
    size_t pos = offset;
    
    // Protocol name
    int bytes_read = DecodeString(buffer, pos, protocol_name_);
    if (bytes_read < 0) return error::MQTT_MALFORMED_PACKET;
    pos += bytes_read;
    
    // Protocol level
    if (pos >= buffer.size()) return error::MQTT_MALFORMED_PACKET;
    protocol_level_ = buffer[pos++];
    
    // Connect flags
    if (pos >= buffer.size()) return error::MQTT_MALFORMED_PACKET;
    connect_flags_ = buffer[pos++];
    clean_session_ = (connect_flags_ & 0x02) != 0;
    
    // Keep alive
    if (pos + 1 >= buffer.size()) return error::MQTT_MALFORMED_PACKET;
    keep_alive_ = (buffer[pos] << 8) | buffer[pos + 1];
    pos += 2;
    
    // Client ID
    bytes_read = DecodeString(buffer, pos, client_id_);
    if (bytes_read < 0) return error::MQTT_MALFORMED_PACKET;
    pos += bytes_read;
    
    // Username (if present)
    if (connect_flags_ & 0x80) {
        bytes_read = DecodeString(buffer, pos, username_);
        if (bytes_read < 0) return error::MQTT_MALFORMED_PACKET;
        pos += bytes_read;
    }
    
    // Password (if present)
    if (connect_flags_ & 0x40) {
        bytes_read = DecodeString(buffer, pos, password_);
        if (bytes_read < 0) return error::MQTT_MALFORMED_PACKET;
        pos += bytes_read;
    }
    
    return error::SUCCESS;
}

size_t MQTTConnectPacket::GetSize() const {
    size_t size = 1; // Fixed header
    size += 4; // Remaining length (max 4 bytes)
    size += 2 + protocol_name_.length(); // Protocol name
    size += 1; // Protocol level
    size += 1; // Connect flags
    size += 2; // Keep alive
    size += 2 + client_id_.length(); // Client ID
    if (!username_.empty()) size += 2 + username_.length();
    if (!password_.empty()) size += 2 + password_.length();
    return size;
}

// ============================================================================
// MQTT CONNACK Packet
// ============================================================================

MQTTConnackPacket::MQTTConnackPacket() 
    : MQTTPacket(MQTTPacketType::CONNACK)
    , connect_flags_(0)
    , return_code_(0)
    , session_present_(false) {
}

int MQTTConnackPacket::Serialize(std::vector<uint8_t>& buffer) const {
    // Fixed header
    buffer.push_back(static_cast<uint8_t>(MQTTPacketType::CONNACK) << 4);
    buffer.push_back(2); // Remaining length
    
    // Variable header
    uint8_t flags = session_present_ ? 0x01 : 0x00;
    buffer.push_back(flags);
    buffer.push_back(return_code_);
    
    return error::SUCCESS;
}

int MQTTConnackPacket::Deserialize(const std::vector<uint8_t>& buffer, size_t offset, size_t length) {
    if (length < 2) return error::MQTT_MALFORMED_PACKET;
    
    connect_flags_ = buffer[offset];
    session_present_ = (connect_flags_ & 0x01) != 0;
    return_code_ = buffer[offset + 1];
    
    return error::SUCCESS;
}

size_t MQTTConnackPacket::GetSize() const {
    return 4; // Fixed header (2) + Variable header (2)
}

// ============================================================================
// MQTT PUBLISH Packet (QoS 0 only)
// ============================================================================

MQTTPublishPacket::MQTTPublishPacket() 
    : MQTTPacket(MQTTPacketType::PUBLISH)
    , qos_(0)
    , dup_(false)
    , retain_(false)
    , packet_id_(0) {
}

int MQTTPublishPacket::Serialize(std::vector<uint8_t>& buffer) const {
    std::vector<uint8_t> variable_header;
    
    // Topic
    EncodeString(topic_, variable_header);
    
    // Packet ID (only for QoS > 0, we only support QoS 0)
    // No packet ID for QoS 0
    
    // Fixed header
    uint8_t fixed_header = static_cast<uint8_t>(MQTTPacketType::PUBLISH) << 4;
    if (dup_) fixed_header |= 0x08;
    if (retain_) fixed_header |= 0x01;
    // QoS is always 0, so no need to set QoS bits
    
    buffer.push_back(fixed_header);
    EncodeRemainingLength(variable_header.size() + payload_.length(), buffer);
    buffer.insert(buffer.end(), variable_header.begin(), variable_header.end());
    buffer.insert(buffer.end(), payload_.begin(), payload_.end());
    
    return error::SUCCESS;
}

int MQTTPublishPacket::Deserialize(const std::vector<uint8_t>& buffer, size_t offset, size_t length) {
    size_t pos = offset;
    
    // Topic
    int bytes_read = DecodeString(buffer, pos, topic_);
    if (bytes_read < 0) return error::MQTT_MALFORMED_PACKET;
    pos += bytes_read;
    
    // QoS 0 - no packet ID
    
    // Payload
    if (pos <= offset + length) {
        payload_.assign(buffer.begin() + pos, buffer.begin() + offset + length);
    }
    
    return error::SUCCESS;
}

size_t MQTTPublishPacket::GetSize() const {
    size_t size = 1; // Fixed header
    size += 4; // Remaining length (max 4 bytes)
    size += 2 + topic_.length(); // Topic
    size += payload_.length(); // Payload
    return size;
}

// ============================================================================
// MQTT PINGREQ/PINGRESP Packets
// ============================================================================

MQTTPingreqPacket::MQTTPingreqPacket() : MQTTPacket(MQTTPacketType::PINGREQ) {
}

int MQTTPingreqPacket::Serialize(std::vector<uint8_t>& buffer) const {
    buffer.push_back(static_cast<uint8_t>(MQTTPacketType::PINGREQ) << 4);
    buffer.push_back(0); // Remaining length
    return error::SUCCESS;
}

int MQTTPingreqPacket::Deserialize(const std::vector<uint8_t>& buffer, size_t offset, size_t length) {
    // PINGREQ has no payload
    return error::SUCCESS;
}

size_t MQTTPingreqPacket::GetSize() const {
    return 2; // Fixed header only
}

MQTTPingrespPacket::MQTTPingrespPacket() : MQTTPacket(MQTTPacketType::PINGRESP) {
}

int MQTTPingrespPacket::Serialize(std::vector<uint8_t>& buffer) const {
    buffer.push_back(static_cast<uint8_t>(MQTTPacketType::PINGRESP) << 4);
    buffer.push_back(0); // Remaining length
    return error::SUCCESS;
}

int MQTTPingrespPacket::Deserialize(const std::vector<uint8_t>& buffer, size_t offset, size_t length) {
    // PINGRESP has no payload
    return error::SUCCESS;
}

size_t MQTTPingrespPacket::GetSize() const {
    return 2; // Fixed header only
}

// ============================================================================
// MQTT DISCONNECT Packet
// ============================================================================

MQTTDisconnectPacket::MQTTDisconnectPacket() : MQTTPacket(MQTTPacketType::DISCONNECT) {
}

int MQTTDisconnectPacket::Serialize(std::vector<uint8_t>& buffer) const {
    buffer.push_back(static_cast<uint8_t>(MQTTPacketType::DISCONNECT) << 4);
    buffer.push_back(0); // Remaining length
    return error::SUCCESS;
}

int MQTTDisconnectPacket::Deserialize(const std::vector<uint8_t>& buffer, size_t offset, size_t length) {
    // DISCONNECT has no payload
    return error::SUCCESS;
}

size_t MQTTDisconnectPacket::GetSize() const {
    return 2; // Fixed header only
}

// ============================================================================
// MQTT SUBSCRIBE Packet
// ============================================================================

MQTTSubscribePacket::MQTTSubscribePacket() : MQTTPacket(MQTTPacketType::SUBSCRIBE) {
    packet_id_ = 0;
    qos_ = 0;
}

int MQTTSubscribePacket::Serialize(std::vector<uint8_t>& buffer) const {
    // Basic implementation - serialize packet header
    buffer.push_back((static_cast<uint8_t>(MQTTPacketType::SUBSCRIBE) << 4) | 0x02);

    // Calculate payload size (simplified)
    uint32_t payload_size = 2 + 2 + static_cast<uint32_t>(topic_.length()) + 1; // Packet ID + topic length + topic + QoS

    // Encode remaining length
    EncodeRemainingLength(payload_size, buffer);

    // Packet identifier
    buffer.push_back((packet_id_ >> 8) & 0xFF);
    buffer.push_back(packet_id_ & 0xFF);

    // Topic filter
    EncodeString(topic_, buffer);
    buffer.push_back(qos_); // QoS

    return error::SUCCESS;
}

int MQTTSubscribePacket::Deserialize(const std::vector<uint8_t>& buffer, size_t offset, size_t length) {
    if (offset + 2 > buffer.size()) {
        return error::MQTT_INVALID_PACKET;
    }

    // Read packet identifier
    packet_id_ = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;

    // Read topic filter (simplified implementation)
    int bytes_read = DecodeString(buffer, offset, topic_);
    if (bytes_read < 0) {
        return error::MQTT_INVALID_PACKET;
    }
    offset += bytes_read;

    if (offset >= buffer.size()) {
        return error::MQTT_INVALID_PACKET;
    }

    qos_ = buffer[offset];

    return error::SUCCESS;
}

size_t MQTTSubscribePacket::GetSize() const {
    return 2 + 2 + topic_.length() + 1; // Packet ID + topic length + topic + QoS
}

// ============================================================================
// MQTT SUBACK Packet
// ============================================================================

MQTTSubackPacket::MQTTSubackPacket() : MQTTPacket(MQTTPacketType::SUBACK) {
    packet_id_ = 0;
    return_code_ = 0;
}

int MQTTSubackPacket::Serialize(std::vector<uint8_t>& buffer) const {
    // Serialize packet header
    buffer.push_back(static_cast<uint8_t>(MQTTPacketType::SUBACK) << 4);

    // Calculate payload size
    uint32_t payload_size = 2 + 1; // Packet identifier + return code

    // Encode remaining length
    EncodeRemainingLength(payload_size, buffer);

    // Packet identifier
    buffer.push_back((packet_id_ >> 8) & 0xFF);
    buffer.push_back(packet_id_ & 0xFF);

    // Return code
    buffer.push_back(return_code_);

    return error::SUCCESS;
}

int MQTTSubackPacket::Deserialize(const std::vector<uint8_t>& buffer, size_t offset, size_t length) {
    if (offset + 3 > buffer.size()) {
        return error::MQTT_INVALID_PACKET;
    }

    // Read packet identifier
    packet_id_ = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;

    // Read return code
    return_code_ = buffer[offset];

    return error::SUCCESS;
}

size_t MQTTSubackPacket::GetSize() const {
    return 2 + 1; // Packet identifier + return code
}

} // namespace xiaozhi
