#pragma once

#include "common/types.h"
#include <vector>
#include <string>

namespace xiaozhi {

/**
 * @brief MQTT packet base class
 */
class MQTTPacket {
public:
    /**
     * @brief Constructor
     * @param type Packet type
     */
    explicit MQTTPacket(MQTTPacketType type);

    /**
     * @brief Virtual destructor
     */
    virtual ~MQTTPacket() = default;

    /**
     * @brief Get packet type
     * @return Packet type
     */
    MQTTPacketType GetType() const;

    /**
     * @brief Serialize packet
     * @param buffer Output buffer
     * @return Error code, 0 indicates success
     */
    virtual int Serialize(std::vector<uint8_t>& buffer) const = 0;

    /**
     * @brief Deserialize packet
     * @param buffer Input buffer
     * @param offset Start offset
     * @param length Data length
     * @return Error code, 0 indicates success
     */
    virtual int Deserialize(const std::vector<uint8_t>& buffer, size_t offset, size_t length) = 0;

    /**
     * @brief Get packet size
     * @return Packet size in bytes
     */
    virtual size_t GetSize() const = 0;

    /**
     * @brief Encode remaining length
     * @param length Length value
     * @param buffer Output buffer
     * @return Number of encoded bytes
     */
    static size_t EncodeRemainingLength(uint32_t length, std::vector<uint8_t>& buffer);

    /**
     * @brief Decode remaining length
     * @param buffer Input buffer
     * @param offset Start offset
     * @param length Output length value
     * @param bytes_read Number of bytes read
     * @return Error code, 0 indicates success
     */
    static int DecodeRemainingLength(const std::vector<uint8_t>& buffer, size_t offset,
                                   uint32_t& length, size_t& bytes_read);

    /**
     * @brief Encode string
     * @param str String
     * @param buffer Output buffer
     */
    static void EncodeString(const std::string& str, std::vector<uint8_t>& buffer);

    /**
     * @brief Decode string
     * @param buffer Input buffer
     * @param offset Start offset
     * @param str Output string
     * @return Number of bytes read, -1 indicates error
     */
    static int DecodeString(const std::vector<uint8_t>& buffer, size_t offset, std::string& str);

protected:

private:
    MQTTPacketType type_;
};

/**
 * @brief MQTT CONNECT packet
 */
class MQTTConnectPacket : public MQTTPacket {
public:
    MQTTConnectPacket();
    ~MQTTConnectPacket() override = default;

    // Implement base class interface
    int Serialize(std::vector<uint8_t>& buffer) const override;
    int Deserialize(const std::vector<uint8_t>& buffer, size_t offset, size_t length) override;
    size_t GetSize() const override;

    // Accessors
    const std::string& GetClientId() const { return client_id_; }
    void SetClientId(const std::string& client_id) { client_id_ = client_id; }
    
    const std::string& GetUsername() const { return username_; }
    void SetUsername(const std::string& username) { username_ = username; }
    
    const std::string& GetPassword() const { return password_; }
    void SetPassword(const std::string& password) { password_ = password; }
    
    uint16_t GetKeepAlive() const { return keep_alive_; }
    void SetKeepAlive(uint16_t keep_alive) { keep_alive_ = keep_alive; }
    
    bool GetCleanSession() const { return clean_session_; }
    void SetCleanSession(bool clean_session) { clean_session_ = clean_session; }
    
    uint8_t GetProtocolLevel() const { return protocol_level_; }
    void SetProtocolLevel(uint8_t level) { protocol_level_ = level; }

private:
    std::string protocol_name_;
    uint8_t protocol_level_;
    uint8_t connect_flags_;
    uint16_t keep_alive_;
    std::string client_id_;
    std::string username_;
    std::string password_;
    bool clean_session_;
};

/**
 * @brief MQTT CONNACK packet
 */
class MQTTConnackPacket : public MQTTPacket {
public:
    MQTTConnackPacket();
    ~MQTTConnackPacket() override = default;

    // Implement base class interface
    int Serialize(std::vector<uint8_t>& buffer) const override;
    int Deserialize(const std::vector<uint8_t>& buffer, size_t offset, size_t length) override;
    size_t GetSize() const override;

    // Accessors
    uint8_t GetReturnCode() const { return return_code_; }
    void SetReturnCode(uint8_t code) { return_code_ = code; }
    
    bool GetSessionPresent() const { return session_present_; }
    void SetSessionPresent(bool present) { session_present_ = present; }

private:
    uint8_t connect_flags_;
    uint8_t return_code_;
    bool session_present_;
};

/**
 * @brief MQTT PUBLISH packet
 */
class MQTTPublishPacket : public MQTTPacket {
public:
    MQTTPublishPacket();
    ~MQTTPublishPacket() override = default;

    // Implement base class interface
    int Serialize(std::vector<uint8_t>& buffer) const override;
    int Deserialize(const std::vector<uint8_t>& buffer, size_t offset, size_t length) override;
    size_t GetSize() const override;

    // Accessors
    const std::string& GetTopic() const { return topic_; }
    void SetTopic(const std::string& topic) { topic_ = topic; }
    
    const std::string& GetPayload() const { return payload_; }
    void SetPayload(const std::string& payload) { payload_ = payload; }
    
    uint8_t GetQoS() const { return qos_; }
    void SetQoS(uint8_t qos) { qos_ = qos; }
    
    bool GetDup() const { return dup_; }
    void SetDup(bool dup) { dup_ = dup; }
    
    bool GetRetain() const { return retain_; }
    void SetRetain(bool retain) { retain_ = retain; }
    
    uint16_t GetPacketId() const { return packet_id_; }
    void SetPacketId(uint16_t id) { packet_id_ = id; }

private:
    std::string topic_;
    std::string payload_;
    uint8_t qos_;
    bool dup_;
    bool retain_;
    uint16_t packet_id_;
};

/**
 * @brief MQTT SUBSCRIBE packet
 */
class MQTTSubscribePacket : public MQTTPacket {
public:
    MQTTSubscribePacket();
    ~MQTTSubscribePacket() override = default;

    // Implement base class interface
    int Serialize(std::vector<uint8_t>& buffer) const override;
    int Deserialize(const std::vector<uint8_t>& buffer, size_t offset, size_t length) override;
    size_t GetSize() const override;

    // Accessors
    uint16_t GetPacketId() const { return packet_id_; }
    void SetPacketId(uint16_t id) { packet_id_ = id; }

    const std::string& GetTopic() const { return topic_; }
    void SetTopic(const std::string& topic) { topic_ = topic; }

    uint8_t GetQoS() const { return qos_; }
    void SetQoS(uint8_t qos) { qos_ = qos; }

private:
    uint16_t packet_id_;
    std::string topic_;
    uint8_t qos_;
};

/**
 * @brief MQTT SUBACK packet
 */
class MQTTSubackPacket : public MQTTPacket {
public:
    MQTTSubackPacket();
    ~MQTTSubackPacket() override = default;

    // Implement base class interface
    int Serialize(std::vector<uint8_t>& buffer) const override;
    int Deserialize(const std::vector<uint8_t>& buffer, size_t offset, size_t length) override;
    size_t GetSize() const override;

    // Accessors
    uint16_t GetPacketId() const { return packet_id_; }
    void SetPacketId(uint16_t id) { packet_id_ = id; }

    uint8_t GetReturnCode() const { return return_code_; }
    void SetReturnCode(uint8_t code) { return_code_ = code; }

private:
    uint16_t packet_id_;
    uint8_t return_code_;
};

/**
 * @brief MQTT PINGREQ packet
 */
class MQTTPingreqPacket : public MQTTPacket {
public:
    MQTTPingreqPacket();
    ~MQTTPingreqPacket() override = default;

    // Implement base class interface
    int Serialize(std::vector<uint8_t>& buffer) const override;
    int Deserialize(const std::vector<uint8_t>& buffer, size_t offset, size_t length) override;
    size_t GetSize() const override;
};

/**
 * @brief MQTT PINGRESP packet
 */
class MQTTPingrespPacket : public MQTTPacket {
public:
    MQTTPingrespPacket();
    ~MQTTPingrespPacket() override = default;

    // Implement base class interface
    int Serialize(std::vector<uint8_t>& buffer) const override;
    int Deserialize(const std::vector<uint8_t>& buffer, size_t offset, size_t length) override;
    size_t GetSize() const override;
};

/**
 * @brief MQTT DISCONNECT packet
 */
class MQTTDisconnectPacket : public MQTTPacket {
public:
    MQTTDisconnectPacket();
    ~MQTTDisconnectPacket() override = default;

    // Implement base class interface
    int Serialize(std::vector<uint8_t>& buffer) const override;
    int Deserialize(const std::vector<uint8_t>& buffer, size_t offset, size_t length) override;
    size_t GetSize() const override;
};

} // namespace xiaozhi
