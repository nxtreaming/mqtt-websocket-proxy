#include "protocol/mqtt_protocol.h"
#include "protocol/mqtt_packet.h"
#include "utils/logger.h"
#include "common/error_codes.h"

#include <iostream>
#include <vector>
#include <cassert>

using namespace xiaozhi;

void TestMQTTConnectPacket() {
    std::cout << "Testing MQTT CONNECT packet..." << std::endl;
    
    MQTTConnectPacket packet;
    packet.SetClientId("test_client_123");
    packet.SetKeepAlive(60);
    packet.SetCleanSession(true);
    
    std::vector<uint8_t> buffer;
    int ret = packet.Serialize(buffer);
    assert(ret == error::SUCCESS);
    assert(!buffer.empty());
    
    // Parse the packet back
    MQTTConnectPacket parsed_packet;
    ret = parsed_packet.Deserialize(buffer, 0, buffer.size());
    assert(ret == error::SUCCESS);
    assert(parsed_packet.GetClientId() == "test_client_123");
    assert(parsed_packet.GetKeepAlive() == 60);
    assert(parsed_packet.GetCleanSession() == true);
    
    std::cout << "MQTT CONNECT packet test passed" << std::endl;
}

void TestMQTTPublishPacket() {
    std::cout << "Testing MQTT PUBLISH packet..." << std::endl;
    
    MQTTPublishPacket packet;
    packet.SetTopic("test/topic");
    packet.SetPayload("Hello, MQTT!");
    packet.SetQoS(0);
    packet.SetRetain(false);
    packet.SetDup(false);
    
    std::vector<uint8_t> buffer;
    int ret = packet.Serialize(buffer);
    assert(ret == error::SUCCESS);
    assert(!buffer.empty());
    
    // Parse the packet back
    MQTTPublishPacket parsed_packet;
    ret = parsed_packet.Deserialize(buffer, 0, buffer.size());
    assert(ret == error::SUCCESS);
    assert(parsed_packet.GetTopic() == "test/topic");
    assert(parsed_packet.GetPayload() == "Hello, MQTT!");
    assert(parsed_packet.GetQoS() == 0);
    assert(parsed_packet.GetRetain() == false);
    assert(parsed_packet.GetDup() == false);
    
    std::cout << "MQTT PUBLISH packet test passed" << std::endl;
}

void TestMQTTProtocolParser() {
    std::cout << "Testing MQTT protocol parser..." << std::endl;
    
    MQTTProtocol protocol;
    
    // Test callback setup
    bool connect_received = false;
    bool publish_received = false;
    
    protocol.SetConnectCallback([&](const MQTTConnectPacket& packet) {
        connect_received = true;
        assert(packet.GetClientId() == "test_client");
    });
    
    protocol.SetPublishCallback([&](const MQTTPublishPacket& packet) {
        publish_received = true;
        assert(packet.GetTopic() == "test/topic");
        assert(packet.GetPayload() == "test message");
    });
    
    // Create test CONNECT packet
    MQTTConnectPacket connect_packet;
    connect_packet.SetClientId("test_client");
    connect_packet.SetKeepAlive(60);
    
    std::vector<uint8_t> connect_buffer;
    int ret = connect_packet.Serialize(connect_buffer);
    assert(ret == error::SUCCESS);
    
    // Process CONNECT packet
    ret = protocol.ProcessData(connect_buffer.data(), connect_buffer.size());
    assert(ret == error::SUCCESS);
    assert(connect_received);
    
    // Create test PUBLISH packet
    MQTTPublishPacket publish_packet;
    publish_packet.SetTopic("test/topic");
    publish_packet.SetPayload("test message");
    publish_packet.SetQoS(0);
    
    std::vector<uint8_t> publish_buffer;
    ret = publish_packet.Serialize(publish_buffer);
    assert(ret == error::SUCCESS);
    
    // Process PUBLISH packet
    ret = protocol.ProcessData(publish_buffer.data(), publish_buffer.size());
    assert(ret == error::SUCCESS);
    assert(publish_received);
    
    std::cout << "MQTT protocol parser test passed" << std::endl;
}

void TestMQTTPacketCreation() {
    std::cout << "Testing MQTT packet creation..." << std::endl;
    
    MQTTProtocol protocol;
    
    // Test CONNACK creation
    std::vector<uint8_t> connack_buffer;
    int ret = protocol.CreateConnackPacket(0, false, connack_buffer);
    assert(ret == error::SUCCESS);
    assert(!connack_buffer.empty());
    
    // Test PUBLISH creation
    std::vector<uint8_t> publish_buffer;
    ret = protocol.CreatePublishPacket("response/topic", "response message", 0, false, false, 0, publish_buffer);
    assert(ret == error::SUCCESS);
    assert(!publish_buffer.empty());
    
    // Test SUBACK creation
    std::vector<uint8_t> suback_buffer;
    ret = protocol.CreateSubackPacket(1234, 0, suback_buffer);
    assert(ret == error::SUCCESS);
    assert(!suback_buffer.empty());
    
    // Test PINGRESP creation
    std::vector<uint8_t> pingresp_buffer;
    ret = protocol.CreatePingrespPacket(pingresp_buffer);
    assert(ret == error::SUCCESS);
    assert(!pingresp_buffer.empty());
    
    std::cout << "MQTT packet creation test passed" << std::endl;
}

int main() {
    std::cout << "=== xiaozhi-mqtt-gateway MQTT Protocol Test ===" << std::endl;
    
    // Initialize logger
    Logger& logger = Logger::GetInstance();
    if (!logger.Initialize(LogLevel::DEBUG)) {
        std::cerr << "Failed to initialize logger" << std::endl;
        return 1;
    }
    
    try {
        TestMQTTConnectPacket();
        TestMQTTPublishPacket();
        TestMQTTProtocolParser();
        TestMQTTPacketCreation();
        
        std::cout << std::endl;
        std::cout << "All MQTT Protocol Tests Passed!" << std::endl;
        std::cout << std::endl;
        std::cout << "Working Features:" << std::endl;
        std::cout << "  MQTT Packet Parsing" << std::endl;
        std::cout << "  MQTT Packet Serialization" << std::endl;
        std::cout << "  MQTT Protocol State Machine" << std::endl;
        std::cout << "  MQTT Callback System" << std::endl;
        std::cout << "  QoS 0 Message Handling" << std::endl;
        std::cout << std::endl;
        std::cout << "The MQTT protocol core is working!" << std::endl;
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}
