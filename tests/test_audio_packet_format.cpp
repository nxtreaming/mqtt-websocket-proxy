#include "utils/crypto_utils.h"
#include "utils/logger.h"
#include "common/error_codes.h"

#include <iostream>
#include <vector>
#include <iomanip>
#include <cassert>

using namespace xiaozhi;
using namespace xiaozhi::crypto;

void PrintHex(const std::vector<uint8_t>& data, const std::string& label) {
    std::cout << label << ": ";
    for (uint8_t byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
}

void TestWebSocketAudioPacketGeneration() {
    std::cout << "Testing WebSocket audio packet generation..." << std::endl;
    
    // Create test Opus audio data
    std::vector<uint8_t> opus_data = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    uint32_t timestamp = 1234567890;

    std::vector<uint8_t> packet;
    int ret = UDPHeaderGenerator::GenerateWebSocketAudioPacket(opus_data, timestamp, packet);
    assert(ret == error::SUCCESS);

    // Verify packet format
    assert(packet.size() == 16 + opus_data.size());

    // Verify first 8 bytes are 0 (unknown data)
    for (int i = 0; i < 8; ++i) {
        assert(packet[i] == 0);
    }

    // Verify timestamp (big-endian, offset 8)
    uint32_t parsed_timestamp = (static_cast<uint32_t>(packet[8]) << 24) |
                               (static_cast<uint32_t>(packet[9]) << 16) |
                               (static_cast<uint32_t>(packet[10]) << 8) |
                               static_cast<uint32_t>(packet[11]);
    assert(parsed_timestamp == timestamp);

    // Verify Opus length (big-endian, offset 12)
    uint32_t parsed_length = (static_cast<uint32_t>(packet[12]) << 24) |
                            (static_cast<uint32_t>(packet[13]) << 16) |
                            (static_cast<uint32_t>(packet[14]) << 8) |
                            static_cast<uint32_t>(packet[15]);
    assert(parsed_length == opus_data.size());

    // Verify Opus data (offset 16)
    for (size_t i = 0; i < opus_data.size(); ++i) {
        assert(packet[16 + i] == opus_data[i]);
    }
    
    PrintHex(packet, "Generated WebSocket Audio Packet");
    
    std::cout << "WebSocket audio packet generation test passed" << std::endl;
}

void TestWebSocketAudioPacketParsing() {
    std::cout << "Testing WebSocket audio packet parsing..." << std::endl;
    
    // Create test packet (JavaScript format)
    std::vector<uint8_t> packet = {
        // Unknown data (8 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Timestamp (4 bytes, big-endian): 1234567890 = 0x499602D2
        0x49, 0x96, 0x02, 0xD2,
        // Opus length (4 bytes, big-endian): 16 = 0x00000010
        0x00, 0x00, 0x00, 0x10,
        // Opus data (16 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };

    std::vector<uint8_t> opus_data;
    uint32_t timestamp;

    int ret = UDPHeaderGenerator::ParseWebSocketAudioPacket(packet, opus_data, timestamp);
    assert(ret == error::SUCCESS);

    // Verify parsing results
    assert(timestamp == 1234567890);
    assert(opus_data.size() == 16);
    
    std::vector<uint8_t> expected_opus = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    
    for (size_t i = 0; i < expected_opus.size(); ++i) {
        assert(opus_data[i] == expected_opus[i]);
    }
    
    PrintHex(opus_data, "Parsed Opus Data");
    std::cout << "Parsed timestamp: " << timestamp << std::endl;
    
    std::cout << "WebSocket audio packet parsing test passed" << std::endl;
}

void TestJavaScriptCompatibility() {
    std::cout << "Testing JavaScript compatibility..." << std::endl;
    
    // Simulate JavaScript code:
    // const timestamp = data.readUInt32BE(8);
    // const opusLength = data.readUInt32BE(12);
    // const opus = data.subarray(16, 16 + opusLength);

    std::vector<uint8_t> original_opus = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00
    };
    uint32_t original_timestamp = 0x12345678;

    // Generate packet
    std::vector<uint8_t> packet;
    int ret = UDPHeaderGenerator::GenerateWebSocketAudioPacket(original_opus, original_timestamp, packet);
    assert(ret == error::SUCCESS);

    // Simulate JavaScript parsing
    assert(packet.size() >= 16);
    
    // JavaScript: const timestamp = data.readUInt32BE(8);
    uint32_t js_timestamp = (static_cast<uint32_t>(packet[8]) << 24) |
                           (static_cast<uint32_t>(packet[9]) << 16) |
                           (static_cast<uint32_t>(packet[10]) << 8) |
                           static_cast<uint32_t>(packet[11]);
    
    // JavaScript: const opusLength = data.readUInt32BE(12);
    uint32_t js_opus_length = (static_cast<uint32_t>(packet[12]) << 24) |
                             (static_cast<uint32_t>(packet[13]) << 16) |
                             (static_cast<uint32_t>(packet[14]) << 8) |
                             static_cast<uint32_t>(packet[15]);
    
    // JavaScript: const opus = data.subarray(16, 16 + opusLength);
    std::vector<uint8_t> js_opus(packet.begin() + 16, packet.begin() + 16 + js_opus_length);
    
    // Verify JavaScript parsing results
    assert(js_timestamp == original_timestamp);
    assert(js_opus_length == original_opus.size());
    assert(js_opus == original_opus);

    // Verify using C++ parser
    std::vector<uint8_t> cpp_opus;
    uint32_t cpp_timestamp;
    ret = UDPHeaderGenerator::ParseWebSocketAudioPacket(packet, cpp_opus, cpp_timestamp);
    assert(ret == error::SUCCESS);
    assert(cpp_timestamp == js_timestamp);
    assert(cpp_opus == js_opus);
    
    std::cout << "JavaScript timestamp: 0x" << std::hex << js_timestamp << std::dec << std::endl;
    std::cout << "JavaScript opus length: " << js_opus_length << std::endl;
    std::cout << "C++ timestamp: 0x" << std::hex << cpp_timestamp << std::dec << std::endl;
    std::cout << "C++ opus length: " << cpp_opus.size() << std::endl;
    
    std::cout << "JavaScript compatibility test passed" << std::endl;
}

void TestErrorHandling() {
    std::cout << "Testing error handling..." << std::endl;
    
    std::vector<uint8_t> opus_data;
    uint32_t timestamp;
    
    // Test packet too short
    std::vector<uint8_t> short_packet = {0x01, 0x02, 0x03};
    int ret = UDPHeaderGenerator::ParseWebSocketAudioPacket(short_packet, opus_data, timestamp);
    assert(ret != error::SUCCESS);

    // Test Opus length mismatch
    std::vector<uint8_t> invalid_packet = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Unknown
        0x00, 0x00, 0x00, 0x01,                          // Timestamp
        0x00, 0x00, 0x00, 0xFF,                          // Invalid opus length (255)
        0x01, 0x02                                       // Only 2 bytes of data
    };
    ret = UDPHeaderGenerator::ParseWebSocketAudioPacket(invalid_packet, opus_data, timestamp);
    assert(ret != error::SUCCESS);
    
    std::cout << "Error handling test passed" << std::endl;
}

int main() {
    std::cout << "=== xiaozhi-mqtt-gateway Audio Packet Format Test ===" << std::endl;
    
    // Initialize logger
    Logger& logger = Logger::GetInstance();
    if (!logger.Initialize(LogLevel::DEBUG)) {
        std::cerr << "Failed to initialize logger" << std::endl;
        return 1;
    }
    
    try {
        TestWebSocketAudioPacketGeneration();
        TestWebSocketAudioPacketParsing();
        TestJavaScriptCompatibility();
        TestErrorHandling();
        
        std::cout << std::endl;
        std::cout << "All Audio Packet Format Tests Passed!" << std::endl;
        std::cout << std::endl;
        std::cout << "Working Features:" << std::endl;
        std::cout << "  WebSocket Audio Packet Generation" << std::endl;
        std::cout << "  WebSocket Audio Packet Parsing" << std::endl;
        std::cout << "  JavaScript Format Compatibility" << std::endl;
        std::cout << "  Big-Endian Timestamp/Length Handling" << std::endl;
        std::cout << "  Error Handling and Validation" << std::endl;
        std::cout << std::endl;
        std::cout << "JavaScript Compatible Format:" << std::endl;
        std::cout << "  [unknown: 8 bytes][timestamp: 4u BE][opusLength: 4u BE][opus: opusLength bytes]" << std::endl;
        std::cout << "  Timestamp at offset 8 (big-endian)" << std::endl;
        std::cout << "  Opus length at offset 12 (big-endian)" << std::endl;
        std::cout << "  Opus data at offset 16" << std::endl;
        std::cout << std::endl;
        std::cout << "Audio packet format is now compatible with JavaScript version!" << std::endl;
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}
