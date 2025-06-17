#include "connection/websocket_bridge.h"
#include "server/mqtt_server.h"
#include "server/udp_server.h"
#include "utils/crypto_utils.h"
#include "utils/logger.h"
#include "common/error_codes.h"
#include "common/constants.h"

#include <iostream>
#include <thread>
#include <chrono>
#include <signal.h>
#include <atomic>

using namespace xiaozhi;

// Global flag for controlling the test
std::atomic<bool> g_running(true);

// Signal handler for graceful shutdown
void signal_handler(int signal) {
    std::cout << "Received signal " << signal << ", shutting down..." << std::endl;
    g_running = false;
}

// Test WebSocket connection with custom headers and binary data
bool test_websocket_connection(const std::string& server_url) {
    std::cout << "Testing WebSocket connection to " << server_url << std::endl;
    
    // Set device info
    std::string mac_address = "00:11:22:33:44:55";
    std::string uuid = "test_client_uuid";
    int protocol_version = 3;
    std::string user_data = "{\"test\":\"integration\"}";

    // Initialize WebSocketBridge with device info
    WebSocketBridge ws_bridge(protocol_version, mac_address, uuid, user_data);
    ServerConfig config;
    config.websocket.production_servers.push_back(server_url); // Use production servers for testing

    // The WebSocketBridge now requires a uv_loop to manage its internal service timer.
    // We create a temporary loop here for the test.
    uv_loop_t loop;
    uv_loop_init(&loop);

    int ret = ws_bridge.Initialize(config, &loop);
    if (ret != error::SUCCESS) {
        std::cerr << "Failed to initialize WebSocketBridge: " << ret << std::endl;
        uv_loop_close(&loop);
        return false;
    }
    
    // Set up callbacks
    std::atomic<bool> connected = false;
    std::atomic<bool> received_message = false;
    
    ws_bridge.SetConnectedCallback([&connected](const std::string& url) {
        std::cout << "Connected to " << url << std::endl;
        connected = true;
    });
    
    ws_bridge.SetMessageCallback([&received_message](const std::string& message) {
        std::cout << "Received message: " << message << std::endl;
        received_message = true;
    });
    
    ws_bridge.SetDisconnectedCallback([](const std::string& url, int reason) {
        std::cout << "Disconnected from " << url << " with reason " << reason << std::endl;
    });
    
    ws_bridge.SetErrorCallback([](const std::string& error) {
        std::cerr << "WebSocket error: " << error << std::endl;
    });
    
    // Connect to server
    ret = ws_bridge.Connect(server_url, {});
    if (ret != error::SUCCESS) {
        std::cerr << "Failed to connect to WebSocket server: " << ret << std::endl;
        uv_loop_close(&loop);
        return false;
    }
    
    // Process events for a while to establish connection
    int max_attempts = 50;  // 5 seconds total
    
    for (int i = 0; i < max_attempts && g_running; ++i) {
        uv_run(&loop, UV_RUN_NOWAIT); // Drive the event loop
        if (connected) {
            std::cout << "Successfully connected!" << std::endl;
            
            // Send a test text message
            std::string test_message = "{\"type\":\"test\",\"data\":\"integration_test\"}";
            ws_bridge.SendMessage(test_message);
            
            // Wait for response to text message
            for (int j = 0; j < 30 && g_running && !received_message; ++j) {
                uv_run(&loop, UV_RUN_NOWAIT);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            if (!received_message) {
                std::cerr << "Timed out waiting for response to text message" << std::endl;
                ws_bridge.Disconnect();
                uv_run(&loop, UV_RUN_ONCE); // Allow disconnect events to process
                uv_loop_close(&loop);
                return false;
            }

            std::cout << "Successfully received response for text message!" << std::endl;

            // NOW, TEST BINARY SEND
            std::cout << "Sending a test binary message..." << std::endl;
            std::vector<unsigned char> binary_payload = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
            int send_ret = ws_bridge.SendBinaryData(binary_payload.data(), binary_payload.size());
            if (send_ret != error::SUCCESS) {
                std::cerr << "Failed to send binary data: " << error::GetErrorMessage(send_ret) << std::endl;
                ws_bridge.Disconnect();
                uv_run(&loop, UV_RUN_ONCE);
                uv_loop_close(&loop);
                return false;
            }

            // We don't have a way to verify the server received it,
            // but we can at least confirm the call succeeded and didn't crash.
            // We'll just wait a bit to let the event loop process the send.
            std::cout << "Binary data send initiated successfully." << std::endl;
            uv_run(&loop, UV_RUN_NOWAIT);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            
            ws_bridge.Disconnect();
            uv_run(&loop, UV_RUN_ONCE); // Allow disconnect events to process
            uv_loop_close(&loop);
            return true;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    std::cerr << "Timed out waiting for connection" << std::endl;
    ws_bridge.Disconnect();
    uv_run(&loop, UV_RUN_ONCE);
    uv_loop_close(&loop);
    return false;
}

// Test OpenSSL crypto implementation
bool test_crypto_implementation() {
    std::cout << "Testing OpenSSL crypto implementation" << std::endl;
    
    // Create crypto instance
    crypto::AudioCrypto crypto;
    
    // Generate a key
    std::vector<uint8_t> key = crypto.GenerateKey();
    std::cout << "Generated key of size: " << key.size() << std::endl;
    
    // Initialize crypto with the key
    int ret = crypto.Initialize(key);
    if (ret != error::SUCCESS) {
        std::cerr << "Failed to initialize crypto: " << ret << std::endl;
        return false;
    }
    
    // Create test data
    std::vector<uint8_t> test_data(1024);
    for (size_t i = 0; i < test_data.size(); ++i) {
        test_data[i] = static_cast<uint8_t>(i & 0xFF);
    }
    
    // Create header/IV
    std::vector<uint8_t> header(constants::AES_BLOCK_SIZE);
    for (size_t i = 0; i < header.size(); ++i) {
        header[i] = static_cast<uint8_t>(i & 0xFF);
    }
    
    // Encrypt data
    std::vector<uint8_t> encrypted_data;
    ret = crypto.Encrypt(test_data, header, encrypted_data);
    if (ret != error::SUCCESS) {
        std::cerr << "Failed to encrypt data: " << ret << std::endl;
        return false;
    }
    
    std::cout << "Encrypted data size: " << encrypted_data.size() << std::endl;
    
    // Decrypt data
    std::vector<uint8_t> decrypted_data;
    ret = crypto.Decrypt(encrypted_data, header, decrypted_data);
    if (ret != error::SUCCESS) {
        std::cerr << "Failed to decrypt data: " << ret << std::endl;
        return false;
    }
    
    std::cout << "Decrypted data size: " << decrypted_data.size() << std::endl;
    
    // Verify decrypted data matches original
    if (decrypted_data.size() != test_data.size()) {
        std::cerr << "Decrypted data size mismatch" << std::endl;
        return false;
    }
    
    for (size_t i = 0; i < test_data.size(); ++i) {
        if (decrypted_data[i] != test_data[i]) {
            std::cerr << "Decrypted data mismatch at index " << i << std::endl;
            return false;
        }
    }
    
    std::cout << "Crypto test passed!" << std::endl;
    return true;
}

// Test UDP header generation and parsing
bool test_udp_headers() {
    std::cout << "Testing UDP header generation and parsing" << std::endl;
    
    crypto::UDPHeaderGenerator header_gen;
    
    // Test values
    uint32_t connection_id = 12345;
    uint16_t length = 1024;
    uint32_t timestamp = 987654321;
    uint32_t sequence = 42;
    
    // Generate header
    std::vector<uint8_t> header;
    int ret = header_gen.GenerateHeader(connection_id, length, timestamp, sequence, header);
    if (ret != error::SUCCESS) {
        std::cerr << "Failed to generate UDP header: " << ret << std::endl;
        return false;
    }
    
    std::cout << "Generated UDP header of size: " << header.size() << std::endl;
    
    // Parse header
    uint32_t parsed_connection_id;
    uint16_t parsed_length;
    uint32_t parsed_timestamp;
    uint32_t parsed_sequence;
    
    ret = header_gen.ParseHeader(header, parsed_connection_id, parsed_length, parsed_timestamp, parsed_sequence);
    if (ret != error::SUCCESS) {
        std::cerr << "Failed to parse UDP header: " << ret << std::endl;
        return false;
    }
    
    // Verify parsed values
    if (parsed_connection_id != connection_id ||
        parsed_length != length ||
        parsed_timestamp != timestamp ||
        parsed_sequence != sequence) {
        std::cerr << "UDP header parsing mismatch" << std::endl;
        std::cerr << "Expected: " << connection_id << ", " << length << ", " << timestamp << ", " << sequence << std::endl;
        std::cerr << "Got: " << parsed_connection_id << ", " << parsed_length << ", " << parsed_timestamp << ", " << parsed_sequence << std::endl;
        return false;
    }
    
    std::cout << "UDP header test passed!" << std::endl;
    return true;
}

int main(int argc, char* argv[]) {
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize logger
    Logger logger;
    logger.Initialize(LogLevel::DEBUG);
    
    std::cout << "Starting integration tests..." << std::endl;
    
    bool all_tests_passed = true;
    
    // Test crypto implementation
    if (!test_crypto_implementation()) {
        std::cerr << "Crypto implementation test failed" << std::endl;
        all_tests_passed = false;
    }
    
    // Test UDP headers
    if (!test_udp_headers()) {
        std::cerr << "UDP header test failed" << std::endl;
        all_tests_passed = false;
    }
    
    // Test WebSocket connection (only if server URL provided)
    if (argc > 1) {
        std::string server_url = argv[1];
        if (!test_websocket_connection(server_url)) {
            std::cerr << "WebSocket connection test failed" << std::endl;
            all_tests_passed = false;
        }
    } else {
        std::cout << "No WebSocket server URL provided, skipping WebSocket test" << std::endl;
        std::cout << "Usage: " << argv[0] << " [websocket_server_url]" << std::endl;
    }
    
    if (all_tests_passed) {
        std::cout << "All integration tests passed!" << std::endl;
        return 0;
    } else {
        std::cerr << "Some integration tests failed" << std::endl;
        return 1;
    }
}
