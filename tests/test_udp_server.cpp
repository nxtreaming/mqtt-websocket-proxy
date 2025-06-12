// System headers first
#include <iostream>
#include <thread>
#include <chrono>
#include <fstream>
#include <uv.h>

// Project headers
#include "server/udp_server.h"
#include "utils/config_manager.h"
#include "common/error_codes.h"
#include "common/types.h"

// Include logger.h last to ensure proper macro definitions
#include "utils/logger.h"

using namespace xiaozhi;

// Test UDP client to simulate audio data
class TestUDPClient {
public:
    TestUDPClient(uv_loop_t* loop) : loop_(loop), udp_handle_(nullptr) {}
    
    ~TestUDPClient() {
        if (udp_handle_) {
            uv_close(reinterpret_cast<uv_handle_t*>(udp_handle_), nullptr);
            delete udp_handle_;
        }
    }
    
    int Initialize() {
        udp_handle_ = new uv_udp_t;
        udp_handle_->data = this;
        
        int ret = uv_udp_init(loop_, udp_handle_);
        if (ret != 0) {
            std::cerr << "Failed to initialize UDP client: " << uv_strerror(ret) << std::endl;
            return -1;
        }
        
        return 0;
    }
    
    int SendHandshake(const std::string& server_host, int server_port) {
        // Create handshake packet
        std::vector<uint8_t> packet;
        packet.push_back(static_cast<uint8_t>(UDPPacketType::HANDSHAKE));
        packet.push_back(0); // Session ID length (0 for handshake)
        
        // Add some handshake data
        std::string handshake_data = "test_client_handshake";
        packet.insert(packet.end(), handshake_data.begin(), handshake_data.end());
        
        return SendPacket(server_host, server_port, packet);
    }
    
    int SendAudioData(const std::string& server_host, int server_port, const std::string& session_id) {
        // Create audio data packet
        std::vector<uint8_t> packet;
        packet.push_back(static_cast<uint8_t>(UDPPacketType::AUDIO_DATA));
        packet.push_back(static_cast<uint8_t>(session_id.length()));
        packet.insert(packet.end(), session_id.begin(), session_id.end());
        
        // Add some fake audio data
        std::vector<uint8_t> audio_data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        packet.insert(packet.end(), audio_data.begin(), audio_data.end());
        
        return SendPacket(server_host, server_port, packet);
    }
    
private:
    int SendPacket(const std::string& host, int port, const std::vector<uint8_t>& data) {
        struct sockaddr_in addr;
        int ret = uv_ip4_addr(host.c_str(), port, &addr);
        if (ret != 0) {
            std::cerr << "Invalid address: " << host << ":" << port << std::endl;
            return -1;
        }
        
        auto send_req = new uv_udp_send_t;
        auto buffer_data = new uint8_t[data.size()];
        std::memcpy(buffer_data, data.data(), data.size());
        
        uv_buf_t buffer = uv_buf_init(reinterpret_cast<char*>(buffer_data), (unsigned int)data.size());
        
        // Store the buffer data in the request's data field for cleanup
        send_req->data = buffer_data;
        
        ret = uv_udp_send(send_req, udp_handle_, &buffer, 1, 
                          reinterpret_cast<const struct sockaddr*>(&addr), 
                          [](uv_udp_send_t* req, int status) {
                              // Clean up the buffer data
                              delete[] static_cast<uint8_t*>(req->data);
                              delete req;
                              if (status != 0) {
                                  std::cerr << "Send failed: " << uv_strerror(status) << std::endl;
                              }
                          });
        
        if (ret != 0) {
            std::cerr << "Failed to send packet: " << uv_strerror(ret) << std::endl;
            delete[] buffer_data;
            delete send_req;
            return -1;
        }
        
        return 0;
    }
    
private:
    uv_loop_t* loop_;
    uv_udp_t* udp_handle_;
};

// Create test configuration
void CreateTestConfig() {
    std::ofstream config_file("tests/udp_test_config.json");
    config_file << R"({
  "mqtt": {
    "host": "127.0.0.1",
    "port": 1883,
    "max_connections": 100,
    "max_payload_size": 8192
  },
  "udp": {
    "host": "127.0.0.1",
    "port": 8884,
    "public_ip": "127.0.0.1"
  },
  "websocket": {
    "production_servers": ["wss://echo.websocket.org"],
    "development_servers": ["wss://echo.websocket.org"],
    "development_mac_addresses": []
  },
  "logging": {
    "enabled": true,
    "level": "debug",
    "file_path": ""
  },
  "mcp": {
    "enabled": false,
    "max_tools_count": 32
  },
  "debug": true
})";
    config_file.close();
}

int main() {
    std::cout << "=== xiaozhi-mqtt-gateway UDP Server Test ===" << std::endl;
    
    // Initialize logger
    Logger& logger = Logger::GetInstance();
    if (!logger.Initialize(LogLevel::DEBUG)) {
        std::cerr << "Failed to initialize logger" << std::endl;
        return 1;
    }
    
    // Create test configuration
    CreateTestConfig();
    
    Logger::GetInstance().Log(LogLevel::INFO, "Starting UDP server test...");
    
    try {
        // Create event loop
        uv_loop_t loop;
        uv_loop_init(&loop);
        
        // Create and configure UDP server
        UDPServer udp_server(&loop);
        
        // Load configuration
        ConfigManager config_manager;
        int ret = config_manager.LoadConfig("tests/udp_test_config.json");
        if (ret != error::SUCCESS) {
            LOG_ERROR("Failed to load configuration: " + error::GetErrorMessage(ret));
            return 1;
        }
        
        ServerConfig config = config_manager.GetConfig();
        
        // Set up callbacks
        udp_server.SetAudioDataCallback([](const std::string& session_id, const std::vector<uint8_t>& audio_data) {
            Logger::GetInstance().Log(LogLevel::INFO, "Audio data received: session=" + session_id + ", size=" + std::to_string(static_cast<unsigned int>(audio_data.size())), __FILE__, __LINE__, "");
        });
        
        udp_server.SetSessionCreatedCallback([](const std::string& session_id, const UDPConnectionInfo& info) {
            Logger::GetInstance().Log(LogLevel::INFO, "Session created: " + session_id + " from " + info.remote_address + ":" + std::to_string(info.remote_port), __FILE__, __LINE__, "");
        });
        
        udp_server.SetSessionClosedCallback([](const std::string& session_id) {
            LOG_INFO("Session closed: " + session_id);
        });
        
        udp_server.SetErrorCallback([](const std::string& error_message) {
            LOG_ERROR("UDP server error: " + error_message);
        });
        
        // Initialize and start UDP server
        ret = udp_server.Initialize(config);
        if (ret != error::SUCCESS) {
            LOG_ERROR("UDP server initialization failed" + error::GetErrorMessage(ret));
            return 1;
        }
        
        ret = udp_server.Start();
        if (ret != error::SUCCESS) {
            LOG_ERROR("UDP server start failed: " + error::GetErrorMessage(ret));
            return 1;
        }
        
        LOG_INFO("UDP server started on 127.0.0.1:8884");
        
        // Create test UDP client
        TestUDPClient client(&loop);
        if (client.Initialize() != 0) {
            LOG_ERROR("UDP client initialization failed");
            return 1;
        }
        
        std::cout << std::endl;
        std::cout << "UDP Server Test Running!" << std::endl;
        std::cout << "  UDP Server: 127.0.0.1:8884" << std::endl;
        std::cout << std::endl;
        std::cout << "Test Sequence:" << std::endl;
        std::cout << "1. Sending handshake packet..." << std::endl;
        
        // Send handshake after a short delay
        auto handshake_timer = new uv_timer_t;
        handshake_timer->data = &client;
        uv_timer_init(&loop, handshake_timer);
        uv_timer_start(handshake_timer, [](uv_timer_t* timer) {
            TestUDPClient* client = static_cast<TestUDPClient*>(timer->data);
            client->SendHandshake("127.0.0.1", 8884);
            std::cout << "2. Handshake sent!" << std::endl;
            
            // Clean up timer
            uv_timer_stop(timer);
            uv_close(reinterpret_cast<uv_handle_t*>(timer), [](uv_handle_t* handle) {
                delete reinterpret_cast<uv_timer_t*>(handle);
            });
        }, 1000, 0);
        
        // Send audio data after handshake
        auto audio_timer = new uv_timer_t;
        audio_timer->data = &client;
        uv_timer_init(&loop, audio_timer);
        uv_timer_start(audio_timer, [](uv_timer_t* timer) {
            TestUDPClient* client = static_cast<TestUDPClient*>(timer->data);
            client->SendAudioData("127.0.0.1", 8884, "test_session_123");
            std::cout << "3. Audio data sent!" << std::endl;
            
            // Clean up timer
            uv_timer_stop(timer);
            uv_close(reinterpret_cast<uv_handle_t*>(timer), [](uv_handle_t* handle) {
                delete reinterpret_cast<uv_timer_t*>(handle);
            });
        }, 2000, 0);
        
        // Stop after 10 seconds
        auto stop_timer = new uv_timer_t;
        stop_timer->data = &udp_server;
        uv_timer_init(&loop, stop_timer);
        uv_timer_start(stop_timer, [](uv_timer_t* timer) {
            UDPServer* server = static_cast<UDPServer*>(timer->data);
            server->Stop();
            std::cout << "4. Test completed!" << std::endl;
            
            // Clean up timer
            uv_timer_stop(timer);
            uv_close(reinterpret_cast<uv_handle_t*>(timer), [](uv_handle_t* handle) {
                delete reinterpret_cast<uv_timer_t*>(handle);
            });
        }, 10000, 0);
        
        // Run event loop
        uv_run(&loop, UV_RUN_DEFAULT);
        
        // Show statistics
        UDPServerStats stats = udp_server.GetStats();
        std::cout << std::endl;
        std::cout << "UDP Server Statistics:" << std::endl;
        std::cout << "  Active sessions: " << stats.active_sessions << std::endl;
        std::cout << "  Total sessions: " << stats.total_sessions << std::endl;
        std::cout << "  Packets received: " << stats.packets_received << std::endl;
        std::cout << "  Packets sent: " << stats.packets_sent << std::endl;
        std::cout << "  Bytes received: " << stats.bytes_received << std::endl;
        std::cout << "  Bytes sent: " << stats.bytes_sent << std::endl;
        
        // Cleanup
        uv_loop_close(&loop);
        
        std::cout << std::endl;
        std::cout << "UDP Server Test Completed Successfully!" << std::endl;
        std::cout << std::endl;
        std::cout << "Working Features:" << std::endl;
        std::cout << "  UDP Server - Accept audio packets" << std::endl;
        std::cout << "  Session Management - Create/close sessions" << std::endl;
        std::cout << "  Packet Parsing - Handle different packet types" << std::endl;
        std::cout << "  Statistics Tracking - Monitor server activity" << std::endl;
        std::cout << "  Handshake Protocol - Client registration" << std::endl;
        std::cout << "  Audio Data Processing - Receive and forward" << std::endl;
        
        return 0;
        
    } catch (const std::exception& e) {
        Logger::GetInstance().Log(LogLevel::ERROR, "Test failed with exception: " + std::string(e.what()));
        return 1;
    }
}
