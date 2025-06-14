// Windows headers must be included first to avoid conflicts
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_   // Prevent winsock.h from being included
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// Undefine Windows macros that conflict with our code
#ifdef ERROR
#undef ERROR
#endif
#endif

#include "connection/mqtt_connection.h"
#include "connection/websocket_bridge.h"
#include "common/error_codes.h"
#include "common/constants.h"
#include "utils/logger.h"
#include "utils/mqtt_auth.h"
#include "utils/crypto_utils.h"

#include <random>
#include <cstdio>

#include <uv.h>
#include <nlohmann/json.hpp>
#include <cstring>

namespace xiaozhi {

MQTTConnection::MQTTConnection(ConnectionId connection_id, uv_tcp_t* tcp_handle, uv_loop_t* loop, const ServerConfig& config)
    : connection_id_(connection_id)
    , tcp_handle_(tcp_handle)
    , loop_(loop)
    , active_(false)
    , authenticated_(false)
    , device_said_goodbye_(false)
    , closing_(false)
    , config_(config)
    , udp_info_()
    , session_start_time_(std::chrono::steady_clock::now())
    , session_duration_ms_(0) {

    tcp_handle_->data = this;
    read_buffer_.reserve(constants::TCP_BUFFER_SIZE);
}

MQTTConnection::~MQTTConnection() {
    Stop();
}

int MQTTConnection::Initialize() {
    // Create MQTT protocol handler
    mqtt_protocol_ = std::make_unique<MQTTProtocol>();

    // Initialize MCP proxy (JavaScript version compatible)
    mcp_proxy_ = std::make_unique<mcp::MCPProxy>();
    // Note: MCP proxy will be initialized after authentication with config

    // Set up MQTT protocol callbacks
    mqtt_protocol_->SetConnectCallback([this](const MQTTConnectPacket& packet) {
        OnMQTTConnect(packet);
    });
    
    mqtt_protocol_->SetPublishCallback([this](const MQTTPublishPacket& packet) {
        OnMQTTPublish(packet);
    });
    
    mqtt_protocol_->SetSubscribeCallback([this](const MQTTSubscribePacket& packet) {
        OnMQTTSubscribe(packet);
    });
    
    mqtt_protocol_->SetPingreqCallback([this]() {
        OnMQTTPingreq();
    });
    
    mqtt_protocol_->SetDisconnectCallback([this]() {
        OnMQTTDisconnect();
    });
    
    mqtt_protocol_->SetErrorCallback([this](int error_code, const std::string& message) {
        OnMQTTError(error_code, message);
    });
    
    // Set maximum payload size
    mqtt_protocol_->SetMaxPayloadSize(constants::MQTT_MAX_PAYLOAD_SIZE);
    
    active_ = true;
    
    LOG_DEBUG("MQTT connection " + std::to_string(connection_id_) + " initialized");
    return error::SUCCESS;
}

int MQTTConnection::StartReading() {
    if (!active_) {
        return error::CONNECTION_CLOSED;
    }
    
    int ret = uv_read_start(reinterpret_cast<uv_stream_t*>(tcp_handle_), AllocBuffer, OnRead);
    if (ret != 0) {
        LOG_ERROR("Failed to start reading from connection " + std::to_string(connection_id_) + 
                  ": " + std::string(uv_strerror(ret)));
        return error::NETWORK_ERROR;
    }
    
    LOG_DEBUG("Started reading from MQTT connection " + std::to_string(connection_id_));
    return error::SUCCESS;
}

void MQTTConnection::Stop() {
    if (!active_) {
        return;
    }
    
    active_ = false;
    
    // Stop reading
    uv_read_stop(reinterpret_cast<uv_stream_t*>(tcp_handle_));
    
    // Close the handle
    Close();
    
    LOG_DEBUG("MQTT connection " + std::to_string(connection_id_) + " stopped");
}

int MQTTConnection::SendData(const uint8_t* data, size_t length) {
    if (!active_ || !data || length == 0) {
        return error::INVALID_PARAMETER;
    }
    
    // Allocate write request
    auto write_req = std::make_unique<uv_write_t>();

    // Allocate buffer (will be freed in write callback)
    auto buffer_data = std::make_unique<uint8_t[]>(length);
    std::memcpy(buffer_data.get(), data, length);

    // Store both connection and buffer pointer in request data for cleanup
    struct WriteData {
        MQTTConnection* connection;
        uint8_t* buffer;
    };
    auto write_data = new WriteData{this, buffer_data.release()};
    write_req->data = write_data;

    uv_buf_t buffer = uv_buf_init(reinterpret_cast<char*>(write_data->buffer), (unsigned int)length);
    
    int ret = uv_write(write_req.release(), reinterpret_cast<uv_stream_t*>(tcp_handle_), 
                       &buffer, 1, OnWrite);
    if (ret != 0) {
        LOG_ERROR("Failed to write to connection " + std::to_string(connection_id_) + 
                  ": " + std::string(uv_strerror(ret)));
        delete[] buffer.base; // Clean up on error
        return error::SEND_FAILED;
    }
    
    return error::SUCCESS;
}

int MQTTConnection::SendMQTTPacket(const std::vector<uint8_t>& buffer) {
    return SendData(buffer.data(), buffer.size());
}

int MQTTConnection::ForwardFromWebSocket(const std::string& topic, const std::string& payload) {
    if (!authenticated_) {
        LOG_WARN("Attempting to forward to unauthenticated connection " + std::to_string(connection_id_));
        return error::MQTT_AUTHENTICATION_FAILED;
    }
    
    // Create PUBLISH packet
    std::vector<uint8_t> buffer;
    int ret = mqtt_protocol_->CreatePublishPacket(topic, payload, 0, false, false, 0, buffer);
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to create PUBLISH packet for forwarding: " + error::GetErrorMessage(ret));
        return ret;
    }
    
    ret = SendMQTTPacket(buffer);
    if (ret == error::SUCCESS) {
        LOG_DEBUG("Forwarded message to client " + std::to_string(connection_id_) + 
                  ": topic=" + topic + ", size=" + std::to_string(payload.length()));
    }
    
    return ret;
}

int MQTTConnection::SendUDPInfo(const UDPConnectionInfo& udp_info) {
    // Send UDP info as a special MQTT message compatible with JS version
    // Format: topic="$SYS/udp/info", payload=JSON with UDP connection details including encryption

    // Convert encryption key and nonce to hex strings (compatible with JS)
    std::string key_hex = crypto::utils::EncodeBase64(udp_info.encryption_key);
    std::string nonce_hex = crypto::utils::EncodeBase64(udp_info.nonce);

    // Create JSON payload with UDP info (compatible with JS hello response)
    nlohmann::json udp_json;
    udp_json["type"] = "hello";
    udp_json["version"] = 3;
    udp_json["session_id"] = udp_info.session_id;
    udp_json["transport"] = "udp";

    nlohmann::json udp_details;
    udp_details["server"] = udp_info.remote_address;
    udp_details["port"] = udp_info.remote_port;
    udp_details["encryption"] = udp_info.encryption_method;
    udp_details["key"] = key_hex;
    udp_details["nonce"] = nonce_hex;

    udp_json["udp"] = udp_details;

    // Add audio parameters (default values)
    nlohmann::json audio_params;
    audio_params["sample_rate"] = constants::AUDIO_SAMPLE_RATE;
    audio_params["channels"] = constants::AUDIO_CHANNELS;
    audio_params["bits_per_sample"] = constants::AUDIO_BITS_PER_SAMPLE;
    audio_params["codec"] = "opus";
    audio_params["bitrate"] = constants::AUDIO_BITRATE;
    audio_params["frame_size"] = constants::AUDIO_FRAME_SIZE;

    udp_json["audio_params"] = audio_params;

    std::string json_payload = udp_json.dump();

    LOG_DEBUG("Sending encrypted UDP info to client " + std::to_string(connection_id_) +
              ": session=" + udp_info.session_id + ", encryption=" + udp_info.encryption_method);

    return ForwardFromWebSocket("hello", json_payload);
}

ConnectionId MQTTConnection::GetConnectionId() const {
    return connection_id_;
}

const std::string& MQTTConnection::GetClientId() const {
    return client_id_;
}

bool MQTTConnection::IsActive() const {
    return active_;
}

std::chrono::milliseconds MQTTConnection::GetSessionDuration() const {
    if (active_) {
        // Calculate current duration if session is still active
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now - session_start_time_);
    }
    // Return stored duration if session has ended
    return session_duration_ms_;
}

bool MQTTConnection::IsKeepAliveTimeout() const {
    return mqtt_protocol_ ? mqtt_protocol_->IsKeepAliveTimeout() : false;
}

void MQTTConnection::OnDataReceived(const uint8_t* data, size_t length) {
    if (!mqtt_protocol_) {
        LOG_ERROR("MQTT protocol not initialized for connection " + std::to_string(connection_id_));
        return;
    }
    
    int ret = mqtt_protocol_->ProcessData(data, length);
    if (ret != error::SUCCESS) {
        LOG_ERROR("MQTT protocol error for connection " + std::to_string(connection_id_) + 
                  ": " + error::GetErrorMessage(ret));
        Stop();
    }
}

void MQTTConnection::OnMQTTConnect(const MQTTConnectPacket& packet) {
    client_id_ = packet.GetClientId();

    LOG_INFO("MQTT CONNECT from " + std::to_string(connection_id_) +
             ": client_id=" + client_id_);

    // Perform strict client authentication (compatible with JavaScript version)
    credentials_ = auth::MqttAuthenticator::ValidateCredentials(
        packet.GetClientId(),
        packet.GetUsername(),
        packet.GetPassword()
    );

    if (!credentials_.is_valid) {
        LOG_WARN("MQTT authentication failed for client: " + packet.GetClientId() +
                 " from connection " + std::to_string(connection_id_));

        // Send CONNACK rejecting connection (5 = Connection Refused, not authorized)
        SendConnack(5);

        // Close connection (JavaScript version: this.close())
        Close();
        return;
    }

    // Set keep alive interval
    mqtt_protocol_->SetKeepAliveInterval(packet.GetKeepAlive());

    // Mark as authenticated
    authenticated_ = true;

    LOG_INFO("MQTT authentication successful: client_id=" + packet.GetClientId() +
             ", group_id=" + credentials_.group_id +
             ", mac_address=" + credentials_.mac_address +
             ", reply_to=" + credentials_.reply_to_topic);

    // Send successful CONNACK (JavaScript version: this.sendConnack(0, false))
    SendConnack(0); // 0 = Connection Accepted

    // Initialize MCP proxy (JavaScript version: this.initializeDeviceTools())
    if (mcp_proxy_) {
        // Use the configuration passed from the gateway server
        ServerConfig mcp_config = config_;
        mcp_config.mcp.enabled = true;
        mcp_config.mcp.max_tools_count = 32;

        mcp_proxy_->Initialize(mcp_config);
        mcp_proxy_->InitializeDeviceTools();
    }

    LOG_INFO("MQTT client authenticated: " + client_id_);
}

void MQTTConnection::OnMQTTPublish(const MQTTPublishPacket& packet) {
    if (!authenticated_) {
        LOG_WARN("PUBLISH from unauthenticated connection " + std::to_string(connection_id_));
        return;
    }

    LOG_DEBUG("MQTT PUBLISH from " + client_id_ +
              ": topic=" + packet.GetTopic() +
              ", size=" + std::to_string(packet.GetPayload().length()));

    // JavaScript version: if (publishData.qos !== 0) { this.close(); return; }
    if (packet.GetQoS() != 0) {
        LOG_WARN("Unsupported QoS level: " + std::to_string(packet.GetQoS()) + ", closing connection");
        Close();
        return;
    }

    // Parse JSON message (JavaScript version: const json = JSON.parse(publishData.payload))
    try {
        nlohmann::json json = nlohmann::json::parse(packet.GetPayload());

        if (json.contains("type")) {
            std::string message_type = json["type"];

            if (message_type == "hello") {
                // JavaScript version: if (json.version !== 3) { this.close(); return; }
                if (!json.contains("version") || json["version"] != 3) {
                    LOG_WARN("Unsupported protocol version: " +
                             (json.contains("version") ? std::to_string(json["version"].get<int>()) : "missing") +
                             ", closing connection");
                    Close();
                    return;
                }

                // Handle hello message (JavaScript version: this.parseHelloMessage(json))
                ParseHelloMessage(json);
                return;

            } else if (message_type == "mcp") {
                // Process MCP message
                if (mcp_proxy_) {
                    if (json.contains("payload") && json["payload"].contains("result")) {
                        // MCP response message
                        mcp_proxy_->HandleMcpResponse(json);
                    } else {
                        // MCP request message (from bridge)
                        mcp_proxy_->OnMcpMessageFromBridge(json);
                    }
                }
                return; // MCP messages are not forwarded to WebSocket

            } else {
                // Other message types (JavaScript version: this.parseOtherMessage(json))
                ParseOtherMessage(json);
                return;
            }
        }

    } catch (const std::exception& e) {
        LOG_ERROR("Failed to parse JSON message: " + std::string(e.what()) + ", closing connection");
        Close();
        return;
    }

    // If we reach here, the message format is problematic
    LOG_WARN("Invalid message format, closing connection");
    Close();
}

void MQTTConnection::ParseHelloMessage(const nlohmann::json& json) {
    // JavaScript version: async parseHelloMessage(json)
    LOG_INFO("Processing hello message from " + client_id_);

    try {
        // Create WebSocket bridge (JavaScript version: this.bridge = new WebSocketBridge(...))
        websocket_bridge_ = std::make_unique<WebSocketBridge>();

        // Initialize WebSocket bridge, passing authentication info
        // JavaScript version: new WebSocketBridge(this, json.version, this.macAddress, this.uuid, this.userData)
        int protocol_version = json.value("version", 3);
        std::string mac_address = credentials_.mac_address;
        std::string user_data = credentials_.uuid; // Use UUID as user data

        int ret = websocket_bridge_->InitializeWithDeviceInfo(config_, loop_,
                                                             mac_address,
                                                             protocol_version,
                                                             user_data);
        if (ret != error::SUCCESS) {
            LOG_ERROR("Failed to initialize WebSocket bridge: " + error::GetErrorMessage(ret));
            Close();
            return;
        }

        // Set WebSocket bridge callbacks
        websocket_bridge_->SetConnectedCallback([this, json](const std::string& server_url) {
            LOG_INFO("WebSocket bridge connected to: " + server_url);
            
            // Send hello message to WebSocket server (JavaScript version compatible)
            nlohmann::json hello_msg;
            hello_msg["type"] = "hello";
            hello_msg["version"] = json.value("version", 3);
            hello_msg["transport"] = "websocket";
            
            // Add client ID (JavaScript version: this.clientId)
            hello_msg["client_id"] = client_id_;
            
            // Add MAC address (JavaScript version: this.macAddress)
            hello_msg["mac_address"] = credentials_.mac_address;
            
            // Add group ID (JavaScript version: this.groupId)
            hello_msg["group_id"] = credentials_.group_id;
            
            // Add UUID if available (JavaScript version: this.uuid)
            if (!credentials_.uuid.empty()) {
                hello_msg["uuid"] = credentials_.uuid;
            }
            
            // Add audio parameters
            if (json.contains("audio_params")) {
                hello_msg["audio_params"] = json["audio_params"];
            } else {
                // Default audio parameters
                nlohmann::json audio_params;
                audio_params["sample_rate"] = constants::AUDIO_SAMPLE_RATE;
                audio_params["channels"] = constants::AUDIO_CHANNELS;
                audio_params["bits_per_sample"] = constants::AUDIO_BITS_PER_SAMPLE;
                audio_params["codec"] = "opus";
                audio_params["bitrate"] = constants::AUDIO_BITRATE;
                audio_params["frame_size"] = constants::AUDIO_FRAME_SIZE;
                hello_msg["audio_params"] = audio_params;
            }
            
            // Add device features
            if (json.contains("features")) {
                hello_msg["features"] = json["features"];
            } else {
                // Default features
                nlohmann::json features;
                features["supports_mcp"] = true;
                features["supports_audio"] = true;
                features["supports_encryption"] = true;
                features["supported_codecs"] = nlohmann::json::array({"opus"});
                hello_msg["features"] = features;
            }
            
            // Add timestamp (JavaScript version: Date.now())
            auto now = std::chrono::system_clock::now();
            auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()).count();
            hello_msg["timestamp"] = timestamp;
            
            // Send hello message
            websocket_bridge_->SendMessage(hello_msg.dump());
        });

        websocket_bridge_->SetDisconnectedCallback([this](const std::string& server_url, int reason) {
            (void)reason; // Suppress unused parameter warning
            LOG_WARN("WebSocket bridge disconnected from: " + server_url);
            if (!device_said_goodbye_ && !closing_) {
                // If not a normal close, close MQTT connection
                Close();
            }
        });

        // Connect to WebSocket server (JavaScript version: await this.bridge.connect(...))
        // Select server based on MAC address
        const std::vector<std::string>& server_list = config_.debug ?
            config_.websocket.development_servers :
            config_.websocket.production_servers;

        if (!server_list.empty()) {
            ret = websocket_bridge_->Connect(server_list[0]);
            if (ret != error::SUCCESS) {
                LOG_ERROR("Failed to connect WebSocket bridge: " + error::GetErrorMessage(ret));
                Close();
                return;
            }
        } else {
            LOG_ERROR("No WebSocket servers configured");
            Close();
            return;
        }

        // Set message callback to handle hello reply
        websocket_bridge_->SetMessageCallback([this](const std::string& message) {
            try {
                nlohmann::json json_msg = nlohmann::json::parse(message);
                
                if (json_msg.contains("type") && json_msg["type"] == "hello") {
                    // This is the hello reply from the WebSocket server
                    LOG_INFO("Received hello reply from WebSocket server");
                    
                    // Extract session ID
                    std::string session_id;
                    if (json_msg.contains("session_id")) {
                        session_id = json_msg["session_id"];
                    } else {
                        // Generate a session ID if not provided
                        // Use a simple UUID generation for compatibility
                        std::random_device rd;
                        std::mt19937 gen(rd());
                        std::uniform_int_distribution<uint32_t> dis(0, 0xFFFFFFFF);
                        
                        char uuid_str[37];
                        snprintf(uuid_str, sizeof(uuid_str),
                                "%08x-%04x-%04x-%04x-%04x%08x",
                                dis(gen),
                                dis(gen) & 0xFFFF,
                                ((dis(gen) & 0x0FFF) | 0x4000), // Version 4
                                ((dis(gen) & 0x3FFF) | 0x8000), // Variant 1
                                dis(gen) & 0xFFFF,
                                dis(gen));
                        
                        session_id = uuid_str;
                    }
                    
                    // Create UDP connection info
                    UDPConnectionInfo udp_info;
                    udp_info.remote_address = config_.udp.public_ip;
                    udp_info.remote_port = config_.udp.port;
                    udp_info.cookie = connection_id_;
                    udp_info.local_sequence = 0;
                    udp_info.remote_sequence = 0;
                    
                    // Generate encryption key and nonce
                    udp_info.encryption_key = crypto::AudioCrypto::GenerateKey();
                    
                    // Generate nonce (16 random bytes)
                    std::vector<uint8_t> nonce(16);
                    std::random_device rd;
                    std::mt19937 gen(rd());
                    std::uniform_int_distribution<int> dis(0, 255);
                    
                    for (size_t i = 0; i < nonce.size(); ++i) {
                        nonce[i] = static_cast<uint8_t>(dis(gen));
                    }
                    udp_info.nonce = nonce;
                    udp_info.encryption_method = "aes-128-ctr";
                    udp_info.session_id = session_id;
                    
                    // Store UDP info for this connection
                    udp_info_ = udp_info;
                    
                    // Notify gateway server about the new UDP session
                    if (udp_info_callback_) {
                        udp_info_callback_(connection_id_, udp_info);
                    }
                    
                    // Send UDP info to the client
                    SendUDPInfo(udp_info);
                    
                    LOG_INFO("UDP session created: " + session_id + ", client: " + client_id_);
                } else if (json_msg.contains("type") && json_msg["type"] == "mcp" && 
                           mcp_proxy_ && json_msg.contains("payload") && 
                           json_msg["payload"].contains("method") && 
                           (json_msg["payload"]["method"] == "initialize" || 
                            json_msg["payload"]["method"] == "notifications/initialized" || 
                            json_msg["payload"]["method"] == "tools/list")) {
                    // Handle MCP initialization messages
                    mcp_proxy_->OnMcpMessageFromBridge(json_msg);
                } else {
                    // Forward other messages to MQTT client
                    ForwardFromWebSocket(credentials_.reply_to_topic, message);
                }
            } catch (const std::exception& e) {
                LOG_ERROR("Failed to parse WebSocket message: " + std::string(e.what()));
            }
        });
        
        // Set binary message callback to handle audio data
        websocket_bridge_->SetBinaryMessageCallback([this](const std::vector<uint8_t>& data) {
            if (data.size() < 16) {
                LOG_WARN("Received invalid binary message: too short");
                return;
            }
            
            // Parse binary message (JavaScript version compatible)
            uint32_t timestamp = 0;
            uint32_t opus_length = 0;
            
            if (data.size() >= 16) {
                timestamp = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
                opus_length = (data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15];
                
                if (data.size() >= 16 + opus_length) {
                    // Extract opus data
                    std::vector<uint8_t> opus_data(data.begin() + 16, data.begin() + 16 + opus_length);
                    
                    // Send via UDP
                    SendUdpMessage(opus_data, timestamp);
                }
            }
        });

    } catch (const std::exception& e) {
        LOG_ERROR("Error processing hello message: " + std::string(e.what()));
        Close();
    }
}

void MQTTConnection::ParseOtherMessage(const nlohmann::json& json) {
    // JavaScript version: parseOtherMessage(json)
    LOG_DEBUG("Processing other message type from " + client_id_);

    // Forward to WebSocket (if connected)
    if (websocket_bridge_ && websocket_bridge_->IsConnected()) {
        int ret = websocket_bridge_->SendMessage(json.dump());
        if (ret != error::SUCCESS) {
            LOG_ERROR("Failed to forward message to WebSocket: " + error::GetErrorMessage(ret));
        }
    } else {
        LOG_WARN("WebSocket bridge not connected, cannot forward message");
    }
}

void MQTTConnection::SendUdpMessage(const std::vector<uint8_t>& opus_data, uint32_t timestamp) {
    // JavaScript version: sendUdpMessage(opus, timestamp)
    if (udp_info_.remote_address.empty() || udp_info_.remote_port == 0) {
        LOG_WARN("UDP connection not established, cannot send audio data");
        return;
    }

    // Create UDP packet header (JavaScript version packet header format)
    std::vector<uint8_t> header(16);

    // JavaScript版本: this.headerBuffer.writeUInt8(1, 0); // type
    header[0] = 1;

    // JavaScript版本: this.headerBuffer.writeUInt8(0, 1); // flag
    header[1] = 0;

    // JavaScript版本: this.headerBuffer.writeUInt16BE(opus.length, 2); // payloadLength
    uint16_t payload_length = static_cast<uint16_t>(opus_data.size());
    header[2] = (payload_length >> 8) & 0xFF;
    header[3] = payload_length & 0xFF;

    // JavaScript版本: this.headerBuffer.writeUInt32BE(this.udp.cookie, 4); // cookie
    header[4] = (udp_info_.cookie >> 24) & 0xFF;
    header[5] = (udp_info_.cookie >> 16) & 0xFF;
    header[6] = (udp_info_.cookie >> 8) & 0xFF;
    header[7] = udp_info_.cookie & 0xFF;

    // JavaScript version: this.headerBuffer.writeUInt32BE(timestamp, 8); // timestamp
    header[8] = (timestamp >> 24) & 0xFF;
    header[9] = (timestamp >> 16) & 0xFF;
    header[10] = (timestamp >> 8) & 0xFF;
    header[11] = timestamp & 0xFF;

    // JavaScript version: this.headerBuffer.writeUInt32BE(this.udp.localSequence++, 12); // sequence
    uint32_t sequence = udp_info_.local_sequence++;
    header[12] = (sequence >> 24) & 0xFF;
    header[13] = (sequence >> 16) & 0xFF;
    header[14] = (sequence >> 8) & 0xFF;
    header[15] = sequence & 0xFF;

    // Combine header and audio data (JavaScript version: Buffer.concat([this.headerBuffer, opus]))
    std::vector<uint8_t> packet;
    packet.reserve(header.size() + opus_data.size());
    packet.insert(packet.end(), header.begin(), header.end());
    packet.insert(packet.end(), opus_data.begin(), opus_data.end());

    // Send UDP packet (JavaScript version: this.server.udpServer.send(...))
    if (udp_send_callback_) {
        udp_send_callback_(packet, udp_info_.remote_address, udp_info_.remote_port);
        LOG_DEBUG("Sent UDP audio packet: size=" + std::to_string(packet.size()) +
                  ", seq=" + std::to_string(sequence) +
                  ", timestamp=" + std::to_string(timestamp));
    } else {
        LOG_ERROR("UDP send callback not set");
    }
}

void MQTTConnection::OnMQTTSubscribe(const MQTTSubscribePacket& packet) {
    if (!authenticated_) {
        LOG_WARN("SUBSCRIBE from unauthenticated connection " + std::to_string(connection_id_));
        return;
    }
    
    LOG_DEBUG("MQTT SUBSCRIBE from " + client_id_ + ": topic=" + packet.GetTopic());
    
    // For a gateway, we accept all subscriptions
    // Send SUBACK with success
    SendSuback(packet.GetPacketId(), 0); // QoS 0 granted
}

void MQTTConnection::OnMQTTPingreq() {
    LOG_DEBUG("MQTT PINGREQ from " + client_id_);
    SendPingresp();
}

void MQTTConnection::OnMQTTDisconnect() {
    LOG_INFO("MQTT DISCONNECT from " + client_id_);

    // JavaScript version: this.deviceSaidGoodbye = true
    device_said_goodbye_ = true;
    
    // Calculate final session duration
    auto now = std::chrono::steady_clock::now();
    session_duration_ms_ = std::chrono::duration_cast<std::chrono::milliseconds>(now - session_start_time_);
    LOG_INFO("Session duration for " + client_id_ + ": " + 
             std::to_string(session_duration_ms_.count()) + " ms");

    // Send goodbye message to WebSocket server if we have a bridge
    if (websocket_bridge_ && websocket_bridge_->IsConnected()) {
        try {
            // Create goodbye message
            nlohmann::json goodbye_msg;
            goodbye_msg["type"] = "goodbye";
            goodbye_msg["client_id"] = client_id_;
            goodbye_msg["session_duration_ms"] = session_duration_ms_.count();
            goodbye_msg["reason"] = "client_disconnect";
            
            // Send goodbye message
            websocket_bridge_->SendMessage(goodbye_msg.dump());
            LOG_INFO("Sent goodbye message to WebSocket server for client " + client_id_);
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to send goodbye message: " + std::string(e.what()));
        }
    }

    // Close WebSocket bridge (JavaScript version: if (this.bridge) { this.bridge.close(); })
    if (websocket_bridge_) {
        websocket_bridge_->Disconnect();
        websocket_bridge_.reset();
    }

    Stop();

    if (disconnect_callback_) {
        disconnect_callback_(connection_id_);
    }
}

void MQTTConnection::OnMQTTError(int error_code, const std::string& message) {
    LOG_ERROR("MQTT error for " + client_id_ + ": " + message + 
              " (code: " + std::to_string(error_code) + ")");
    
    // Calculate final session duration
    auto now = std::chrono::steady_clock::now();
    session_duration_ms_ = std::chrono::duration_cast<std::chrono::milliseconds>(now - session_start_time_);
    LOG_INFO("Session duration for " + client_id_ + ": " + 
             std::to_string(session_duration_ms_.count()) + " ms");
    
    // Send goodbye message with error reason
    if (websocket_bridge_ && websocket_bridge_->IsConnected()) {
        try {
            // Create goodbye message
            nlohmann::json goodbye_msg;
            goodbye_msg["type"] = "goodbye";
            goodbye_msg["client_id"] = client_id_;
            goodbye_msg["session_duration_ms"] = session_duration_ms_.count();
            goodbye_msg["reason"] = "mqtt_error";
            goodbye_msg["error_code"] = error_code;
            goodbye_msg["error_message"] = message;
            
            // Send goodbye message
            websocket_bridge_->SendMessage(goodbye_msg.dump());
            LOG_INFO("Sent goodbye message to WebSocket server for client " + client_id_);
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to send goodbye message: " + std::string(e.what()));
        }
    }
    
    Stop();
    
    if (disconnect_callback_) {
        disconnect_callback_(connection_id_);
    }
}

void MQTTConnection::SendConnack(uint8_t return_code) {
    std::vector<uint8_t> buffer;
    int ret = mqtt_protocol_->CreateConnackPacket(return_code, false, buffer);
    if (ret == error::SUCCESS) {
        SendMQTTPacket(buffer);
    }
}

void MQTTConnection::SendSuback(uint16_t packet_id, uint8_t return_code) {
    std::vector<uint8_t> buffer;
    int ret = mqtt_protocol_->CreateSubackPacket(packet_id, return_code, buffer);
    if (ret == error::SUCCESS) {
        SendMQTTPacket(buffer);
    }
}

void MQTTConnection::SendPingresp() {
    std::vector<uint8_t> buffer;
    int ret = mqtt_protocol_->CreatePingrespPacket(buffer);
    if (ret == error::SUCCESS) {
        SendMQTTPacket(buffer);
    }
}

void MQTTConnection::Close() {
    if (closing_) {
        return; // Avoid duplicate closing
    }

    LOG_DEBUG("Closing MQTT connection " + std::to_string(connection_id_));

    // Calculate final session duration if not already done (if not disconnected gracefully)
    if (active_) {
        auto now = std::chrono::steady_clock::now();
        session_duration_ms_ = std::chrono::duration_cast<std::chrono::milliseconds>(now - session_start_time_);
        LOG_INFO("Session duration for " + client_id_ + ": " + 
                 std::to_string(session_duration_ms_.count()) + " ms");
    }

    // JavaScript version: this.closing = true
    closing_ = true;
    active_ = false;

    // Send goodbye message to WebSocket server if we have a bridge and client didn't say goodbye
    if (!device_said_goodbye_ && websocket_bridge_ && websocket_bridge_->IsConnected()) {
        try {
            // Create goodbye message
            nlohmann::json goodbye_msg;
            goodbye_msg["type"] = "goodbye";
            goodbye_msg["client_id"] = client_id_;
            goodbye_msg["session_duration_ms"] = session_duration_ms_.count();
            goodbye_msg["reason"] = "connection_closed";
            
            // Send goodbye message
            websocket_bridge_->SendMessage(goodbye_msg.dump());
            LOG_INFO("Sent goodbye message to WebSocket server for client " + client_id_);
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to send goodbye message: " + std::string(e.what()));
        }
    }

    // Close WebSocket bridge (JavaScript version: if (this.bridge) { this.bridge.close(); })
    if (websocket_bridge_) {
        websocket_bridge_->Disconnect();
        websocket_bridge_.reset();
    }

    if (tcp_handle_) {
        uv_close(reinterpret_cast<uv_handle_t*>(tcp_handle_), OnClose);
        tcp_handle_ = nullptr;
    }
}

void MQTTConnection::OnRead(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    MQTTConnection* connection = static_cast<MQTTConnection*>(stream->data);
    
    if (nread > 0) {
        connection->OnDataReceived(reinterpret_cast<const uint8_t*>(buf->base), nread);
    } else if (nread < 0) {
        if (nread != UV_EOF) {
            LOG_ERROR("Read error on connection " + std::to_string(connection->connection_id_) + 
                      ": " + std::string(uv_strerror((int)nread)));
        }
        connection->Stop();
        
        if (connection->disconnect_callback_) {
            connection->disconnect_callback_(connection->connection_id_);
        }
    }
    
    if (buf->base) {
        delete[] buf->base;
    }
}

void MQTTConnection::OnWrite(uv_write_t* req, int status) {
    // Clean up the buffer and connection data
    struct WriteData {
        MQTTConnection* connection;
        uint8_t* buffer;
    };

    WriteData* write_data = static_cast<WriteData*>(req->data);
    if (write_data) {
        if (write_data->buffer) {
            delete[] write_data->buffer;
        }

        if (status != 0) {
            LOG_ERROR("Write error on connection " + std::to_string(write_data->connection->connection_id_) +
                      ": " + std::string(uv_strerror(status)));
            write_data->connection->Stop();
        }

        delete write_data;
    }
    delete req;
}

void MQTTConnection::OnClose(uv_handle_t* handle) {
    delete reinterpret_cast<uv_tcp_t*>(handle);
}

void MQTTConnection::AllocBuffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    (void)handle;
    buf->base = new char[suggested_size];
    buf->len = (ULONG)suggested_size;
}

} // namespace xiaozhi
