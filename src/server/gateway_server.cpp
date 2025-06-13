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

#include "server/gateway_server.h"
#include "server/mqtt_server.h"
#include "server/udp_server.h"
#include "connection/websocket_bridge.h"
#include "utils/logger.h"
#include "utils/crypto_utils.h"
#include "common/error_codes.h"

#include <uv.h>
#include <libwebsockets.h>
#include <nlohmann/json.hpp>
#include <chrono>
#include <csignal>
#include <mutex>

namespace xiaozhi {

GatewayServer::GatewayServer() 
    : running_(false)
    , stopping_(false)
    , start_time_(0)
    , last_stats_time_(0) {
}

GatewayServer::~GatewayServer() {
    Stop();
    CleanupEventLoop();
}

int GatewayServer::Initialize(const std::string& config_path) {
    LOG_INFO("Initializing gateway server...");
    
    config_path_ = config_path;
    
    // Initialize event loop
    int ret = InitializeEventLoop();
    if (ret != error::SUCCESS) {
        return ret;
    }
    
    // Initialize configuration manager
    config_manager_ = std::make_unique<ConfigManager>();
    ret = config_manager_->LoadConfig(config_path_);
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to load configuration");
        return ret;
    }

    // Set configuration change callback (JavaScript version: configManager.on('configChanged', callback))
    config_manager_->SetConfigChangedCallback([this](const ServerConfig& new_config) {
        OnConfigChanged(new_config);
    });

    // Start configuration file monitoring (JavaScript version: this.watchConfig())
    ret = config_manager_->StartWatching();
    if (ret != error::SUCCESS) {
        LOG_WARN("Failed to start configuration watching: " + error::GetErrorMessage(ret));
        // Not a fatal error, continue startup
    }
    
    config_ = config_manager_->GetConfig();
    
    // Initialize logging with config
    ret = InitializeLogging();
    if (ret != error::SUCCESS) {
        return ret;
    }
    
    // Validate configuration
    ret = ValidateConfig();
    if (ret != error::SUCCESS) {
        return ret;
    }
    
    LOG_INFO("Gateway server initialized successfully");
    return error::SUCCESS;
}

int GatewayServer::Start() {
    if (running_.load()) {
        LOG_WARN("Server is already running");
        return error::ALREADY_EXISTS;
    }
    
    LOG_INFO("Starting gateway server...");
    
    start_time_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // Initialize MQTT server
    int ret = InitializeMQTTServer();
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to initialize MQTT server");
        return ret;
    }
    
    // Initialize UDP server
    ret = InitializeUDPServer();
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to initialize UDP server");
        return ret;
    }

    // Initialize WebSocket bridge
    ret = InitializeWebSocketBridge();
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to initialize WebSocket bridge");
        return ret;
    }
    
    // Start statistics timer
    ret = StartStatsTimer();
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to start statistics timer");
        return ret;
    }
    
    running_.store(true);
    stats_.start_time = start_time_;
    
    LOG_INFO("Gateway server started successfully");
    LOG_INFO("MQTT server listening on " + config_.mqtt.host + ":" + std::to_string(config_.mqtt.port));
    LOG_INFO("UDP server listening on " + config_.udp.host + ":" + std::to_string(config_.udp.port));
    
    return error::SUCCESS;
}

int GatewayServer::Stop() {
    if (!running_.load()) {
        return error::SUCCESS;
    }

    LOG_INFO("Stopping gateway server...");
    stopping_.store(true);

    // Stop configuration file monitoring (JavaScript version: cleanup)
    if (config_manager_) {
        config_manager_->StopWatching();
    }

    // Stop statistics timer
    StopStatsTimer();
    
    // Stop WebSocket bridge
    if (websocket_bridge_) {
        LOG_INFO("Stopping WebSocket bridge...");
        websocket_bridge_->Disconnect();
    }
    
    // Stop MQTT server
    if (mqtt_server_) {
        LOG_INFO("Stopping MQTT server...");
        int ret = mqtt_server_->Stop();
        if (ret != error::SUCCESS) {
            LOG_WARN("Failed to stop MQTT server cleanly: " + error::GetErrorMessage(ret));
        } else {
            LOG_INFO("MQTT server stopped successfully");
        }
    }
    
    // Stop UDP server
    if (udp_server_) {
        LOG_INFO("Stopping UDP server...");
        int ret = udp_server_->Stop();
        if (ret != error::SUCCESS) {
            LOG_WARN("Failed to stop UDP server cleanly: " + error::GetErrorMessage(ret));
        } else {
            LOG_INFO("UDP server stopped successfully");
        }
    }
    
    running_.store(false);
    stopping_.store(false);
    
    LOG_INFO("Gateway server stopped");
    return error::SUCCESS;
}

void GatewayServer::Run() {
    if (!running_.load()) {
        LOG_ERROR("Server is not running");
        return;
    }
    
    LOG_INFO("Running server event loop...");
    
    // Run the event loop
    while (running_.load() && !stopping_.load()) {
        uv_run(event_loop_.get(), UV_RUN_ONCE);

        // Process WebSocket events
        if (websocket_bridge_) {
            websocket_bridge_->ProcessEvents(1); // 1ms timeout
        }
    }
    
    LOG_INFO("Server event loop finished");
}

bool GatewayServer::IsRunning() const {
    return running_.load();
}

ServerStats GatewayServer::GetStats() const {
    return stats_;
}

const ServerConfig& GatewayServer::GetConfig() const {
    return config_;
}

int GatewayServer::ReloadConfig(const std::string& config_path) {
    std::string path = config_path.empty() ? config_path_ : config_path;
    
    LOG_INFO("Reloading configuration from: " + path);
    
    int ret = config_manager_->LoadConfig(path);
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to reload configuration");
        return ret;
    }
    
    config_ = config_manager_->GetConfig();
    
    ret = ValidateConfig();
    if (ret != error::SUCCESS) {
        LOG_ERROR("Configuration validation failed after reload");
        return ret;
    }
    
    LOG_INFO("Configuration reloaded successfully");
    return error::SUCCESS;
}

void GatewayServer::OnConfigChanged(const ServerConfig& new_config) {
    // JavaScript version: configManager.on('configChanged', (config) => { ... })
    LOG_INFO("Configuration changed, applying new settings...");

    // Update internal configuration
    config_ = new_config;

    // Update log level (JavaScript version: setDebugEnabled(config.debug))
    if (new_config.debug) {
        Logger::GetInstance().SetLevel(LogLevel::DEBUG);
        LOG_INFO("Debug logging enabled");
    } else {
        Logger::GetInstance().SetLevel(LogLevel::INFO);
        LOG_INFO("Debug logging disabled");
    }

    // Update MCP configuration
    if (new_config.mcp.enabled) {
        LOG_INFO("MCP enabled with max_tools_count: " + std::to_string(new_config.mcp.max_tools_count));
    } else {
        LOG_INFO("MCP disabled");
    }

    // Update WebSocket server configuration
    LOG_INFO("WebSocket servers updated: " +
             std::to_string(new_config.websocket.development_servers.size()) + " dev, " +
             std::to_string(new_config.websocket.production_servers.size()) + " prod");

    // Note: Port changes require server restart, only log warnings here
    if (config_.mqtt.port != new_config.mqtt.port) {
        LOG_WARN("MQTT port changed from " + std::to_string(config_.mqtt.port) +
                 " to " + std::to_string(new_config.mqtt.port) +
                 " - restart required for this change to take effect");
    }

    if (config_.udp.port != new_config.udp.port) {
        LOG_WARN("UDP port changed from " + std::to_string(config_.udp.port) +
                 " to " + std::to_string(new_config.udp.port) +
                 " - restart required for this change to take effect");
    }

    LOG_INFO("Configuration change applied successfully");
}


uv_loop_t* GatewayServer::GetEventLoop() const {
    return event_loop_.get();
}

int GatewayServer::InitializeEventLoop() {
    event_loop_ = std::make_unique<uv_loop_t>();
    
    int ret = uv_loop_init(event_loop_.get());
    if (ret != 0) {
        LOG_ERROR("Failed to initialize event loop: " + std::string(uv_strerror(ret)));
        return error::INTERNAL_ERROR;
    }
    
    LOG_DEBUG("Event loop initialized");
    return error::SUCCESS;
}

void GatewayServer::CleanupEventLoop() {
    if (event_loop_) {
        uv_loop_close(event_loop_.get());
        event_loop_.reset();
        LOG_DEBUG("Event loop cleaned up");
    }
}

int GatewayServer::InitializeLogging() {
    if (!config_.logging.enabled) {
        return error::SUCCESS;
    }
    
    // Parse log level
    LogLevel level = LogLevel::INFO;
    if (config_.logging.level == "trace") level = LogLevel::TRACE;
    else if (config_.logging.level == "debug") level = LogLevel::DEBUG;
    else if (config_.logging.level == "info") level = LogLevel::INFO;
    else if (config_.logging.level == "warn") level = LogLevel::WARN;
    else if (config_.logging.level == "error") level = LogLevel::ERROR;
    else if (config_.logging.level == "fatal") level = LogLevel::FATAL;
    
    Logger& logger = Logger::GetInstance();
    if (!logger.Initialize(level, config_.logging.file_path)) {
        return error::INTERNAL_ERROR;
    }
    
    LOG_INFO("Logging initialized with level: " + config_.logging.level);
    return error::SUCCESS;
}

int GatewayServer::InitializeMQTTServer() {
    mqtt_server_ = std::make_unique<MQTTServer>(event_loop_.get());

    // Set up callbacks
    mqtt_server_->SetMessageForwardCallback([this](ConnectionId connection_id, const std::string& topic, const std::string& payload) {
        OnMQTTMessageForward(connection_id, topic, payload);
    });

    mqtt_server_->SetClientConnectedCallback([this](ConnectionId connection_id, const std::string& client_id) {
        OnMQTTClientConnected(connection_id, client_id);
    });

    mqtt_server_->SetClientDisconnectedCallback([this](ConnectionId connection_id, const std::string& client_id) {
        OnMQTTClientDisconnected(connection_id, client_id);
    });

    mqtt_server_->SetUDPInfoRequestCallback([this](ConnectionId connection_id) -> UDPConnectionInfo {
        return OnUDPInfoRequest(connection_id);
    });

    int ret = mqtt_server_->Initialize(config_);
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to initialize MQTT server: " + error::GetErrorMessage(ret));
        return ret;
    }

    ret = mqtt_server_->Start();
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to start MQTT server: " + error::GetErrorMessage(ret));
        return ret;
    }

    LOG_INFO("MQTT server initialized and started");
    return error::SUCCESS;
}

int GatewayServer::InitializeUDPServer() {
    udp_server_ = std::make_unique<UDPServer>(event_loop_.get());

    // Set up callbacks
    udp_server_->SetAudioDataCallback([this](const std::string& session_id, const std::vector<uint8_t>& audio_data) {
        OnUDPAudioData(session_id, audio_data);
    });

    udp_server_->SetSessionCreatedCallback([this](const std::string& session_id, const UDPConnectionInfo& info) {
        OnUDPSessionCreated(session_id, info);
    });

    udp_server_->SetSessionClosedCallback([this](const std::string& session_id) {
        OnUDPSessionClosed(session_id);
    });

    udp_server_->SetErrorCallback([this](const std::string& error_message) {
        LOG_ERROR("UDP server error: " + error_message);
    });

    int ret = udp_server_->Initialize(config_);
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to initialize UDP server: " + error::GetErrorMessage(ret));
        return ret;
    }

    ret = udp_server_->Start();
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to start UDP server: " + error::GetErrorMessage(ret));
        return ret;
    }

    LOG_INFO("UDP server initialized and started");
    return error::SUCCESS;
}

int GatewayServer::InitializeWebSocketBridge() {
    websocket_bridge_ = std::make_unique<WebSocketBridge>();

    // Set up callbacks
    websocket_bridge_->SetMessageCallback([this](const std::string& message) {
        OnWebSocketMessageReceived(message);
    });

    // Set binary message callback (JavaScript version: isBinary handling)
    websocket_bridge_->SetBinaryMessageCallback([this](const std::vector<uint8_t>& data) {
        OnWebSocketBinaryMessageReceived(data);
    });

    websocket_bridge_->SetConnectedCallback([this](const std::string& server_url) {
        OnWebSocketConnected(server_url);
    });

    websocket_bridge_->SetDisconnectedCallback([this](const std::string& server_url, int reason) {
        OnWebSocketDisconnected(server_url, reason);
    });

    websocket_bridge_->SetErrorCallback([this](const std::string& error_message) {
        LOG_ERROR("WebSocket error: " + error_message);
    });

    int ret = websocket_bridge_->Initialize(config_, event_loop_.get());
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to initialize WebSocket bridge: " + error::GetErrorMessage(ret));
        return ret;
    }

    // Configure reconnection policy
    websocket_bridge_->SetReconnectionPolicy(
        true,  // Enable reconnection
        0,     // Infinite attempts
        constants::WEBSOCKET_RECONNECT_DELAY_MS,  // Initial delay: 5 seconds
        60000, // Max delay: 60 seconds
        2.0    // Exponential backoff multiplier
    );

    // Connect to WebSocket server
    std::string server_url;
    if (config_.debug) {
        // Use development server
        if (!config_.websocket.development_servers.empty()) {
            server_url = config_.websocket.development_servers[0];
        }
    } else {
        // Use production server
        if (!config_.websocket.production_servers.empty()) {
            server_url = config_.websocket.production_servers[0];
        }
    }

    if (!server_url.empty()) {
        ret = websocket_bridge_->Connect(server_url);
        if (ret != error::SUCCESS) {
            LOG_WARN("Failed to connect to WebSocket server: " + server_url +
                     " - automatic reconnection will be attempted");
            // Don't fail initialization, reconnection will handle this
        }
    } else {
        LOG_WARN("No WebSocket server configured");
    }

    LOG_INFO("WebSocket bridge initialized with automatic reconnection");
    return error::SUCCESS;
}

int GatewayServer::StartStatsTimer() {
    stats_timer_ = std::make_unique<uv_timer_t>();
    stats_timer_->data = this;
    
    int ret = uv_timer_init(event_loop_.get(), stats_timer_.get());
    if (ret != 0) {
        LOG_ERROR("Failed to initialize stats timer: " + std::string(uv_strerror(ret)));
        return error::INTERNAL_ERROR;
    }
    
    // Start timer with 30 second interval
    ret = uv_timer_start(stats_timer_.get(), OnStatsTimer, 30000, 30000);
    if (ret != 0) {
        LOG_ERROR("Failed to start stats timer: " + std::string(uv_strerror(ret)));
        return error::INTERNAL_ERROR;
    }
    
    LOG_DEBUG("Statistics timer started");
    return error::SUCCESS;
}

void GatewayServer::StopStatsTimer() {
    if (stats_timer_) {
        uv_timer_stop(stats_timer_.get());
        uv_close(reinterpret_cast<uv_handle_t*>(stats_timer_.get()), nullptr);
        stats_timer_.reset();
        LOG_DEBUG("Statistics timer stopped");
    }
}

void GatewayServer::OnStatsTimer(uv_timer_t* timer) {
    GatewayServer* server = static_cast<GatewayServer*>(timer->data);
    if (server) {
        server->PrintStats();
    }
}


void GatewayServer::PrintStats() {
    int64_t current_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    int64_t uptime = current_time - start_time_;
    int64_t uptime_seconds = uptime / 1000;
    
    LOG_INFO("=== Server Statistics ===");
    LOG_INFO("Uptime: " + std::to_string(uptime_seconds) + " seconds");
    LOG_INFO("Active connections: " + std::to_string(stats_.active_connections));
    LOG_INFO("Total connections: " + std::to_string(stats_.total_connections));
    LOG_INFO("MQTT messages: RX=" + std::to_string(stats_.mqtt_messages_received) + 
             " TX=" + std::to_string(stats_.mqtt_messages_sent));
    LOG_INFO("UDP packets: RX=" + std::to_string(stats_.udp_packets_received) + 
             " TX=" + std::to_string(stats_.udp_packets_sent));
    LOG_INFO("WebSocket messages: RX=" + std::to_string(stats_.websocket_messages_received) + 
             " TX=" + std::to_string(stats_.websocket_messages_sent));
    LOG_INFO("Bytes: RX=" + std::to_string(stats_.bytes_received) + 
             " TX=" + std::to_string(stats_.bytes_sent));
    
    last_stats_time_ = current_time;
}

int GatewayServer::ValidateConfig() {
    return config_manager_->ValidateConfig();
}

void GatewayServer::OnMQTTMessageForward(ConnectionId connection_id, const std::string& topic, const std::string& payload) {
    LOG_DEBUG("Forwarding MQTT message from connection " + std::to_string(connection_id) +
              ": topic=" + topic + ", size=" + std::to_string(payload.length()));

    // Forward to WebSocket server
    if (websocket_bridge_ && websocket_bridge_->IsConnected()) {
        std::string client_id = "client_" + std::to_string(connection_id);
        int ret = websocket_bridge_->SendMQTTMessage(topic, payload, client_id);
        if (ret == error::SUCCESS) {
            LOG_DEBUG("Message forwarded to WebSocket server");
            stats_.websocket_messages_sent++;
            stats_.bytes_sent += payload.length();
        } else {
            LOG_ERROR("Failed to forward message to WebSocket server: " + error::GetErrorMessage(ret));
        }
    } else {
        LOG_WARN("WebSocket not connected, cannot forward message");
    }

    // Update statistics
    stats_.mqtt_messages_received++;
    stats_.bytes_received += payload.length();
}

void GatewayServer::OnMQTTClientConnected(ConnectionId connection_id, const std::string& client_id) {
    LOG_INFO("MQTT client connected: " + client_id + " (connection " + std::to_string(connection_id) + ")");

    // Update statistics
    stats_.total_connections++;
    stats_.active_connections++;
}

void GatewayServer::OnMQTTClientDisconnected(ConnectionId connection_id, const std::string& client_id) {
    LOG_INFO("MQTT client disconnected: " + client_id + " (connection " + std::to_string(connection_id) + ")");

    // Update statistics
    stats_.active_connections--;
}

UDPConnectionInfo GatewayServer::OnUDPInfoRequest(ConnectionId connection_id) {
    LOG_DEBUG("UDP info request from connection " + std::to_string(connection_id));

    // Create UDP session for this MQTT connection
    if (udp_server_) {
        return udp_server_->CreateSession(connection_id);
    }

    // Fallback if UDP server not available
    UDPConnectionInfo info;
    info.remote_address = config_.udp.public_ip;
    info.remote_port = config_.udp.port;
    info.session_id = "session_" + std::to_string(connection_id);
    info.start_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    return info;
}

void GatewayServer::OnWebSocketMessageReceived(const std::string& message) {
    LOG_DEBUG("WebSocket message received: " + message.substr(0, 100) +
              (message.length() > 100 ? "..." : ""));

    // Update statistics
    stats_.websocket_messages_received++;
    stats_.bytes_received += message.length();

    // Parse JSON message and process based on message type
    try {
        nlohmann::json json_msg = nlohmann::json::parse(message);

        if (json_msg.contains("type")) {
            std::string msg_type = json_msg["type"];
            
            // Handle server hello reply which may contain session ID
            if (msg_type == "hello" || msg_type == "server_hello") {
                // If the server provides a session ID, use it
                if (json_msg.contains("session_id")) {
                    std::string server_session_id = json_msg["session_id"];
                    if (!server_session_id.empty()) {
                        LOG_INFO("Received session ID from server: " + server_session_id);
                        std::lock_guard<std::mutex> lock(websocket_session_mutex_);
                        active_websocket_session_id_ = server_session_id;
                    }
                }
                
                // Process other hello message fields if needed
                LOG_INFO("Received hello from WebSocket server");
            }
            // Handle MQTT message forwarding
            else if (msg_type == "mqtt_forward") {
                std::string topic = json_msg.value("topic", "");
                std::string payload = json_msg.value("payload", "");

                if (!topic.empty()) {
                    // Broadcast to all MQTT clients
                    if (mqtt_server_) {
                        mqtt_server_->BroadcastToClients(topic, payload);
                        LOG_DEBUG("Forwarded WebSocket message to MQTT clients: " + topic);
                    }
                }
            }
            // Handle session management messages
            else if (msg_type == "session_update" && json_msg.contains("session_id")) {
                std::string session_id = json_msg["session_id"];
                LOG_INFO("Session update received: " + session_id);
                std::lock_guard<std::mutex> lock(websocket_session_mutex_);
                active_websocket_session_id_ = session_id;
            }
        }
    } catch (const std::exception& e) {
        LOG_WARN("Failed to parse WebSocket message as JSON: " + std::string(e.what()));
    }
}

void GatewayServer::OnWebSocketBinaryMessageReceived(const std::vector<uint8_t>& data) {
    LOG_DEBUG("WebSocket binary message received: " + std::to_string(data.size()) + " bytes");

    // JavaScript version binary message handling:
    // if (isBinary) {
    //     const timestamp = data.readUInt32BE(8);
    //     const opusLength = data.readUInt32BE(12);
    //     const opus = data.subarray(16, 16 + opusLength);
    //     // Binary data sent via UDP
    //     this.connection.sendUdpMessage(opus, timestamp);
    // }

    // Parse WebSocket audio packet format
    std::vector<uint8_t> opus_data;
    uint32_t timestamp;

    int ret = crypto::UDPHeaderGenerator::ParseWebSocketAudioPacket(data, opus_data, timestamp);
    if (ret != error::SUCCESS) {
        LOG_WARN("Failed to parse WebSocket audio packet: " + error::GetErrorMessage(ret));
        return;
    }

    LOG_DEBUG("Parsed audio packet: timestamp=" + std::to_string(timestamp) +
              ", opus_size=" + std::to_string(opus_data.size()));

    // Send audio data via UDP (JavaScript version: this.connection.sendUdpMessage(opus, timestamp))
    if (udp_server_) {
        // Use the active WebSocket session ID with mutex protection
        std::string session_id;
        {
            std::lock_guard<std::mutex> lock(websocket_session_mutex_);
            session_id = active_websocket_session_id_;
        }
        
        if (session_id.empty()) {
            LOG_WARN("No active WebSocket session ID available, cannot forward audio data");
            return;
        }

        ret = udp_server_->SendAudioData(session_id, opus_data);
        if (ret == error::SUCCESS) {
            LOG_DEBUG("Audio data forwarded to UDP: session=" + session_id);
            stats_.udp_packets_sent++;
            stats_.bytes_sent += opus_data.size();
        } else {
            LOG_ERROR("Failed to forward audio data to UDP: " + error::GetErrorMessage(ret));
        }
    } else {
        LOG_WARN("UDP server not available, cannot forward audio data");
    }

    // Update statistics
    stats_.websocket_messages_received++;
    stats_.bytes_received += data.size();
}

void GatewayServer::OnWebSocketConnected(const std::string& server_url) {
    LOG_INFO("WebSocket connected to: " + server_url);

    // Generate a new session ID for this connection
    std::string new_session_id = "ws_" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    
    {
        std::lock_guard<std::mutex> lock(websocket_session_mutex_);
        active_websocket_session_id_ = new_session_id;
    }
    
    LOG_INFO("Created new WebSocket session ID: " + new_session_id);

    // Send initial hello message
    if (websocket_bridge_) {
        nlohmann::json hello_json;
        hello_json["type"] = "gateway_hello";
        hello_json["gateway_id"] = "mqtt-websocket-proxy";
        hello_json["version"] = "1.0.0";
        hello_json["session_id"] = active_websocket_session_id_;
        
        websocket_bridge_->SendMessage(hello_json.dump());
    }
}

void GatewayServer::OnWebSocketDisconnected(const std::string& server_url, int reason) {
    LOG_WARN("WebSocket disconnected from: " + server_url + " (reason: " + std::to_string(reason) + ")");

    // Log the session ID that is being closed and clear it with mutex protection
    std::string session_id;
    {
        std::lock_guard<std::mutex> lock(websocket_session_mutex_);
        session_id = active_websocket_session_id_;
        if (!session_id.empty()) {
            LOG_INFO("Closing WebSocket session: " + session_id);
            active_websocket_session_id_.clear();
        }
    }

    if (reason == LWS_CLOSE_STATUS_NORMAL) {
        LOG_INFO("WebSocket disconnected normally (manual disconnect)");
    } else {
        LOG_WARN("WebSocket disconnected unexpectedly - automatic reconnection will be attempted");

        // Update statistics
        stats_.websocket_disconnections++;
    }
}

void GatewayServer::OnUDPAudioData(const std::string& session_id, const std::vector<uint8_t>& audio_data) {
    LOG_DEBUG("UDP audio data received: session=" + session_id + ", size=" + std::to_string(audio_data.size()));

    // Forward audio data to WebSocket server
    if (websocket_bridge_ && websocket_bridge_->IsConnected()) {
        // Create JSON message for audio data
        nlohmann::json audio_msg;
        audio_msg["type"] = "audio_data";
        audio_msg["session_id"] = session_id;
        audio_msg["data"] = audio_data; // Base64 encoding would be better for production
        audio_msg["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        std::string json_str = audio_msg.dump();
        int ret = websocket_bridge_->SendMessage(json_str);
        if (ret == error::SUCCESS) {
            LOG_DEBUG("Audio data forwarded to WebSocket server");
            stats_.udp_packets_received++;
            stats_.bytes_received += audio_data.size();
        } else {
            LOG_ERROR("Failed to forward audio data to WebSocket server");
        }
    } else {
        LOG_WARN("WebSocket not connected, cannot forward audio data");
    }
}

void GatewayServer::OnUDPSessionCreated(const std::string& session_id, const UDPConnectionInfo& info) {
    LOG_INFO("UDP session created: " + session_id);

    // Notify WebSocket server about new session
    if (websocket_bridge_ && websocket_bridge_->IsConnected()) {
        nlohmann::json session_msg;
        session_msg["type"] = "udp_session_created";
        session_msg["session_id"] = session_id;
        session_msg["remote_address"] = info.remote_address;
        session_msg["remote_port"] = info.remote_port;
        session_msg["start_time"] = info.start_time;

        websocket_bridge_->SendMessage(session_msg.dump());
    }
}

void GatewayServer::OnUDPSessionClosed(const std::string& session_id) {
    LOG_INFO("UDP session closed: " + session_id);

    // Notify WebSocket server about closed session
    if (websocket_bridge_ && websocket_bridge_->IsConnected()) {
        nlohmann::json session_msg;
        session_msg["type"] = "udp_session_closed";
        session_msg["session_id"] = session_id;
        session_msg["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        websocket_bridge_->SendMessage(session_msg.dump());
    }
}

} // namespace xiaozhi
