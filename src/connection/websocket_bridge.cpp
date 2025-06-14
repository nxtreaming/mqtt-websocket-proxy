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

#include "connection/websocket_bridge.h"
#include "utils/logger.h"
#include "common/error_codes.h"
#include "common/constants.h"
#include <nlohmann/json.hpp>

#include <libwebsockets.h>
#include <regex>
#include <chrono>
#include <sstream>

namespace xiaozhi {

// WebSocket protocol definition
static const struct lws_protocols protocols[] = {
    {
        "xiaozhi-mqtt-gateway",     // name
        WebSocketBridge::WebSocketCallback,  // callback
        0,                          // per_session_data_size
        constants::WEBSOCKET_MAX_MESSAGE_SIZE  // rx_buffer_size
    },
    { NULL, NULL, 0, 0 } // terminator
};

WebSocketBridge::WebSocketBridge()
    : connected_(false)
    , context_(nullptr)
    , websocket_(nullptr)
    , protocol_version_(3)
    , device_said_goodbye_(false)
    , reconnection_enabled_(false)
    , max_reconnection_attempts_(0)
    , initial_reconnection_delay_(1000)
    , max_reconnection_delay_(30000)
    , backoff_multiplier_(2.0)
    , reconnection_attempts_(0)
    , current_reconnection_delay_(1000)
    , reconnecting_(false)
    , current_server_index_(0)
    , event_loop_(nullptr) {
    // Initialize preallocated send buffer with a default capacity.
    // LWS_PRE is padding required by libwebsockets.
    // Assuming constants::WEBSOCKET_MAX_MESSAGE_SIZE is defined appropriately.
    preallocated_send_buffer_.reserve(LWS_PRE + constants::WEBSOCKET_MAX_MESSAGE_SIZE);
}

WebSocketBridge::~WebSocketBridge() {
    StopReconnectionTimer();
    Disconnect();
}

int WebSocketBridge::Initialize(const ServerConfig& config, uv_loop_t* loop) {
    config_ = config;
    event_loop_ = loop;

    // Initialize libwebsockets context
    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));

    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.gid = 0;
    info.uid = 0;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.user = this;

    context_ = lws_create_context(&info);
    if (!context_) {
        LOG_ERROR("Failed to create WebSocket context");
        return error::WEBSOCKET_ERROR;
    }

    // Set default server list from config
    std::vector<std::string> servers;
    if (config_.debug) {
        servers = config_.websocket.development_servers;
    } else {
        servers = config_.websocket.production_servers;
    }
    SetServerList(servers);

    // Enable reconnection by default
    SetReconnectionPolicy(true, 0, 1000, 30000, 2.0);

    LOG_INFO("WebSocket bridge initialized with reconnection support");
    return error::SUCCESS;
}

int WebSocketBridge::UpdateConfig(const ServerConfig& config) {
    LOG_INFO("Updating WebSocket bridge configuration");
    
    bool servers_changed = false;
    
    // Check if development servers changed
    if (config_.websocket.development_servers != config.websocket.development_servers) {
        LOG_INFO("Development WebSocket servers updated");
        config_.websocket.development_servers = config.websocket.development_servers;
        servers_changed = true;
    }
    
    // Check if production servers changed
    if (config_.websocket.production_servers != config.websocket.production_servers) {
        LOG_INFO("Production WebSocket servers updated");
        config_.websocket.production_servers = config.websocket.production_servers;
        servers_changed = true;
    }
    
    // Check if development MAC addresses changed
    if (config_.websocket.development_mac_addresses != config.websocket.development_mac_addresses) {
        LOG_INFO("Development MAC addresses updated");
        config_.websocket.development_mac_addresses = config.websocket.development_mac_addresses;
    }
    
    // Update debug level
    if (config_.debug != config.debug) {
        config_.debug = config.debug;
        // Update logging level if needed
    }
    
    // If server lists changed and we're connected, consider reconnecting
    // to potentially use a different server from the updated list
    if (servers_changed && IsConnected() && reconnection_enabled_) {
        LOG_INFO("WebSocket server list changed, scheduling reconnection");
        StartReconnectionTimer();
    }
    
    return error::SUCCESS;
}

int WebSocketBridge::InitializeWithDeviceInfo(const ServerConfig& config, uv_loop_t* loop,
                                             const std::string& mac_address, const std::string& client_uuid,
                                             int protocol_version, const std::string& user_data) {
    // Call basic initialization first
    int ret = Initialize(config, loop);
    if (ret != error::SUCCESS) {
        return ret;
    }

    // Save device information (JavaScript version: constructor(connection, protocolVersion, macAddress, uuid, userData))
    mac_address_ = mac_address;
    client_uuid_ = client_uuid;
    protocol_version_ = protocol_version;
    user_data_ = user_data;
    device_said_goodbye_ = false;

    // JavaScript version: initializeChatServer()
    std::vector<std::string> chat_servers;

    // JavaScript version: const devMacAddresss = configManager.get('development')?.mac_addresss || [];
    const auto& dev_mac_addresses = config_.websocket.development_mac_addresses;

    // JavaScript version: if (devMacAddresss.includes(this.macAddress))
    bool is_development = false;
    for (const auto& dev_mac : dev_mac_addresses) {
        if (dev_mac == mac_address_) {
            is_development = true;
            break;
        }
    }

    // Select server list (JavaScript version: chatServers = configManager.get('development/production')?.chat_servers)
    if (is_development) {
        chat_servers = config_.websocket.development_servers;
        LOG_INFO("Using development servers for MAC: " + mac_address_);
    } else {
        chat_servers = config_.websocket.production_servers;
        LOG_INFO("Using production servers for MAC: " + mac_address_);
    }

    if (chat_servers.empty()) {
        LOG_ERROR("No chat servers found for MAC address: " + mac_address_);
        return error::CONFIG_MISSING_REQUIRED;
    }

    // Set server list
    SetServerList(chat_servers);

    LOG_INFO("WebSocket bridge initialized with device info: MAC=" + mac_address_ +
             ", protocol=" + std::to_string(protocol_version_) +
             ", servers=" + std::to_string(chat_servers.size()));

    return error::SUCCESS;
}

int WebSocketBridge::Connect(const std::string& server_url) {
    if (connected_.load()) {
        LOG_WARN("WebSocket already connected, disconnecting first");
        Disconnect();
    }
    
    current_server_ = server_url;
    
    // Parse URL
    std::string host, path;
    int port;
    bool use_ssl;
    
    int ret = ParseWebSocketURL(server_url, host, port, path, use_ssl);
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to parse WebSocket URL: " + server_url);
        return ret;
    }
    
    // Create connection info
    struct lws_client_connect_info ccinfo;
    memset(&ccinfo, 0, sizeof(ccinfo));
    
    ccinfo.context = context_;
    ccinfo.address = host.c_str();
    ccinfo.port = port;
    ccinfo.path = path.c_str();
    ccinfo.host = host.c_str();
    ccinfo.origin = host.c_str();
    ccinfo.protocol = protocols[0].name;
    ccinfo.userdata = this;
    
    // Add required custom headers for compatibility with JavaScript version
    // Format: "header-name: header-value\r\n"
    // JS sends:
    // 'device-id': this.macAddress,
    // 'protocol-version': '2',
    // 'authorization': `Bearer test-token`
    // 'client-id': this.uuid (if exists)
    // 'x-forwarded-for': this.userData.ip (if exists)
    std::string new_headers_str; // Using a different local variable name to avoid potential conflict

    // device-id (Assuming mac_address_ is a member variable like std::string mac_address_)
    // Ensure mac_address_ is accessible here (e.g., a member of WebSocketBridge)
    if (!mac_address_.empty()) { 
        new_headers_str += "device-id: " + mac_address_ + "\r\n";
    } else {
        LOG_WARN("MAC address (for device-id header) is empty. Header not sent.");
    }

    // protocol-version
    new_headers_str += "protocol-version: 2\r\n"; // String "2" is correct

    // authorization
    new_headers_str += "authorization: Bearer test-token\r\n"; // Matching JS static token

    // client-id (optional, assuming client_uuid_ is a member like std::string client_uuid_)
    if (!client_uuid_.empty()) {
        new_headers_str += "client-id: " + client_uuid_ + "\r\n";
    }

    // x-forwarded-for (optional, from parsed user_data_)
    std::string client_ip_from_user_data;

    if (!user_data_.empty()) {
        try {
            auto user_data_json = nlohmann::json::parse(user_data_);
            if (user_data_json.contains("ip") && user_data_json["ip"].is_string()) {
                client_ip_from_user_data = user_data_json["ip"].get<std::string>();
            }
        } catch (const nlohmann::json::parse_error& e) {
            LOG_WARN("Failed to parse user_data as JSON: " + std::string(e.what()) + ". user_data: " + user_data_);
        }
    }

    if (!client_ip_from_user_data.empty()) { 
        new_headers_str += "x-forwarded-for: " + client_ip_from_user_data + "\r\n";
    }
    
    // Set headers in connection info
    if (!new_headers_str.empty()) {
        LOG_DEBUG("Adding WebSocket headers: " + new_headers_str);
        custom_headers_ = new_headers_str; // custom_headers_ is the member that lws uses
    }
    
    if (use_ssl) {
        ccinfo.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
    }
    
    // Connect
    websocket_ = lws_client_connect_via_info(&ccinfo);
    if (!websocket_) {
        LOG_ERROR("Failed to initiate WebSocket connection to: " + server_url);
        return error::WEBSOCKET_CONNECTION_FAILED;
    }
    
    LOG_INFO("Connecting to WebSocket server: " + server_url);
    return error::SUCCESS;
}

int WebSocketBridge::Disconnect() {
    // Stop reconnection timer
    StopReconnectionTimer();

    if (websocket_) {
        lws_close_reason(websocket_, LWS_CLOSE_STATUS_NORMAL, nullptr, 0);
        websocket_ = nullptr;
    }

    connected_.store(false);
    reconnecting_.store(false);
    current_server_.clear();

    // Clear send queue
    std::lock_guard<std::mutex> lock(send_queue_mutex_);
    while (!send_queue_.empty()) {
        send_queue_.pop();
    }

    if (context_) {
        lws_context_destroy(context_);
        context_ = nullptr;
    }

    LOG_INFO("WebSocket disconnected");
    return error::SUCCESS;
}

int WebSocketBridge::SendMessage(const std::string& message) {
    if (!connected_.load()) {
        LOG_WARN("Cannot send message - WebSocket not connected");
        return error::CONNECTION_CLOSED;
    }
    
    // Add to send queue
    {
        std::lock_guard<std::mutex> lock(send_queue_mutex_);
        send_queue_.push(message);
    }
    
    // Request callback to send
    lws_callback_on_writable(websocket_);
    
    return error::SUCCESS;
}

int WebSocketBridge::SendMQTTMessage(const std::string& topic, const std::string& payload, const std::string& client_id) {
    std::string json_message = CreateMQTTJSON(topic, payload, client_id);
    return SendMessage(json_message);
}

int WebSocketBridge::ProcessEvents(int timeout_ms) {
    if (!context_) {
        return error::WEBSOCKET_ERROR;
    }
    
    int ret = lws_service(context_, timeout_ms);
    if (ret < 0) {
        LOG_ERROR("WebSocket service error: " + std::to_string(ret));
        return error::WEBSOCKET_ERROR;
    }
    
    return error::SUCCESS;
}

bool WebSocketBridge::IsConnected() const {
    return connected_.load();
}

const std::string& WebSocketBridge::GetCurrentServer() const {
    return current_server_;
}

WebSocketConnectionInfo WebSocketBridge::GetConnectionInfo() const {
    return connection_info_;
}

void WebSocketBridge::OnConnected() {
    connected_.store(true);
    connection_info_.is_connected = true;
    connection_info_.server_url = current_server_;

    // Reset reconnection state on successful connection
    ResetReconnectionState();
    StopReconnectionTimer();

    LOG_INFO("WebSocket connected to: " + current_server_);

    if (connected_callback_) {
        connected_callback_(current_server_);
    }
}

void WebSocketBridge::OnMessageReceived(const std::string& message) {
    LOG_DEBUG("WebSocket text message received: " + message.substr(0, 100) +
              (message.length() > 100 ? "..." : ""));

    if (message_callback_) {
        message_callback_(message);
    }
}

void WebSocketBridge::OnBinaryMessageReceived(const std::vector<uint8_t>& data) {
    LOG_DEBUG("WebSocket binary message received: " + std::to_string(data.size()) + " bytes");

    // JavaScript version binary message handling:
    // if (isBinary) {
    //     const timestamp = data.readUInt32BE(8);
    //     const opusLength = data.readUInt32BE(12);
    //     const opus = data.subarray(16, 16 + opusLength);
    //     // Binary data sent via UDP
    //     this.connection.sendUdpMessage(opus, timestamp);
    // }

    if (data.size() < 16) {
        LOG_WARN("Binary message too short for audio packet format: " + std::to_string(data.size()) + " bytes");
        return;
    }

    // Parse JavaScript format audio packet
    // Timestamp at offset 8 (big-endian)
    uint32_t timestamp = (static_cast<uint32_t>(data[8]) << 24) |
                        (static_cast<uint32_t>(data[9]) << 16) |
                        (static_cast<uint32_t>(data[10]) << 8) |
                        static_cast<uint32_t>(data[11]);

    // Opus length at offset 12 (big-endian)
    uint32_t opus_length = (static_cast<uint32_t>(data[12]) << 24) |
                          (static_cast<uint32_t>(data[13]) << 16) |
                          (static_cast<uint32_t>(data[14]) << 8) |
                          static_cast<uint32_t>(data[15]);

    // Check data length
    if (data.size() < 16 + opus_length) {
        LOG_WARN("Binary message too short for declared Opus length: " +
                 std::to_string(data.size()) + " < " + std::to_string(16 + opus_length));
        return;
    }

    // Extract Opus audio data (starting from offset 16)
    std::vector<uint8_t> opus_data(data.begin() + 16, data.begin() + 16 + opus_length);

    LOG_DEBUG("Extracted audio data: timestamp=" + std::to_string(timestamp) +
              ", opus_length=" + std::to_string(opus_length));

    if (binary_message_callback_) {
        // Pass audio data to callback for handling (send via UDP)
        binary_message_callback_(opus_data);
    }
}

void WebSocketBridge::OnDisconnected(int reason) {
    bool was_connected = connected_.exchange(false);
    connection_info_.is_connected = false;

    if (was_connected) {
        LOG_INFO("WebSocket disconnected from: " + current_server_ +
                 " (reason: " + std::to_string(reason) + ")");

        if (disconnected_callback_) {
            disconnected_callback_(current_server_, reason);
        }

        // Trigger reconnection if enabled and not manually disconnected
        if (reconnection_enabled_ && reason != LWS_CLOSE_STATUS_NORMAL && !reconnecting_.exchange(true)) {
            LOG_INFO("Starting automatic reconnection...");
            StartReconnectionTimer();
        }
    }
}

void WebSocketBridge::OnError(const std::string& error_message) {
    LOG_ERROR("WebSocket error: " + error_message);
    
    if (error_callback_) {
        error_callback_(error_message);
    }
}

int WebSocketBridge::ParseWebSocketURL(const std::string& url, std::string& host, int& port, std::string& path, bool& use_ssl) {
    // Parse WebSocket URL: ws://host:port/path or wss://host:port/path
    std::regex url_regex(R"(^(wss?)://([^:/]+)(?::(\d+))?(/.*)?$)");
    std::smatch matches;
    
    if (!std::regex_match(url, matches, url_regex)) {
        return error::INVALID_PARAMETER;
    }
    
    std::string scheme = matches[1].str();
    host = matches[2].str();
    std::string port_str = matches[3].str();
    path = matches[4].str();
    
    use_ssl = (scheme == "wss");
    
    if (port_str.empty()) {
        port = use_ssl ? 443 : 80;
    } else {
        port = std::stoi(port_str);
    }
    
    if (path.empty()) {
        path = "/";
    }
    
    return error::SUCCESS;
}

std::string WebSocketBridge::CreateMQTTJSON(const std::string& topic, const std::string& payload, const std::string& client_id) {
    nlohmann::json json_msg;
    
    json_msg["type"] = "mqtt_message";
    json_msg["topic"] = topic;
    json_msg["payload"] = payload;
    json_msg["client_id"] = client_id;
    json_msg["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    json_msg["qos"] = 0;
    
    return json_msg.dump();
}

void WebSocketBridge::ProcessSendQueue() {
    std::lock_guard<std::mutex> lock(send_queue_mutex_);
    
    if (send_queue_.empty()) {
        return;
    }
    
    std::string message = send_queue_.front();
    send_queue_.pop();
    
    // Prepare message for sending using preallocated buffer
    size_t message_len = message.length();
    size_t required_size = LWS_PRE + message_len;

    // Ensure buffer has enough capacity. 
    // resize will reallocate if capacity is insufficient and current size is smaller.
    // Explicitly reserve if a larger capacity is needed beyond the current message to avoid frequent reallocations.
    if (preallocated_send_buffer_.capacity() < required_size) {
        preallocated_send_buffer_.reserve(required_size); 
    }
    preallocated_send_buffer_.resize(required_size); // Set the current size of the buffer for lws_write
    
    memcpy(preallocated_send_buffer_.data() + LWS_PRE, message.c_str(), message_len);
    
    int ret = lws_write(websocket_, preallocated_send_buffer_.data() + LWS_PRE, message_len, LWS_WRITE_TEXT);
    if (ret < 0) {
        LOG_ERROR("Failed to send WebSocket message");
        OnError("Failed to send message");
    } else {
        LOG_DEBUG("WebSocket message sent: " + std::to_string(message_len) + " bytes");
    }
    
    // If there are more messages, request another callback
    if (!send_queue_.empty()) {
        lws_callback_on_writable(websocket_);
    }
}

int WebSocketBridge::WebSocketCallback(struct lws* wsi, enum lws_callback_reasons reason, void* user, void* in, size_t len) {
    (void)user;
    WebSocketBridge* bridge = static_cast<WebSocketBridge*>(lws_context_user(lws_get_context(wsi)));
    if (!bridge) {
        return 0;
    }
    
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            bridge->OnConnected();
            break;
            
        case LWS_CALLBACK_CLIENT_RECEIVE:
            if (in && len > 0) {
                // Check if it's binary data (JavaScript version: isBinary)
                if (lws_frame_is_binary(wsi)) {
                    // Handle binary message (audio data)
                    std::vector<uint8_t> binary_data(static_cast<const uint8_t*>(in),
                                                   static_cast<const uint8_t*>(in) + len);
                    bridge->OnBinaryMessageReceived(binary_data);
                } else {
                    // Handle text message (JSON data)
                    std::string message(static_cast<const char*>(in), len);
                    bridge->OnMessageReceived(message);
                }
            }
            break;
            
        case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
            // This callback allows us to add custom headers to the client handshake
            if (!bridge->custom_headers_.empty()) {
                unsigned char **p = (unsigned char **)in;
                unsigned char *end = (*p) + len;
                
                // Parse the custom headers string and add each header
                std::istringstream headers_stream(bridge->custom_headers_);
                std::string header_line;
                
                while (std::getline(headers_stream, header_line)) {
                    // Skip empty lines
                    if (header_line.empty() || header_line == "\r") {
                        continue;
                    }
                    
                    // Remove trailing \r if present
                    if (!header_line.empty() && header_line.back() == '\r') {
                        header_line.pop_back();
                    }
                    
                    // Find the colon separator
                    size_t colon_pos = header_line.find(':');
                    if (colon_pos != std::string::npos) {
                        std::string name = header_line.substr(0, colon_pos);
                        // Skip the colon and any leading space
                        size_t value_start = colon_pos + 1;
                        while (value_start < header_line.size() && header_line[value_start] == ' ') {
                            value_start++;
                        }
                        std::string value = header_line.substr(value_start);
                        
                        LOG_DEBUG("Adding header: '" + name + "' with value '" + value + "'");
                        
                        if (lws_add_http_header_by_name(wsi, 
                                                       (unsigned char *)name.c_str(),
                                                       (unsigned char *)value.c_str(), 
                                                       value.length(), 
                                                       p, 
                                                       end)) {
                            LOG_ERROR("Failed to add header: " + name);
                            return -1;
                        }
                    }
                }
            }
            break;
        }
            
        case LWS_CALLBACK_CLIENT_WRITEABLE:
            bridge->ProcessSendQueue();
            break;
            
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            bridge->OnError("Connection error");
            bridge->OnDisconnected(-1);
            break;
            
        case LWS_CALLBACK_CLOSED:
            bridge->OnDisconnected(0);
            break;
            
        case LWS_CALLBACK_WSI_DESTROY:
            bridge->websocket_ = nullptr;
            break;
            
        default:
            break;
    }
    
    return 0;
}

void WebSocketBridge::SetReconnectionPolicy(bool enable, int max_attempts, int initial_delay,
                                           int max_delay, double backoff_multiplier) {
    reconnection_enabled_ = enable;
    max_reconnection_attempts_ = max_attempts;
    initial_reconnection_delay_ = initial_delay;
    max_reconnection_delay_ = max_delay;
    backoff_multiplier_ = backoff_multiplier;

    current_reconnection_delay_.store(initial_delay);

    LOG_INFO("WebSocket reconnection policy set: enabled=" + std::string(enable ? "true" : "false") +
             ", max_attempts=" + std::to_string(max_attempts) +
             ", initial_delay=" + std::to_string(initial_delay) + "ms");
}

void WebSocketBridge::SetServerList(const std::vector<std::string>& servers) {
    server_list_ = servers;
    current_server_index_.store(0);

    LOG_INFO("WebSocket server list set with " + std::to_string(servers.size()) + " servers");
    for (size_t i = 0; i < servers.size(); ++i) {
        LOG_DEBUG("  Server " + std::to_string(i) + ": " + servers[i]);
    }
}

int WebSocketBridge::Reconnect() {
    if (connected_.load()) {
        LOG_INFO("Already connected, disconnecting first for manual reconnect");
        Disconnect();
    }

    ResetReconnectionState();
    return TryNextServer();
}

WebSocketConnectionInfo WebSocketBridge::GetConnectionStatus() const {
    WebSocketConnectionInfo status = connection_info_;
    status.reconnection_attempts = reconnection_attempts_.load();
    status.is_reconnecting = reconnecting_.load();
    status.current_server_index = current_server_index_.load();
    return status;
}

void WebSocketBridge::StartReconnectionTimer() {
    if (!reconnection_enabled_ || !event_loop_) {
        return;
    }

    StopReconnectionTimer(); // Stop any existing timer

    int delay = CalculateReconnectionDelay();

    reconnection_timer_ = std::make_unique<uv_timer_t>();
    reconnection_timer_->data = this;

    int ret = uv_timer_init(event_loop_, reconnection_timer_.get());
    if (ret != 0) {
        LOG_ERROR("Failed to initialize reconnection timer: " + std::string(uv_strerror(ret)));
        return;
    }

    ret = uv_timer_start(reconnection_timer_.get(), OnReconnectionTimerCallback, delay, 0);
    if (ret != 0) {
        LOG_ERROR("Failed to start reconnection timer: " + std::string(uv_strerror(ret)));
        return;
    }

    LOG_INFO("Reconnection timer started: " + std::to_string(delay) + "ms delay");
}

void WebSocketBridge::StopReconnectionTimer() {
    if (reconnection_timer_) {
        uv_timer_stop(reconnection_timer_.get());
        uv_close(reinterpret_cast<uv_handle_t*>(reconnection_timer_.get()),
                 [](uv_handle_t* handle) {
                     delete reinterpret_cast<uv_timer_t*>(handle);
                 });
        reconnection_timer_.reset();
    }
}

void WebSocketBridge::OnReconnectionTimer() {
    LOG_INFO("Reconnection timer triggered, attempting to reconnect...");

    int ret = TryNextServer();
    if (ret != error::SUCCESS) {
        LOG_ERROR("Reconnection attempt failed: " + error::GetErrorMessage(ret));

        // Check if we should continue trying
        int attempts = reconnection_attempts_.load();
        if (max_reconnection_attempts_ > 0 && attempts >= max_reconnection_attempts_) {
            LOG_ERROR("Maximum reconnection attempts reached (" + std::to_string(max_reconnection_attempts_) +
                      "), giving up");
            reconnecting_.store(false);
            return;
        }

        // Schedule next attempt
        StartReconnectionTimer();
    }
}

int WebSocketBridge::TryNextServer() {
    if (server_list_.empty()) {
        LOG_ERROR("No servers configured for reconnection");
        return error::WEBSOCKET_CONNECTION_FAILED;
    }

    size_t server_index = current_server_index_.load();
    std::string server_url = server_list_[server_index];

    LOG_INFO("Attempting to connect to server " + std::to_string(server_index) + ": " + server_url);

    int ret = Connect(server_url);
    if (ret != error::SUCCESS) {
        // Try next server
        current_server_index_.store((server_index + 1) % server_list_.size());
        reconnection_attempts_.fetch_add(1);

        LOG_WARN("Failed to connect to " + server_url + ", will try next server");
        return ret;
    }

    return error::SUCCESS;
}

int WebSocketBridge::CalculateReconnectionDelay() {
    int current_delay = current_reconnection_delay_.load();

    // Calculate next delay with exponential backoff
    int next_delay = static_cast<int>(current_delay * backoff_multiplier_);
    if (next_delay > max_reconnection_delay_) {
        next_delay = max_reconnection_delay_;
    }

    current_reconnection_delay_.store(next_delay);

    return current_delay;
}

void WebSocketBridge::ResetReconnectionState() {
    reconnection_attempts_.store(0);
    current_reconnection_delay_.store(initial_reconnection_delay_);
    current_server_index_.store(0);
    reconnecting_.store(false);
}

void WebSocketBridge::OnReconnectionTimerCallback(uv_timer_t* timer) {
    WebSocketBridge* bridge = static_cast<WebSocketBridge*>(timer->data);
    if (bridge) {
        bridge->OnReconnectionTimer();
    }
}

} // namespace xiaozhi
