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

#include "server/mqtt_server.h"
#include "connection/mqtt_connection.h"
#include "utils/logger.h"
#include "common/error_codes.h"

#include <uv.h>
#include <chrono>

namespace xiaozhi {

MQTTServer::MQTTServer(uv_loop_t* loop) 
    : loop_(loop)
    , running_(false)
    , next_connection_id_(1) {
}

MQTTServer::~MQTTServer() {
    Stop();
}

int MQTTServer::Initialize(const ServerConfig& config) {
    config_ = config;
    
    // Initialize TCP server
    tcp_server_ = std::make_unique<uv_tcp_t>();
    tcp_server_->data = this;
    
    int ret = uv_tcp_init(loop_, tcp_server_.get());
    if (ret != 0) {
        LOG_ERROR("Failed to initialize TCP server: " + std::string(uv_strerror(ret)));
        return error::NETWORK_ERROR;
    }
    
    // Initialize cleanup timer
    cleanup_timer_ = std::make_unique<uv_timer_t>();
    cleanup_timer_->data = this;
    
    ret = uv_timer_init(loop_, cleanup_timer_.get());
    if (ret != 0) {
        LOG_ERROR("Failed to initialize cleanup timer: " + std::string(uv_strerror(ret)));
        return error::INTERNAL_ERROR;
    }
    
    LOG_INFO("MQTT server initialized");
    return error::SUCCESS;
}

int MQTTServer::Start() {
    if (running_.load()) {
        LOG_WARN("MQTT server is already running");
        return error::ALREADY_EXISTS;
    }
    
    // Bind to address
    struct sockaddr_in addr;
    int ret = uv_ip4_addr(config_.mqtt.host.c_str(), config_.mqtt.port, &addr);
    if (ret != 0) {
        LOG_ERROR("Invalid MQTT server address: " + config_.mqtt.host + ":" + std::to_string(config_.mqtt.port));
        return error::INVALID_PARAMETER;
    }
    
    ret = uv_tcp_bind(tcp_server_.get(), reinterpret_cast<const struct sockaddr*>(&addr), 0);
    if (ret != 0) {
        LOG_ERROR("Failed to bind MQTT server: " + std::string(uv_strerror(ret)));
        return error::BIND_FAILED;
    }
    
    // Start listening
    ret = uv_listen(reinterpret_cast<uv_stream_t*>(tcp_server_.get()), 
                    constants::MAX_PENDING_CONNECTIONS, OnConnection);
    if (ret != 0) {
        LOG_ERROR("Failed to listen on MQTT server: " + std::string(uv_strerror(ret)));
        return error::LISTEN_FAILED;
    }
    
    // Start cleanup timer (every 30 seconds)
    ret = uv_timer_start(cleanup_timer_.get(), OnCleanupTimer, 30000, 30000);
    if (ret != 0) {
        LOG_ERROR("Failed to start cleanup timer: " + std::string(uv_strerror(ret)));
        return error::INTERNAL_ERROR;
    }
    
    running_.store(true);
    
    LOG_INFO("MQTT server started on " + config_.mqtt.host + ":" + std::to_string(config_.mqtt.port));
    return error::SUCCESS;
}

int MQTTServer::Stop() {
    if (!running_.load()) {
        return error::SUCCESS;
    }
    
    LOG_INFO("Stopping MQTT server...");
    running_.store(false);
    
    // Stop accepting new connections
    if (tcp_server_) {
        uv_close(reinterpret_cast<uv_handle_t*>(tcp_server_.get()), nullptr);
    }
    
    // Stop cleanup timer
    if (cleanup_timer_) {
        uv_timer_stop(cleanup_timer_.get());
        uv_close(reinterpret_cast<uv_handle_t*>(cleanup_timer_.get()), nullptr);
    }
    
    // Close all connections
    for (auto& [connection_id, connection] : connections_) {
        connection->Stop();
    }
    connections_.clear();
    client_ids_.clear();
    
    LOG_INFO("MQTT server stopped");
    return error::SUCCESS;
}

bool MQTTServer::IsRunning() const {
    return running_.load();
}

size_t MQTTServer::GetConnectionCount() const {
    return connections_.size();
}

int MQTTServer::ForwardToClient(ConnectionId connection_id, const std::string& topic, const std::string& payload) {
    auto it = connections_.find(connection_id);
    if (it == connections_.end()) {
        LOG_WARN("Connection not found for forwarding: " + std::to_string(connection_id));
        return error::NOT_FOUND;
    }
    
    return it->second->ForwardFromWebSocket(topic, payload);
}

int MQTTServer::BroadcastToClients(const std::string& topic, const std::string& payload) {
    int success_count = 0;
    int error_count = 0;
    
    for (auto& [connection_id, connection] : connections_) {
        int ret = connection->ForwardFromWebSocket(topic, payload);
        if (ret == error::SUCCESS) {
            success_count++;
        } else {
            error_count++;
        }
    }
    
    LOG_DEBUG("Broadcast to " + std::to_string(success_count) + " clients, " + 
              std::to_string(error_count) + " errors");
    
    return error::SUCCESS;
}

int MQTTServer::SendUDPInfoToClient(ConnectionId connection_id, const UDPConnectionInfo& udp_info) {
    auto it = connections_.find(connection_id);
    if (it == connections_.end()) {
        LOG_WARN("Connection not found for UDP info: " + std::to_string(connection_id));
        return error::NOT_FOUND;
    }
    
    return it->second->SendUDPInfo(udp_info);
}

ServerStats MQTTServer::GetStats() const {
    // Update stats inline since we can't call non-const UpdateStats from const function
    const_cast<MQTTServer*>(this)->stats_.active_connections = connections_.size();
    return stats_;
}

void MQTTServer::OnNewConnection(int status) {
    if (status < 0) {
        LOG_ERROR("New connection error: " + std::string(uv_strerror(status)));
        return;
    }
    
    if (!running_.load()) {
        LOG_DEBUG("Rejecting connection - server is stopping");
        return;
    }
    
    if (connections_.size() >= config_.mqtt.max_connections) {
        LOG_WARN("Maximum connections reached, rejecting new connection");
        return;
    }
    
    // Create new TCP handle for the client
    auto client_tcp = std::make_unique<uv_tcp_t>();
    int ret = uv_tcp_init(loop_, client_tcp.get());
    if (ret != 0) {
        LOG_ERROR("Failed to initialize client TCP: " + std::string(uv_strerror(ret)));
        return;
    }
    
    // Accept the connection
    ret = uv_accept(reinterpret_cast<uv_stream_t*>(tcp_server_.get()),
                    reinterpret_cast<uv_stream_t*>(client_tcp.get()));
    if (ret != 0) {
        LOG_ERROR("Failed to accept connection: " + std::string(uv_strerror(ret)));
        uv_close(reinterpret_cast<uv_handle_t*>(client_tcp.get()), nullptr);
        return;
    }
    
    // Generate connection ID
    ConnectionId connection_id = GenerateConnectionId();
    
    // Create MQTT connection
    auto connection = std::make_unique<MQTTConnection>(connection_id, client_tcp.release(), loop_, config_);
    
    // Set up callbacks
    connection->SetDisconnectCallback([this](ConnectionId id) {
        OnClientDisconnected(id);
    });
    
    connection->SetForwardMessageCallback([this, connection_id](const std::string& topic, const std::string& payload) {
        OnMessageForward(connection_id, topic, payload);
    });
    
    connection->SetUDPInfoCallback([this, connection_id](ConnectionId id, const UDPConnectionInfo& info) {
        (void)id;
        OnUDPInfoRequest(connection_id, info);
    });
    
    // Initialize and start the connection
    ret = connection->Initialize();
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to initialize MQTT connection: " + error::GetErrorMessage(ret));
        return;
    }
    
    ret = connection->StartReading();
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to start reading from MQTT connection: " + error::GetErrorMessage(ret));
        return;
    }
    
    // Store the connection
    connections_[connection_id] = std::move(connection);
    
    LOG_INFO("New MQTT client connected: " + std::to_string(connection_id));
    
    // Update statistics
    stats_.total_connections++;
    stats_.active_connections = connections_.size();
}

void MQTTServer::OnClientDisconnected(ConnectionId connection_id) {
    auto it = connections_.find(connection_id);
    if (it != connections_.end()) {
        std::string client_id;
        auto client_it = client_ids_.find(connection_id);
        if (client_it != client_ids_.end()) {
            client_id = client_it->second;
            client_ids_.erase(client_it);
        }
        
        connections_.erase(it);
        
        LOG_INFO("MQTT client disconnected: " + std::to_string(connection_id) + 
                 (client_id.empty() ? "" : " (" + client_id + ")"));
        
        // Trigger callback
        if (client_disconnected_callback_) {
            client_disconnected_callback_(connection_id, client_id);
        }
        
        // Update statistics
        stats_.active_connections = connections_.size();
    }
}

void MQTTServer::OnMessageForward(ConnectionId connection_id, const std::string& topic, const std::string& payload) {
    LOG_DEBUG("Forwarding message from client " + std::to_string(connection_id) + 
              ": topic=" + topic + ", size=" + std::to_string(payload.length()));
    
    // Update statistics
    stats_.mqtt_messages_received++;
    stats_.bytes_received += payload.length();
    
    // Trigger callback
    if (message_forward_callback_) {
        message_forward_callback_(connection_id, topic, payload);
    }
}

void MQTTServer::OnUDPInfoRequest(ConnectionId connection_id, const UDPConnectionInfo& udp_info) {
    (void)udp_info;
    LOG_DEBUG("UDP info request from client " + std::to_string(connection_id));
    
    // Trigger callback to get UDP info
    if (udp_info_request_callback_) {
        UDPConnectionInfo response_info = udp_info_request_callback_(connection_id);
        SendUDPInfoToClient(connection_id, response_info);
    }
}

ConnectionId MQTTServer::GenerateConnectionId() {
    return next_connection_id_.fetch_add(1);
}

void MQTTServer::CleanupConnections() {
    std::vector<ConnectionId> to_remove;
    
    for (auto& [connection_id, connection] : connections_) {
        if (!connection->IsActive() || connection->IsKeepAliveTimeout()) {
            to_remove.push_back(connection_id);
        }
    }
    
    for (ConnectionId id : to_remove) {
        LOG_INFO("Cleaning up inactive connection: " + std::to_string(id));
        OnClientDisconnected(id);
    }
}

void MQTTServer::UpdateStats() {
    stats_.active_connections = connections_.size();
}

void MQTTServer::OnConnection(uv_stream_t* server, int status) {
    MQTTServer* mqtt_server = static_cast<MQTTServer*>(server->data);
    if (mqtt_server) {
        mqtt_server->OnNewConnection(status);
    }
}

void MQTTServer::OnCleanupTimer(uv_timer_t* timer) {
    MQTTServer* mqtt_server = static_cast<MQTTServer*>(timer->data);
    if (mqtt_server) {
        mqtt_server->CleanupConnections();
    }
}

} // namespace xiaozhi
