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

#include "server/udp_server.h"
#include "utils/logger.h"
#include "utils/crypto_utils.h"
#include "common/error_codes.h"

#include <uv.h>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace xiaozhi {

UDPServer::UDPServer(uv_loop_t* loop) 
    : loop_(loop)
    , running_(false)
    , next_session_id_(1) {
}

UDPServer::~UDPServer() {
    Stop();
}

int UDPServer::Initialize(const ServerConfig& config) {
    config_ = config;
    
    // Initialize UDP handle
    udp_handle_ = std::make_unique<uv_udp_t>();
    udp_handle_->data = this;
    
    int ret = uv_udp_init(loop_, udp_handle_.get());
    if (ret != 0) {
        LOG_ERROR("Failed to initialize UDP handle: " + std::string(uv_strerror(ret)));
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
    
    LOG_INFO("UDP server initialized");
    return error::SUCCESS;
}

int UDPServer::Start() {
    if (running_.load()) {
        LOG_WARN("UDP server is already running");
        return error::ALREADY_EXISTS;
    }
    
    // Bind to address
    struct sockaddr_in addr;
    int ret = uv_ip4_addr(config_.udp.host.c_str(), config_.udp.port, &addr);
    if (ret != 0) {
        LOG_ERROR("Invalid UDP server address: " + config_.udp.host + ":" + std::to_string(config_.udp.port));
        return error::INVALID_PARAMETER;
    }
    
    ret = uv_udp_bind(udp_handle_.get(), reinterpret_cast<const struct sockaddr*>(&addr), 0);
    if (ret != 0) {
        LOG_ERROR("Failed to bind UDP server: " + std::string(uv_strerror(ret)));
        return error::BIND_FAILED;
    }
    
    // Start receiving
    ret = uv_udp_recv_start(udp_handle_.get(), AllocBuffer, OnReceive);
    if (ret != 0) {
        LOG_ERROR("Failed to start UDP receiving: " + std::string(uv_strerror(ret)));
        return error::NETWORK_ERROR;
    }
    
    // Start cleanup timer (every 60 seconds)
    ret = uv_timer_start(cleanup_timer_.get(), OnCleanupTimer, 60000, 60000);
    if (ret != 0) {
        LOG_ERROR("Failed to start cleanup timer: " + std::string(uv_strerror(ret)));
        return error::INTERNAL_ERROR;
    }
    
    running_.store(true);
    
    LOG_INFO("UDP server started on " + config_.udp.host + ":" + std::to_string(config_.udp.port));
    return error::SUCCESS;
}

int UDPServer::Stop() {
    if (!running_.load()) {
        return error::SUCCESS;
    }
    
    LOG_INFO("Stopping UDP server...");
    running_.store(false);
    
    // Stop receiving
    if (udp_handle_) {
        uv_udp_recv_stop(udp_handle_.get());
        uv_close(reinterpret_cast<uv_handle_t*>(udp_handle_.get()), nullptr);
    }
    
    // Stop cleanup timer
    if (cleanup_timer_) {
        uv_timer_stop(cleanup_timer_.get());
        uv_close(reinterpret_cast<uv_handle_t*>(cleanup_timer_.get()), nullptr);
    }
    
    // Clear all sessions
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_.clear();
        address_to_session_.clear();
        session_crypto_.clear();
        session_keys_.clear();
    }
    
    LOG_INFO("UDP server stopped");
    return error::SUCCESS;
}

bool UDPServer::IsRunning() const {
    return running_.load();
}

int UDPServer::SendAudioData(const std::string& session_id, const std::vector<uint8_t>& audio_data) {
    // Use current timestamp
    uint32_t timestamp = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());

    return SendEncryptedAudioPacket(session_id, audio_data, timestamp);
}

int UDPServer::SendEncryptedAudioPacket(const std::string& session_id, const std::vector<uint8_t>& audio_data, uint32_t timestamp) {
    if (!running_.load()) {
        return error::CONNECTION_CLOSED;
    }

    UDPSessionInfo session_info;
    std::unique_ptr<crypto::AudioCrypto> crypto_ptr;

    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) {
            LOG_WARN("Session not found for audio data: " + session_id);
            return error::NOT_FOUND;
        }
        session_info = it->second;

        // Get crypto for this session
        auto crypto_it = session_crypto_.find(session_id);
        if (crypto_it == session_crypto_.end()) {
            LOG_WARN("No crypto found for session: " + session_id);
            return error::CRYPTO_INIT_FAILED;
        }

        // Create a copy of the crypto object for thread safety
        crypto_ptr = std::make_unique<crypto::AudioCrypto>();
        auto key_it = session_keys_.find(session_id);
        if (key_it != session_keys_.end()) {
            crypto_ptr->Initialize(key_it->second);
        }
    }

    // Increment sequence number for this session
    session_info.packets_sent++;
    uint32_t sequence = static_cast<uint32_t>(session_info.packets_sent);

    // Generate UDP header (16 bytes) for encryption IV
    std::vector<uint8_t> header;
    int ret = crypto::UDPHeaderGenerator::GenerateHeader(
        static_cast<uint32_t>(session_info.connection_id),
        static_cast<uint16_t>(audio_data.size()),
        timestamp,
        sequence,
        header);
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to generate UDP header");
        return ret;
    }

    // Encrypt audio data using header as IV
    std::vector<uint8_t> encrypted_data;
    ret = crypto_ptr->Encrypt(audio_data, header, encrypted_data);
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to encrypt audio data");
        return ret;
    }

    // Create complete packet: [header][encrypted_data]
    std::vector<uint8_t> packet_buffer;
    packet_buffer.reserve(header.size() + encrypted_data.size());
    packet_buffer.insert(packet_buffer.end(), header.begin(), header.end());
    packet_buffer.insert(packet_buffer.end(), encrypted_data.begin(), encrypted_data.end());

    // Send packet
    auto send_req = std::make_unique<uv_udp_send_t>();

    // Allocate buffer (will be freed in send callback)
    auto buffer_data = std::make_unique<uint8_t[]>(packet_buffer.size());
    std::memcpy(buffer_data.get(), packet_buffer.data(), packet_buffer.size());

    // Store buffer pointer in request data for cleanup
    send_req->data = buffer_data.release();

    uv_buf_t buffer = uv_buf_init(reinterpret_cast<char*>(send_req->data), (unsigned int)packet_buffer.size());

    // Parse address
    struct sockaddr_in addr;
    ret = uv_ip4_addr(session_info.remote_address.c_str(), session_info.remote_port, &addr);
    if (ret != 0) {
        LOG_ERROR("Invalid session address: " + session_info.remote_address + ":" + std::to_string(session_info.remote_port));
        delete[] buffer.base;
        return error::INVALID_PARAMETER;
    }

    ret = uv_udp_send(send_req.release(), udp_handle_.get(), &buffer, 1,
                      reinterpret_cast<const struct sockaddr*>(&addr), OnSend);
    if (ret != 0) {
        LOG_ERROR("Failed to send UDP packet: " + std::string(uv_strerror(ret)));
        delete[] buffer.base;
        return error::SEND_FAILED;
    }

    // Update session statistics
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = sessions_.find(session_id);
        if (it != sessions_.end()) {
            it->second.packets_sent++;
            it->second.bytes_sent += audio_data.size();
        }
    }

    // Update server statistics
    stats_.packets_sent++;
    stats_.bytes_sent += audio_data.size();

    LOG_DEBUG("Sent encrypted audio packet: session=" + session_id +
              ", size=" + std::to_string(audio_data.size()) +
              ", sequence=" + std::to_string(sequence));

    return error::SUCCESS;
}

UDPConnectionInfo UDPServer::CreateSession(ConnectionId connection_id) {
    std::string session_id = GenerateSessionId();

    // Generate encryption key and nonce
    std::vector<uint8_t> encryption_key = crypto::AudioCrypto::GenerateKey();

    UDPConnectionInfo info;
    info.remote_address = config_.udp.public_ip;
    info.remote_port = config_.udp.port;
    info.session_id = session_id;
    info.encryption_key = encryption_key;
    info.encryption_method = constants::DEFAULT_ENCRYPTION_METHOD;
    info.local_sequence = 0;
    info.remote_sequence = 0;
    info.start_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    // Generate initial nonce (UDP header with zeros)
    std::vector<uint8_t> nonce;
    crypto::UDPHeaderGenerator::GenerateHeader(
        static_cast<uint32_t>(connection_id), 0, 0, 0, nonce);
    info.nonce = nonce;

    // Create session info
    UDPSessionInfo session_info;
    session_info.session_id = session_id;
    session_info.connection_id = connection_id;
    session_info.remote_address = ""; // Will be set when client connects
    session_info.remote_port = 0;
    session_info.start_time = info.start_time;
    session_info.last_activity = info.start_time;
    session_info.is_active = false; // Will be activated on first packet
    session_info.packets_received = 0;
    session_info.packets_sent = 0;
    session_info.bytes_received = 0;
    session_info.bytes_sent = 0;

    // Create crypto instance for this session
    auto crypto_instance = std::make_unique<crypto::AudioCrypto>();
    int ret = crypto_instance->Initialize(encryption_key);
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to initialize crypto for session: " + session_id);
        return info; // Return info anyway, but crypto will fail
    }

    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_[session_id] = session_info;
        session_crypto_[session_id] = std::move(crypto_instance);
        session_keys_[session_id] = encryption_key;
    }

    LOG_INFO("Created encrypted UDP session: " + session_id + " for connection " + std::to_string(connection_id));

    if (session_created_callback_) {
        session_created_callback_(session_id, info);
    }

    return info;
}

int UDPServer::CloseSession(const std::string& session_id) {
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) {
            return error::NOT_FOUND;
        }

        // Remove from address mapping
        std::string address_key = it->second.remote_address + ":" + std::to_string(it->second.remote_port);
        address_to_session_.erase(address_key);

        // Remove crypto and keys
        session_crypto_.erase(session_id);
        session_keys_.erase(session_id);

        sessions_.erase(it);
    }

    LOG_INFO("Closed encrypted UDP session: " + session_id);

    if (session_closed_callback_) {
        session_closed_callback_(session_id);
    }

    return error::SUCCESS;
}

UDPSessionInfo UDPServer::GetSessionInfo(const std::string& session_id) const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        return it->second;
    }
    return UDPSessionInfo{};
}

std::unordered_map<std::string, UDPSessionInfo> UDPServer::GetActiveSessions() const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    return sessions_;
}

UDPServerStats UDPServer::GetStats() const {
    // Update stats inline since we can't call non-const UpdateStats from const function
    const_cast<UDPServer*>(this)->stats_.active_sessions = (uint32_t)sessions_.size();
    return stats_;
}

void UDPServer::OnPacketReceived(const uint8_t* data, size_t length, const struct sockaddr* addr) {
    if (!data || length == 0 || !addr) {
        return;
    }
    
    // Update statistics
    stats_.packets_received++;
    stats_.bytes_received += length;
    
    // Parse packet header
    UDPPacketType packet_type;
    std::string session_id;
    size_t payload_offset;
    
    int ret = ParsePacketHeader(data, length, packet_type, session_id, payload_offset);
    if (ret != error::SUCCESS) {
        LOG_WARN("Invalid UDP packet header");
        return;
    }
    
    switch (packet_type) {
        case UDPPacketType::HANDSHAKE:
            HandleSessionHandshake(addr, std::vector<uint8_t>(data + payload_offset, data + length));
            break;
            
        case UDPPacketType::AUDIO_DATA:
            {
                // For encrypted audio data, we need to handle it differently
                // The packet format is: [16-byte header][encrypted payload]
                if (length < 16) {
                    LOG_WARN("Audio packet too short for encryption header");
                    return;
                }

                // Extract header and encrypted payload
                std::vector<uint8_t> header(data, data + 16);
                std::vector<uint8_t> encrypted_payload(data + 16, data + length);

                // Parse header to get connection info
                uint32_t connection_id, timestamp, sequence;
                uint16_t payload_length;
                ret = crypto::UDPHeaderGenerator::ParseHeader(header, connection_id, payload_length, timestamp, sequence);
                if (ret != error::SUCCESS) {
                    LOG_WARN("Failed to parse UDP header for audio packet");
                    return;
                }

                // Find session by connection ID or address
                std::string found_session_id;
                std::unique_ptr<crypto::AudioCrypto> crypto_ptr;

                {
                    std::lock_guard<std::mutex> lock(sessions_mutex_);

                    // Try to find session by connection ID first
                    for (const auto& [sid, session_info] : sessions_) {
                        if (session_info.connection_id == connection_id) {
                            found_session_id = sid;
                            break;
                        }
                    }

                    // If not found, try by address
                    if (found_session_id.empty()) {
                        std::string addr_str = AddressToString(addr);
                        auto addr_it = address_to_session_.find(addr_str);
                        if (addr_it != address_to_session_.end()) {
                            found_session_id = addr_it->second;
                        }
                    }

                    if (found_session_id.empty()) {
                        LOG_WARN("No session found for audio packet from " + AddressToString(addr));
                        return;
                    }

                    // Get crypto for decryption
                    auto crypto_it = session_crypto_.find(found_session_id);
                    if (crypto_it == session_crypto_.end()) {
                        LOG_WARN("No crypto found for session: " + found_session_id);
                        return;
                    }

                    // Create a copy for thread safety
                    crypto_ptr = std::make_unique<crypto::AudioCrypto>();
                    auto key_it = session_keys_.find(found_session_id);
                    if (key_it != session_keys_.end()) {
                        crypto_ptr->Initialize(key_it->second);
                    }

                    // Update session activity
                    auto session_it = sessions_.find(found_session_id);
                    if (session_it != sessions_.end()) {
                        session_it->second.last_activity = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
                        session_it->second.packets_received++;
                        session_it->second.bytes_received += encrypted_payload.size();
                        session_it->second.remote_sequence = sequence;

                        // Set client address if not set
                        if (!session_it->second.is_active) {
                            std::string addr_str = AddressToString(addr);
                            size_t colon_pos = addr_str.find(':');
                            if (colon_pos != std::string::npos) {
                                session_it->second.remote_address = addr_str.substr(0, colon_pos);
                                session_it->second.remote_port = (uint16_t)std::stoi(addr_str.substr(colon_pos + 1));
                                session_it->second.is_active = true;

                                address_to_session_[addr_str] = found_session_id;
                            }
                        }
                    }
                }

                // Decrypt audio data using header as IV
                std::vector<uint8_t> decrypted_audio;
                ret = crypto_ptr->Decrypt(encrypted_payload, header, decrypted_audio);
                if (ret != error::SUCCESS) {
                    LOG_ERROR("Failed to decrypt audio data for session: " + found_session_id);
                    return;
                }

                LOG_DEBUG("Decrypted audio packet: session=" + found_session_id +
                          ", encrypted_size=" + std::to_string(encrypted_payload.size()) +
                          ", decrypted_size=" + std::to_string(decrypted_audio.size()) +
                          ", sequence=" + std::to_string(sequence));

                // Process decrypted audio data
                ProcessAudioPacket(found_session_id, decrypted_audio);
            }
            break;
            
        case UDPPacketType::HEARTBEAT:
            // Just update activity time (already done above)
            LOG_DEBUG("Heartbeat received from session: " + session_id);
            break;
            
        default:
            LOG_WARN("Unknown UDP packet type: " + std::to_string(static_cast<int>(packet_type)));
            break;
    }
}

void UDPServer::ProcessAudioPacket(const std::string& session_id, const std::vector<uint8_t>& audio_data) {
    LOG_DEBUG("Processing audio packet: session=" + session_id + ", size=" + std::to_string(audio_data.size()));
    
    if (audio_data_callback_) {
        audio_data_callback_(session_id, audio_data);
    }
}

void UDPServer::HandleSessionHandshake(const struct sockaddr* addr, const std::vector<uint8_t>& handshake_data) {
    (void)handshake_data;
    std::string addr_str = AddressToString(addr);
    LOG_INFO("UDP handshake from: " + addr_str);
    
    // Check if session already exists for this address
    std::string session_id;
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = address_to_session_.find(addr_str);
        if (it != address_to_session_.end()) {
            session_id = it->second;
        }
    }
    
    if (session_id.empty()) {
        // Create new session
        session_id = GenerateSessionId();
        
        UDPSessionInfo session_info;
        session_info.session_id = session_id;
        session_info.connection_id = 0; // Will be linked later
        
        size_t colon_pos = addr_str.find(':');
        if (colon_pos != std::string::npos) {
            session_info.remote_address = addr_str.substr(0, colon_pos);
            session_info.remote_port = (uint16_t)std::stoi(addr_str.substr(colon_pos + 1));
        }
        
        session_info.start_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        session_info.last_activity = session_info.start_time;
        session_info.is_active = true;
        
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            sessions_[session_id] = session_info;
            address_to_session_[addr_str] = session_id;
        }
        
        LOG_INFO("Created new UDP session: " + session_id);
    }
    
    // Send handshake response
    SendHandshakeResponse(addr, session_id);
}

void UDPServer::SendHandshakeResponse(const struct sockaddr* addr, const std::string& session_id) {
    // Create handshake response packet
    std::vector<uint8_t> response_data;
    response_data.insert(response_data.end(), session_id.begin(), session_id.end());
    
    std::vector<uint8_t> packet_buffer;
    int ret = CreatePacket(UDPPacketType::HANDSHAKE_RESPONSE, session_id, response_data, packet_buffer);
    if (ret != error::SUCCESS) {
        LOG_ERROR("Failed to create handshake response packet");
        return;
    }
    
    // Send response
    auto send_req = std::make_unique<uv_udp_send_t>();
    send_req->data = this;
    
    auto buffer_data = std::make_unique<uint8_t[]>(packet_buffer.size());
    std::memcpy(buffer_data.get(), packet_buffer.data(), packet_buffer.size());
    
    uv_buf_t buffer = uv_buf_init(reinterpret_cast<char*>(buffer_data.release()), (unsigned int)packet_buffer.size());
    
    ret = uv_udp_send(send_req.release(), udp_handle_.get(), &buffer, 1, addr, OnSend);
    if (ret != 0) {
        LOG_ERROR("Failed to send handshake response: " + std::string(uv_strerror(ret)));
        delete[] buffer.base;
    } else {
        LOG_DEBUG("Sent handshake response to session: " + session_id);
    }
}

std::string UDPServer::GenerateSessionId() {
    uint32_t id = next_session_id_.fetch_add(1);
    
    // Add timestamp for uniqueness
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    
    std::ostringstream oss;
    oss << "udp_" << std::hex << timestamp << "_" << std::hex << id;
    return oss.str();
}

std::string UDPServer::GetSessionByAddress(const struct sockaddr* addr) const {
    std::string addr_str = AddressToString(addr);
    
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = address_to_session_.find(addr_str);
    if (it != address_to_session_.end()) {
        return it->second;
    }
    return "";
}

int UDPServer::ParsePacketHeader(const uint8_t* data, size_t length, 
                                UDPPacketType& packet_type, std::string& session_id, size_t& payload_offset) {
    if (length < 4) { // Minimum header size
        return error::UDP_INVALID_PACKET;
    }
    
    // Simple packet format:
    // [1 byte: packet type][1 byte: session_id length][N bytes: session_id][payload]
    
    packet_type = static_cast<UDPPacketType>(data[0]);
    uint8_t session_id_length = data[1];
    
    if (length < 2 + session_id_length) {
        return error::UDP_INVALID_PACKET;
    }
    
    session_id.assign(reinterpret_cast<const char*>(data + 2), session_id_length);
    payload_offset = 2 + session_id_length;
    
    return error::SUCCESS;
}

int UDPServer::CreatePacket(UDPPacketType packet_type, const std::string& session_id, 
                           const std::vector<uint8_t>& payload, std::vector<uint8_t>& buffer) {
    if (session_id.length() > 255) {
        return error::INVALID_PARAMETER;
    }
    
    buffer.clear();
    buffer.reserve(2 + session_id.length() + payload.size());
    
    // Packet type
    buffer.push_back(static_cast<uint8_t>(packet_type));
    
    // Session ID length
    buffer.push_back(static_cast<uint8_t>(session_id.length()));
    
    // Session ID
    buffer.insert(buffer.end(), session_id.begin(), session_id.end());
    
    // Payload
    buffer.insert(buffer.end(), payload.begin(), payload.end());
    
    return error::SUCCESS;
}

void UDPServer::CleanupSessions() {
    auto current_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    std::vector<std::string> sessions_to_remove;
    
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (const auto& [session_id, session_info] : sessions_) {
            // Remove sessions inactive for more than 5 minutes
            if (current_time - session_info.last_activity > 300000) {
                sessions_to_remove.push_back(session_id);
            }
        }
    }
    
    for (const std::string& session_id : sessions_to_remove) {
        LOG_INFO("Cleaning up inactive UDP session: " + session_id);
        CloseSession(session_id);
    }
}

void UDPServer::UpdateStats() {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    stats_.active_sessions = (uint32_t)sessions_.size();
}

std::string UDPServer::AddressToString(const struct sockaddr* addr) const {
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in* addr_in = reinterpret_cast<const struct sockaddr_in*>(addr);
        char ip_str[INET_ADDRSTRLEN];
        uv_ip4_name(addr_in, ip_str, sizeof(ip_str));
        return std::string(ip_str) + ":" + std::to_string(ntohs(addr_in->sin_port));
    }
    return "unknown";
}

void UDPServer::OnReceive(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, 
                         const struct sockaddr* addr, unsigned flags) {
    (void)flags;
    UDPServer* server = static_cast<UDPServer*>(handle->data);
    
    if (nread > 0 && addr) {
        server->OnPacketReceived(reinterpret_cast<const uint8_t*>(buf->base), nread, addr);
    } else if (nread < 0) {
        LOG_ERROR("UDP receive error: " + std::string(uv_strerror((int)nread)));
    }
    
    if (buf->base) {
        delete[] buf->base;
    }
}

void UDPServer::OnSend(uv_udp_send_t* req, int status) {
    // Clean up the buffer (stored in req->data)
    if (req->data) {
        delete[] static_cast<uint8_t*>(req->data);
    }
    delete req;

    if (status != 0) {
        LOG_ERROR("UDP send error: " + std::string(uv_strerror(status)));
    }
}

void UDPServer::OnCleanupTimer(uv_timer_t* timer) {
    UDPServer* server = static_cast<UDPServer*>(timer->data);
    if (server) {
        server->CleanupSessions();
    }
}

void UDPServer::AllocBuffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    (void)handle;
    buf->base = new char[suggested_size];
    buf->len = (ULONG)suggested_size;
}

} // namespace xiaozhi
