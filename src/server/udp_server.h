#pragma once

#include "common/types.h"
#include "common/constants.h"
#include "utils/crypto_utils.h"

#include <uv.h>
#include <memory>
#include <unordered_map>
#include <functional>
#include <atomic>
#include <mutex>

namespace xiaozhi {

/**
 * @brief UDP server for audio data handling
 * 
 * Handles UDP audio packets and forwards them through WebSocket bridge
 */
class UDPServer {
public:
    // Callback types
    using AudioDataCallback = std::function<void(const std::string& session_id, const std::vector<uint8_t>& audio_data)>;
    using SessionCreatedCallback = std::function<void(const std::string& session_id, const UDPConnectionInfo& info)>;
    using SessionClosedCallback = std::function<void(const std::string& session_id)>;
    using ErrorCallback = std::function<void(const std::string& error_message)>;
    
    /**
     * @brief Constructor
     * @param loop Event loop
     */
    explicit UDPServer(uv_loop_t* loop);
    
    /**
     * @brief Destructor
     */
    ~UDPServer();
    
    /**
     * @brief Initialize the UDP server
     * @param config Server configuration
     * @return Error code, 0 indicates success
     */
    int Initialize(const ServerConfig& config);

    /**
     * @brief Update the server configuration
     * @param config New server configuration
     * @return Error code, 0 indicates success
     */
    int UpdateConfig(const ServerConfig& config);
    
    /**
     * @brief Set the session ID for UDP connections
     * @param session_id The session ID to set
     */
    void SetSessionId(const std::string& session_id);
    
    /**
     * @brief Start the UDP server
     * @return Error code, 0 indicates success
     */
    int Start();
    
    /**
     * @brief Stop the UDP server
     * @return Error code, 0 indicates success
     */
    int Stop();
    
    /**
     * @brief Check if server is running
     * @return true if running
     */
    bool IsRunning() const;
    
    /**
     * @brief Send audio data to specific session (encrypted)
     * @param session_id Target session ID
     * @param audio_data Audio data to send
     * @return Error code, 0 indicates success
     */
    int SendAudioData(const std::string& session_id, const std::vector<uint8_t>& audio_data);

    /**
     * @brief Send encrypted audio packet to specific session
     * @param session_id Target session ID
     * @param audio_data Audio data to send
     * @param timestamp Timestamp for packet
     * @return Error code, 0 indicates success
     */
    int SendEncryptedAudioPacket(const std::string& session_id, const std::vector<uint8_t>& audio_data, uint32_t timestamp);
    
    /**
     * @brief Create new UDP session for MQTT client
     * @param connection_id MQTT connection ID
     * @return UDP connection info
     */
    UDPConnectionInfo CreateSession(ConnectionId connection_id);
    
    /**
     * @brief Close UDP session
     * @param session_id Session ID to close
     * @return Error code, 0 indicates success
     */
    int CloseSession(const std::string& session_id);
    
    /**
     * @brief Get session information
     * @param session_id Session ID
     * @return Session info or empty if not found
     */
    UDPSessionInfo GetSessionInfo(const std::string& session_id) const;
    
    /**
     * @brief Get all active sessions
     * @return Map of session ID to session info
     */
    std::unordered_map<std::string, UDPSessionInfo> GetActiveSessions() const;
    
    /**
     * @brief Get server statistics
     * @return UDP server statistics
     */
    UDPServerStats GetStats() const;
    
    /**
     * @brief Set callbacks
     */
    void SetAudioDataCallback(AudioDataCallback callback) { audio_data_callback_ = std::move(callback); }
    void SetSessionCreatedCallback(SessionCreatedCallback callback) { session_created_callback_ = std::move(callback); }
    void SetSessionClosedCallback(SessionClosedCallback callback) { session_closed_callback_ = std::move(callback); }
    void SetErrorCallback(ErrorCallback callback) { error_callback_ = std::move(callback); }

private:
    /**
     * @brief Handle incoming UDP packet
     * @param data Received data
     * @param length Data length
     * @param addr Sender address
     */
    void OnPacketReceived(const uint8_t* data, size_t length, const struct sockaddr* addr);
    
    /**
     * @brief Process audio packet
     * @param session_id Session ID
     * @param audio_data Audio data
     */
    void ProcessAudioPacket(const std::string& session_id, const std::vector<uint8_t>& audio_data);
    
    /**
     * @brief Handle session handshake
     * @param addr Client address
     * @param handshake_data Handshake data
     */
    void HandleSessionHandshake(const struct sockaddr* addr, const std::vector<uint8_t>& handshake_data);
    
    /**
     * @brief Send handshake response
     * @param addr Client address
     * @param session_id Assigned session ID
     */
    void SendHandshakeResponse(const struct sockaddr* addr, const std::string& session_id);
    
    /**
     * @brief Generate unique session ID
     * @return New session ID
     */
    std::string GenerateSessionId();
    
    /**
     * @brief Get session by address
     * @param addr Client address
     * @return Session ID or empty if not found
     */
    std::string GetSessionByAddress(const struct sockaddr* addr) const;
    
    /**
     * @brief Parse UDP packet header
     * @param data Packet data
     * @param length Data length
     * @param packet_type Output packet type
     * @param session_id Output session ID
     * @param payload_offset Output payload offset
     * @return Error code, 0 indicates success
     */
    int ParsePacketHeader(const uint8_t* data, size_t length, 
                         UDPPacketType& packet_type, std::string& session_id, size_t& payload_offset);
    
    /**
     * @brief Create UDP packet
     * @param packet_type Packet type
     * @param session_id Session ID
     * @param payload Payload data
     * @param buffer Output buffer
     * @return Error code, 0 indicates success
     */
    int CreatePacket(UDPPacketType packet_type, const std::string& session_id, 
                    const std::vector<uint8_t>& payload, std::vector<uint8_t>& buffer);
    
    /**
     * @brief Cleanup inactive sessions
     */
    void CleanupSessions();
    
    /**
     * @brief Update server statistics
     */
    void UpdateStats();
    
    /**
     * @brief Convert sockaddr to string
     * @param addr Socket address
     * @return Address string
     */
    std::string AddressToString(const struct sockaddr* addr) const;
    
    // Static callbacks for libuv
    static void OnReceive(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, 
                         const struct sockaddr* addr, unsigned flags);
    static void OnSend(uv_udp_send_t* req, int status);
    static void OnCleanupTimer(uv_timer_t* timer);
    static void AllocBuffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);

private:
    uv_loop_t* loop_;
    std::unique_ptr<uv_udp_t> udp_handle_;
    std::unique_ptr<uv_timer_t> cleanup_timer_;
    
    ServerConfig config_;
    std::atomic<bool> running_;
    std::atomic<uint32_t> next_session_id_;
    
    // Session management
    mutable std::mutex sessions_mutex_;
    std::unordered_map<std::string, UDPSessionInfo> sessions_;
    std::unordered_map<std::string, std::string> address_to_session_; // address -> session_id
    std::unordered_map<std::string, std::unique_ptr<crypto::AudioCrypto>> session_crypto_; // session_id -> crypto
    std::unordered_map<std::string, std::vector<uint8_t>> session_keys_; // session_id -> encryption key
    std::string default_session_id_; // Default session ID from WebSocket
    
    // Statistics
    mutable UDPServerStats stats_;
    
    // Callbacks
    AudioDataCallback audio_data_callback_;
    SessionCreatedCallback session_created_callback_;
    SessionClosedCallback session_closed_callback_;
    ErrorCallback error_callback_;
    
    // Disable copy
    UDPServer(const UDPServer&) = delete;
    UDPServer& operator=(const UDPServer&) = delete;
};

} // namespace xiaozhi
