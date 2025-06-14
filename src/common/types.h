#pragma once

// Fix Windows macro conflicts
#ifdef _WIN32
#ifdef ERROR
#undef ERROR
#endif
#ifdef WARN
#undef WARN
#endif
#ifdef DEBUG
#undef DEBUG
#endif
#ifdef INFO
#undef INFO
#endif
#endif

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

// Forward declarations
struct uv_loop_s;
struct uv_tcp_s;
struct uv_udp_s;
struct uv_timer_s;
struct lws_context;
struct lws;

namespace xiaozhi {

// Forward declarations for libuv types (use actual libuv types)
// Note: These are already defined in uv.h, so we don't need to redefine them

// Basic types
using ConnectionId = uint32_t;
using SessionId = std::string;
using MacAddress = std::string;
using ClientId = std::string;

// Callback function types
using ErrorCallback = std::function<void(int error_code, const std::string& message)>;
using DataCallback = std::function<void(const std::vector<uint8_t>& data)>;
using MessageCallback = std::function<void(const std::string& message)>;

// MQTT related structures
struct MQTTConnectInfo {
    std::string client_id;
    std::string username;
    std::string password;
    std::string protocol;
    uint8_t protocol_level = 4;  // MQTT 3.1.1
    uint16_t keep_alive = 60;
    bool clean_session = true;
};

struct MQTTPublishInfo {
    std::string topic;
    std::string payload;
    uint8_t qos = 0;
    bool dup = false;
    bool retain = false;
    uint16_t packet_id = 0;
};

struct MQTTSubscribeInfo {
    std::string topic;
    uint8_t qos = 0;
    uint16_t packet_id = 0;
};

// UDP related structures

/**
 * @brief UDP packet types
 */
enum class UDPPacketType : uint8_t {
    HANDSHAKE = 0x01,
    HANDSHAKE_RESPONSE = 0x02,
    AUDIO_DATA = 0x03,
    HEARTBEAT = 0x04
};

struct UDPConnectionInfo {
    std::string remote_address;
    uint16_t remote_port = 0;

    // Fields for JavaScript compatibility: mirrors JavaScript this.udp = { ... }
    uint32_t cookie = 0;                    // JavaScript: cookie
    uint32_t local_sequence = 0;           // JavaScript: localSequence
    uint32_t remote_sequence = 0;          // JavaScript: remoteSequence

    // Encryption information (JavaScript compatibility)
    std::vector<uint8_t> encryption_key;   // JavaScript: key (crypto.randomBytes(16))
    std::vector<uint8_t> nonce;            // JavaScript: nonce (crypto.randomBytes(16))
    std::string encryption_method = "aes-128-ctr";  // JavaScript: encryption

    // Session information
    int64_t start_time = 0;
    SessionId session_id;
};

/**
 * @brief UDP session information
 */
struct UDPSessionInfo {
    std::string session_id;
    ConnectionId connection_id = 0;
    std::string remote_address;
    uint16_t remote_port = 0;
    int64_t start_time = 0;
    int64_t last_activity = 0;
    bool is_active = false;
    uint64_t packets_received = 0;
    uint64_t packets_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t bytes_sent = 0;
    uint32_t remote_sequence = 0;  // Remote sequence number for packet ordering
};

/**
 * @brief UDP server statistics
 */
struct UDPServerStats {
    uint32_t active_sessions = 0;
    uint64_t total_sessions = 0;
    uint64_t packets_received = 0;
    uint64_t packets_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t bytes_sent = 0;
};

// WebSocket related structures
struct WebSocketConnectionInfo {
    std::string server_url;
    std::unordered_map<std::string, std::string> headers;
    bool is_connected = false;
    lws_context* context = nullptr;
    lws* websocket = nullptr;

    // Reconnection information
    uint32_t reconnection_attempts = 0;
    bool is_reconnecting = false;
    size_t current_server_index = 0;
};

// Audio parameters
struct AudioParams {
    uint32_t sample_rate = 16000;
    uint8_t channels = 1;
    uint8_t bits_per_sample = 16;
    std::string codec = "opus";
    uint32_t bitrate = 32000;
    uint32_t frame_size = 320;  // 20ms at 16kHz
};

// Device features
struct DeviceFeatures {
    bool supports_mcp = false;
    bool supports_audio = true;
    bool supports_encryption = true;
    std::vector<std::string> supported_codecs = {"opus"};
};

// Hello message structure
struct HelloMessage {
    uint8_t version = 3;
    std::string type = "hello";
    AudioParams audio_params;
    DeviceFeatures features;
    SessionId session_id;
    std::string transport = "udp";
    UDPConnectionInfo udp_info;
};

// Configuration structure
struct ServerConfig {
    struct {
        std::string host = "0.0.0.0";
        uint16_t port = 1883;
        uint32_t max_connections = 10000;
        uint32_t max_payload_size = 8192;
    } mqtt;

    struct {
        std::string host = "0.0.0.0";
        uint16_t port = 8884;
        std::string public_ip = "127.0.0.1";
    } udp;

    struct {
        std::vector<std::string> development_servers;
        std::vector<std::string> production_servers;
        std::vector<MacAddress> development_mac_addresses;
    } websocket;

    struct {
        bool enabled = false;
        std::string level = "info";
        std::string file_path;
    } logging;

    struct {
        uint32_t max_tools_count = 32;
        bool enabled = false;
    } mcp;

    bool debug = false;
};

// Statistics information
struct ServerStats {
    uint64_t total_connections = 0;
    uint64_t active_connections = 0;
    uint64_t mqtt_messages_received = 0;
    uint64_t mqtt_messages_sent = 0;
    uint64_t udp_packets_received = 0;
    uint64_t udp_packets_sent = 0;
    uint64_t websocket_messages_received = 0;
    uint64_t websocket_messages_sent = 0;
    uint64_t websocket_connections = 0;
    uint64_t websocket_disconnections = 0;
    uint64_t bytes_received = 0;
    uint64_t bytes_sent = 0;
    int64_t start_time = 0;
};

// Error information structure
struct ErrorInfo {
    int code;
    std::string message;
    std::string component;
    int64_t timestamp;
};

// Connection state enumeration
enum class ConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    AUTHENTICATING,
    AUTHENTICATED,
    CLOSING,
    ERROR
};

// MQTT packet type enumeration
enum class MQTTPacketType : uint8_t {
    CONNECT = 1,
    CONNACK = 2,
    PUBLISH = 3,
    PUBACK = 4,
    PUBREC = 5,
    PUBREL = 6,
    PUBCOMP = 7,
    SUBSCRIBE = 8,
    SUBACK = 9,
    UNSUBSCRIBE = 10,
    UNSUBACK = 11,
    PINGREQ = 12,
    PINGRESP = 13,
    DISCONNECT = 14
};

// WebSocket message type enumeration
enum class WebSocketMessageType {
    TEXT,
    BINARY,
    CLOSE,
    PING,
    PONG
};

// Log level enumeration
enum class LogLevel {
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
    FATAL
};

} // namespace xiaozhi
