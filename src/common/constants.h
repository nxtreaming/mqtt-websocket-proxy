#pragma once

#include <cstdint>

namespace xiaozhi {
namespace constants {

// MQTT protocol constants
constexpr uint8_t MQTT_PROTOCOL_LEVEL = 4;  // MQTT 3.1.1
constexpr const char* MQTT_PROTOCOL_NAME = "MQTT";
constexpr uint16_t MQTT_DEFAULT_PORT = 1883;
constexpr uint16_t MQTT_DEFAULT_KEEP_ALIVE = 60;
constexpr uint32_t MQTT_MAX_PAYLOAD_SIZE = 8192;
constexpr uint32_t MQTT_MAX_CLIENT_ID_LENGTH = 256;
constexpr uint32_t MQTT_MAX_TOPIC_LENGTH = 1024;

// UDP protocol constants
constexpr uint16_t UDP_DEFAULT_PORT = 8884;
constexpr uint32_t UDP_HEADER_SIZE = 16;
constexpr uint32_t UDP_MAX_PAYLOAD_SIZE = 1400;  // Avoid IP fragmentation
constexpr uint8_t UDP_PACKET_TYPE_AUDIO = 1;

// WebSocket constants
constexpr uint32_t WEBSOCKET_CONNECT_TIMEOUT_MS = 10000;  // 10 seconds
constexpr uint32_t WEBSOCKET_PING_INTERVAL_MS = 30000;    // 30 seconds
constexpr uint32_t WEBSOCKET_MAX_MESSAGE_SIZE = 1024 * 1024;  // 1MB

// Encryption constants
constexpr uint32_t AES_KEY_SIZE = 16;  // AES-128
constexpr uint32_t AES_BLOCK_SIZE = 16;
constexpr const char* DEFAULT_ENCRYPTION_METHOD = "aes-128-ctr";

// Connection management constants
constexpr uint32_t MAX_CONNECTIONS = 10000;
constexpr uint32_t CONNECTION_TIMEOUT_MS = 300000;  // 5 minutes
constexpr uint32_t KEEP_ALIVE_CHECK_INTERVAL_MS = 1000;  // 1 second
constexpr double HEARTBEAT_TIMEOUT_MULTIPLIER = 1.5;

// Buffer size constants
constexpr uint32_t TCP_BUFFER_SIZE = 8192;
constexpr uint32_t UDP_BUFFER_SIZE = 2048;
constexpr uint32_t JSON_BUFFER_SIZE = 4096;

// Retry and timeout constants
constexpr uint32_t MAX_RETRY_ATTEMPTS = 3;
constexpr uint32_t RETRY_DELAY_MS = 1000;
constexpr uint32_t WEBSOCKET_RECONNECT_DELAY_MS = 5000;

// Performance related constants
constexpr uint32_t MAX_PENDING_CONNECTIONS = 128;
constexpr uint32_t THREAD_POOL_SIZE = 4;
constexpr uint32_t EVENT_LOOP_TIMEOUT_MS = 100;

// MCP (Model Context Protocol) constants
constexpr uint32_t MCP_MAX_TOOLS_COUNT = 32;
constexpr uint32_t MCP_REQUEST_TIMEOUT_MS = 30000;  // 30 seconds
constexpr uint32_t MCP_INITIAL_REQUEST_ID = 10000;

// Audio related constants
constexpr uint32_t AUDIO_SAMPLE_RATE = 16000;  // 16kHz
constexpr uint8_t AUDIO_CHANNELS = 1;          // Mono
constexpr uint8_t AUDIO_BITS_PER_SAMPLE = 16; // 16-bit
constexpr uint32_t AUDIO_FRAME_SIZE = 320;     // 20ms at 16kHz
constexpr uint32_t AUDIO_BITRATE = 32000;      // 32kbps

// Note: Error codes are defined in error_codes.h to avoid Windows macro conflicts

// String constants
constexpr const char* DEFAULT_CONFIG_FILE = "config/gateway.json";
constexpr const char* DEFAULT_LOG_FILE = "logs/gateway.log";
constexpr const char* DEFAULT_PID_FILE = "/var/run/xiaozhi-mqtt-gateway.pid";

// Version information
#ifdef PROJECT_VERSION
    constexpr const char* VERSION_STRING = PROJECT_VERSION;
#else
    constexpr const char* VERSION_STRING = "1.0.0";
#endif
constexpr const char* BUILD_DATE = __DATE__;
constexpr const char* BUILD_TIME = __TIME__;

// Regular expression patterns
constexpr const char* MAC_ADDRESS_PATTERN = "^[0-9a-f]{2}(:[0-9a-f]{2}){5}$";
constexpr const char* CLIENT_ID_PATTERN = "^[A-Za-z0-9_@-]+$";
constexpr const char* TOPIC_PATTERN = "^[^#+\\0]+$";

// HTTP status codes
constexpr int HTTP_OK = 200;
constexpr int HTTP_BAD_REQUEST = 400;
constexpr int HTTP_UNAUTHORIZED = 401;
constexpr int HTTP_FORBIDDEN = 403;
constexpr int HTTP_NOT_FOUND = 404;
constexpr int HTTP_INTERNAL_SERVER_ERROR = 500;
constexpr int HTTP_SERVICE_UNAVAILABLE = 503;

// WebSocket close codes
constexpr uint16_t WS_CLOSE_NORMAL = 1000;
constexpr uint16_t WS_CLOSE_GOING_AWAY = 1001;
constexpr uint16_t WS_CLOSE_PROTOCOL_ERROR = 1002;
constexpr uint16_t WS_CLOSE_UNSUPPORTED_DATA = 1003;
constexpr uint16_t WS_CLOSE_INVALID_FRAME_PAYLOAD_DATA = 1007;
constexpr uint16_t WS_CLOSE_POLICY_VIOLATION = 1008;
constexpr uint16_t WS_CLOSE_MESSAGE_TOO_BIG = 1009;
constexpr uint16_t WS_CLOSE_INTERNAL_SERVER_ERROR = 1011;

// Environment variable names
constexpr const char* ENV_MQTT_PORT = "MQTT_PORT";
constexpr const char* ENV_UDP_PORT = "UDP_PORT";
constexpr const char* ENV_PUBLIC_IP = "PUBLIC_IP";
constexpr const char* ENV_CONFIG_FILE = "CONFIG_FILE";
constexpr const char* ENV_LOG_LEVEL = "LOG_LEVEL";
constexpr const char* ENV_DEBUG = "DEBUG";

// Default values
constexpr const char* DEFAULT_PUBLIC_IP = "127.0.0.1";
constexpr const char* DEFAULT_WEBSOCKET_SERVER = "wss://chat.xiaozhi.me/ws";
constexpr const char* DEFAULT_LOG_LEVEL = "info";

} // namespace constants
} // namespace xiaozhi
