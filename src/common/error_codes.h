#pragma once

#include <string>
#include <unordered_map>

namespace xiaozhi {
namespace error {

// Error code enumeration
enum Code {
    // Success
    SUCCESS = 0,

    // General errors (1-99)
    INVALID_PARAMETER = 1,
    OUT_OF_MEMORY = 2,
    INTERNAL_ERROR = 3,
    NOT_IMPLEMENTED = 4,
    OPERATION_FAILED = 5,
    TIMEOUT = 6,
    CANCELLED = 7,
    ALREADY_EXISTS = 8,
    NOT_FOUND = 9,
    PERMISSION_DENIED = 10,
    BUSY = 11,

    // Network errors (100-199)
    NETWORK_ERROR = 100,
    CONNECTION_FAILED = 101,
    CONNECTION_CLOSED = 102,
    CONNECTION_TIMEOUT = 103,
    BIND_FAILED = 104,
    LISTEN_FAILED = 105,
    ACCEPT_FAILED = 106,
    SEND_FAILED = 107,
    RECEIVE_FAILED = 108,
    SOCKET_OPERATION_ERROR = 109,
    DNS_RESOLUTION_FAILED = 110,

    // MQTT protocol errors (200-299)
    MQTT_PROTOCOL_ERROR = 200,
    MQTT_INVALID_PACKET = 201,
    MQTT_UNSUPPORTED_VERSION = 202,
    MQTT_UNSUPPORTED_PROTOCOL_VERSION = 203,
    MQTT_INVALID_PROTOCOL_NAME = 204,
    MQTT_INVALID_CLIENT_ID = 205,
    MQTT_AUTHENTICATION_FAILED = 206,
    MQTT_AUTHORIZATION_FAILED = 207,
    MQTT_SERVER_UNAVAILABLE = 208,
    MQTT_MALFORMED_PACKET = 209,
    MQTT_PACKET_TOO_LARGE = 210,
    MQTT_INVALID_TOPIC = 211,
    MQTT_QOS_NOT_SUPPORTED = 212,
    MQTT_KEEP_ALIVE_TIMEOUT = 213,

    // UDP protocol errors (300-399)
    UDP_PROTOCOL_ERROR = 300,
    UDP_INVALID_PACKET = 301,
    UDP_ENCRYPTION_FAILED = 302,
    UDP_DECRYPTION_FAILED = 303,
    UDP_INVALID_SEQUENCE = 304,
    UDP_PACKET_TOO_LARGE = 305,
    UDP_INVALID_HEADER = 306,
    UDP_CHECKSUM_ERROR = 307,

    // WebSocket errors (400-499)
    WEBSOCKET_ERROR = 400,
    WEBSOCKET_CONNECTION_FAILED = 401,
    WEBSOCKET_HANDSHAKE_FAILED = 402,
    WEBSOCKET_PROTOCOL_ERROR = 403,
    WEBSOCKET_INVALID_FRAME = 404,
    WEBSOCKET_MESSAGE_TOO_LARGE = 405,
    WEBSOCKET_CLOSE_TIMEOUT = 406,
    WEBSOCKET_SSL_ERROR = 407,

    // Configuration errors (500-599)
    CONFIG_ERROR = 500,
    CONFIG_FILE_NOT_FOUND = 501,
    CONFIG_PARSE_ERROR = 502,
    CONFIG_INVALID_VALUE = 503,
    CONFIG_MISSING_REQUIRED = 504,
    CONFIG_VALIDATION_FAILED = 505,

    // Encryption errors (600-699)
    CRYPTO_ERROR = 600,
    CRYPTO_INIT_FAILED = 601,
    CRYPTO_ENCRYPTION_FAILED = 602,
    CRYPTO_DECRYPTION_FAILED = 603,
    CRYPTO_KEY_GENERATION_FAILED = 604,
    CRYPTO_INVALID_KEY = 605,
    CRYPTO_INVALID_IV = 606,
    CRYPTO_ALGORITHM_NOT_SUPPORTED = 607,

    // JSON errors (700-799)
    JSON_ERROR = 700,
    JSON_PARSE_ERROR = 701,
    JSON_INVALID_FORMAT = 702,
    JSON_MISSING_FIELD = 703,
    JSON_TYPE_ERROR = 704,
    JSON_SERIALIZATION_ERROR = 705,

    // MCP errors (800-899)
    MCP_ERROR = 800,
    MCP_REQUEST_FAILED = 801,
    MCP_RESPONSE_TIMEOUT = 802,
    MCP_INVALID_REQUEST = 803,
    MCP_INVALID_RESPONSE = 804,
    MCP_TOOL_NOT_FOUND = 805,
    MCP_TOOL_EXECUTION_FAILED = 806,
    MCP_INITIALIZATION_FAILED = 807,

    // File system errors (900-999)
    FILE_ERROR = 900,
    FILE_NOT_FOUND = 901,
    FILE_PERMISSION_DENIED = 902,
    FILE_READ_ERROR = 903,
    FILE_WRITE_ERROR = 904,
    FILE_CREATE_ERROR = 905,
    FILE_DELETE_ERROR = 906,
    DIRECTORY_NOT_FOUND = 907,
    DIRECTORY_CREATE_ERROR = 908
};

// Error message mapping
inline const std::unordered_map<int, std::string>& GetErrorMessages() {
    static const std::unordered_map<int, std::string> error_messages = {
        // Success
        {SUCCESS, "Success"},

        // General errors
        {INVALID_PARAMETER, "Invalid parameter"},
        {BUSY, "Resource or operation is busy"},
        {OUT_OF_MEMORY, "Out of memory"},
        {INTERNAL_ERROR, "Internal error"},
        {NOT_IMPLEMENTED, "Not implemented"},
        {OPERATION_FAILED, "Operation failed"},
        {TIMEOUT, "Operation timeout"},
        {CANCELLED, "Operation cancelled"},
        {ALREADY_EXISTS, "Resource already exists"},
        {NOT_FOUND, "Resource not found"},
        {PERMISSION_DENIED, "Permission denied"},

        // Network errors
        {NETWORK_ERROR, "Network error"},
        {CONNECTION_FAILED, "Connection failed"},
        {CONNECTION_CLOSED, "Connection closed"},
        {CONNECTION_TIMEOUT, "Connection timeout"},
        {BIND_FAILED, "Socket bind failed"},
        {LISTEN_FAILED, "Socket listen failed"},
        {ACCEPT_FAILED, "Socket accept failed"},
        {SEND_FAILED, "Send data failed"},
        {RECEIVE_FAILED, "Receive data failed"},
        {SOCKET_OPERATION_ERROR, "Socket error"},
        {DNS_RESOLUTION_FAILED, "DNS resolution failed"},

        // MQTT protocol errors
        {MQTT_PROTOCOL_ERROR, "MQTT protocol error"},
        {MQTT_INVALID_PACKET, "Invalid MQTT packet"},
        {MQTT_UNSUPPORTED_VERSION, "Unsupported MQTT version"},
        {MQTT_UNSUPPORTED_PROTOCOL_VERSION, "Unsupported MQTT protocol version (expected: 4)"},
        {MQTT_INVALID_PROTOCOL_NAME, "Invalid MQTT protocol name (expected: MQTT)"},
        {MQTT_INVALID_CLIENT_ID, "Invalid MQTT client ID"},
        {MQTT_AUTHENTICATION_FAILED, "MQTT authentication failed"},
        {MQTT_AUTHORIZATION_FAILED, "MQTT authorization failed"},
        {MQTT_SERVER_UNAVAILABLE, "MQTT server unavailable"},
        {MQTT_MALFORMED_PACKET, "Malformed MQTT packet"},
        {MQTT_PACKET_TOO_LARGE, "MQTT packet too large"},
        {MQTT_INVALID_TOPIC, "Invalid MQTT topic"},
        {MQTT_QOS_NOT_SUPPORTED, "MQTT QoS not supported"},
        {MQTT_KEEP_ALIVE_TIMEOUT, "MQTT keep alive timeout"},

        // UDP protocol errors
        {UDP_PROTOCOL_ERROR, "UDP protocol error"},
        {UDP_INVALID_PACKET, "Invalid UDP packet"},
        {UDP_ENCRYPTION_FAILED, "UDP encryption failed"},
        {UDP_DECRYPTION_FAILED, "UDP decryption failed"},
        {UDP_INVALID_SEQUENCE, "Invalid UDP sequence number"},
        {UDP_PACKET_TOO_LARGE, "UDP packet too large"},
        {UDP_INVALID_HEADER, "Invalid UDP header"},
        {UDP_CHECKSUM_ERROR, "UDP checksum error"},

        // WebSocket errors
        {WEBSOCKET_ERROR, "WebSocket error"},
        {WEBSOCKET_CONNECTION_FAILED, "WebSocket connection failed"},
        {WEBSOCKET_HANDSHAKE_FAILED, "WebSocket handshake failed"},
        {WEBSOCKET_PROTOCOL_ERROR, "WebSocket protocol error"},
        {WEBSOCKET_INVALID_FRAME, "Invalid WebSocket frame"},
        {WEBSOCKET_MESSAGE_TOO_LARGE, "WebSocket message too large"},
        {WEBSOCKET_CLOSE_TIMEOUT, "WebSocket close timeout"},
        {WEBSOCKET_SSL_ERROR, "WebSocket SSL error"},
        
        // Configuration errors
        {CONFIG_ERROR, "Configuration error"},
        {CONFIG_FILE_NOT_FOUND, "Configuration file not found"},
        {CONFIG_PARSE_ERROR, "Configuration parse error"},
        {CONFIG_INVALID_VALUE, "Invalid configuration value"},
        {CONFIG_MISSING_REQUIRED, "Missing required configuration"},
        {CONFIG_VALIDATION_FAILED, "Configuration validation failed"},
        
        // Encryption errors
        {CRYPTO_ERROR, "Cryptography error"},
        {CRYPTO_INIT_FAILED, "Cryptography initialization failed"},
        {CRYPTO_ENCRYPTION_FAILED, "Encryption failed"},
        {CRYPTO_DECRYPTION_FAILED, "Decryption failed"},
        {CRYPTO_KEY_GENERATION_FAILED, "Key generation failed"},
        {CRYPTO_INVALID_KEY, "Invalid cryptographic key"},
        {CRYPTO_INVALID_IV, "Invalid initialization vector"},
        {CRYPTO_ALGORITHM_NOT_SUPPORTED, "Cryptographic algorithm not supported"},
        
        // JSON errors
        {JSON_ERROR, "JSON error"},
        {JSON_PARSE_ERROR, "JSON parse error"},
        {JSON_INVALID_FORMAT, "Invalid JSON format"},
        {JSON_MISSING_FIELD, "Missing JSON field"},
        {JSON_TYPE_ERROR, "JSON type error"},
        {JSON_SERIALIZATION_ERROR, "JSON serialization error"},
        
        // MCP errors
        {MCP_ERROR, "MCP error"},
        {MCP_REQUEST_FAILED, "MCP request failed"},
        {MCP_RESPONSE_TIMEOUT, "MCP response timeout"},
        {MCP_INVALID_REQUEST, "Invalid MCP request"},
        {MCP_INVALID_RESPONSE, "Invalid MCP response"},
        {MCP_TOOL_NOT_FOUND, "MCP tool not found"},
        {MCP_TOOL_EXECUTION_FAILED, "MCP tool execution failed"},
        {MCP_INITIALIZATION_FAILED, "MCP initialization failed"},
        
        // File system errors
        {FILE_ERROR, "File system error"},
        {FILE_NOT_FOUND, "File not found"},
        {FILE_PERMISSION_DENIED, "File permission denied"},
        {FILE_READ_ERROR, "File read error"},
        {FILE_WRITE_ERROR, "File write error"},
        {FILE_CREATE_ERROR, "File create error"},
        {FILE_DELETE_ERROR, "File delete error"},
        {DIRECTORY_NOT_FOUND, "Directory not found"},
        {DIRECTORY_CREATE_ERROR, "Directory create error"}
    };
    return error_messages;
}

// Get error message
inline std::string GetErrorMessage(int error_code) {
    const auto& messages = GetErrorMessages();
    auto it = messages.find(error_code);
    if (it != messages.end()) {
        return it->second;
    }
    return "Unknown error (code: " + std::to_string(error_code) + ")";
}

// Check if successful
inline bool IsSuccess(int error_code) {
    return error_code == SUCCESS;
}

// Check if network error
inline bool IsNetworkError(int error_code) {
    return error_code >= 100 && error_code < 200;
}

// Check if protocol error
inline bool IsProtocolError(int error_code) {
    return (error_code >= 200 && error_code < 500);
}

} // namespace error
} // namespace xiaozhi
