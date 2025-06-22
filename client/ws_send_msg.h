#ifndef WS_SEND_MSG_H
#define WS_SEND_MSG_H

#include <stdio.h>
#include <stddef.h>
#include "cjson/cJSON.h"
#include <stdlib.h>
#include <libwebsockets.h>
#include <time.h>

// Audio parameters structure
typedef struct {
    char format[32];           // Audio format (e.g., "opus")
    int sample_rate;           // Sample rate in Hz (e.g., 16000, 24000)
    int channels;              // Number of audio channels (e.g., 1, 2)
    int frame_duration;        // Frame duration in ms (e.g., 60)
} audio_params_t;

// WebSocket client state enumeration
typedef enum {
    WS_STATE_DISCONNECTED = 0,  // Initial state, not connected
    WS_STATE_CONNECTING,        // WebSocket connection in progress
    WS_STATE_CONNECTED,         // WebSocket connected, waiting for hello exchange
    WS_STATE_HELLO_SENT,        // Client hello sent, waiting for server hello
    WS_STATE_AUTHENTICATED,     // Hello exchange complete, ready for operations
    WS_STATE_LISTENING,         // In listening mode (audio streaming)
    WS_STATE_SPEAKING,          // Speaking/processing mode
    WS_STATE_ERROR,             // Error state
    WS_STATE_CLOSING            // Connection closing
} websocket_state_t;

// Connection state structure
typedef struct {
    // Formal state machine
    websocket_state_t current_state;
    websocket_state_t previous_state;
    
    // Connection state (legacy - kept for compatibility)
    int connected;
    int hello_sent;
    int server_hello_received;
    int listen_sent;
    int listen_stopped;
    time_t listen_sent_time;
    time_t last_activity;       // Timestamp of last activity (for keep-alive)
    
    // Message state
    int pending_write;
    size_t write_len;
    int write_is_binary;
    unsigned char write_buf[LWS_PRE + 4096];  // Buffer for outgoing messages
    
    // Session information
    char session_id[64];  // Store session ID from server hello
    char stt_text[1024];  // Store STT recognized text
    
    // Connection control
    int should_close;        // Flag to indicate connection should be closed
    int interactive_mode;    // Flag to indicate interactive mode is active
    int should_send_abort;   // Flag to indicate abort message should be sent
    
    audio_params_t audio_params; // Audio parameters
    // Timeout handling
    time_t hello_sent_time;
    
    // Protocol compliance tracking
    int protocol_version;    // Protocol version from server
    int features_mcp;        // MCP feature support
    int features_stt;        // STT feature support
    int features_tts;        // TTS feature support
    int features_llm;        // LLM feature support
} connection_state_t;

// External reference to global context for immediate service wakeup
extern struct lws_context* g_context;

/**
 * Send a WebSocket message (text or binary)
 * 
 * @param wsi WebSocket instance
 * @param conn_state Connection state
 * @param message Message content
 * @param message_len Message length
 * @param is_binary 1 for binary message, 0 for text message
 * @return 0 on success, -1 on failure
 */
int send_ws_message(struct lws* wsi, connection_state_t* conn_state, const char* message, size_t message_len, int is_binary);

/**
 * Send a JSON message over WebSocket
 * 
 * @param wsi WebSocket instance
 * @param conn_state Connection state
 * @param format Format string (printf-style)
 * @param ... Variable arguments for format string
 * @return 0 on success, -1 on failure
 */
int send_mcp_response(struct lws* wsi, connection_state_t* conn_state, int rpc_id, cJSON* result);

/**
 * Send a binary frame over WebSocket
 * 
 * @param wsi WebSocket instance
 * @param conn_state Connection state
 * @param frame_size Size of the binary frame to send
 * @return 0 on success, -1 on failure
 */
int send_binary_frame(struct lws *wsi, connection_state_t *conn_state, size_t frame_size);

/**
 * Send a stop listening message over WebSocket
 * 
 * @param wsi WebSocket instance
 * @param conn_state Connection state
 * @return 0 on success, -1 on failure
 */
int send_stop_listening_message(struct lws *wsi, connection_state_t *conn_state);

/**
 * Send a detect message over WebSocket
 * 
 * @param wsi WebSocket instance
 * @param conn_state Connection state
 * @param text Text to detect
 * @return 0 on success, -1 on failure
 */
int send_detect_message(struct lws *wsi, connection_state_t *conn_state, const char *text);

/**
 * Send a chat message over WebSocket
 * 
 * @param wsi WebSocket instance
 * @param conn_state Connection state
 * @param text Chat text
 * @return 0 on success, -1 on failure
 */
int send_chat_message(struct lws *wsi, connection_state_t *conn_state, const char *text);

/**
 * Send a start listening message over WebSocket
 * 
 * @param wsi WebSocket instance
 * @param conn_state Connection state
 * @return 0 on success, -1 on failure
 */
int send_start_listening_message(struct lws *wsi, connection_state_t *conn_state);

/**
 * @brief Send an abort message with an optional reason
 * @param wsi WebSocket instance
 * @param conn_state Connection state
 * @param reason Optional reason for abort (can be NULL)
 * @return 0 on success, -1 on failure
 */
int send_abort_message_with_reason(struct lws *wsi, connection_state_t *conn_state, const char *reason);

/**
 * @brief Send an MCP message with a JSON-RPC payload
 * @param wsi WebSocket instance
 * @param conn_state Connection state
 * @param payload JSON-RPC payload as a string
 * @return 0 on success, -1 on failure
 */
int send_mcp_message(struct lws *wsi, connection_state_t *conn_state, const char *payload);

/**
 * State management functions
 */

/**
 * Initialize connection state structure
 * @param conn_state Connection state to initialize
 */
void init_connection_state(connection_state_t *conn_state);

/**
 * Change WebSocket client state
 * @param conn_state Connection state
 * @param new_state New state to transition to
 * @return 0 on success, -1 if transition is invalid
 */
int change_websocket_state(connection_state_t *conn_state, websocket_state_t new_state);

/**
 * Get current state as string for logging
 * @param state State enumeration value
 * @return String representation of state
 */
const char* websocket_state_to_string(websocket_state_t state);

/**
 * Check if state transition is valid
 * @param from_state Current state
 * @param to_state Target state
 * @return 1 if valid, 0 if invalid
 */
int is_valid_state_transition(websocket_state_t from_state, websocket_state_t to_state);

#endif // WS_SEND_MSG_H
