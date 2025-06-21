#ifndef WS_SEND_MSG_H
#define WS_SEND_MSG_H

#include <stdio.h>
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

// Connection state structure
typedef struct {
    // Connection state
    int connected;
    int hello_sent;
    int server_hello_received;
    int listen_sent;
    int listen_stopped;
    time_t listen_sent_time;
    
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
} connection_state_t;

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
int send_json_message(struct lws* wsi, connection_state_t* conn_state, const char* format, ...);

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

#endif /* WS_SEND_MSG_H */
