#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libwebsockets.h>
#include <stdarg.h>
#include "cjson/cJSON.h"
#include "ws_send_msg.h"

static cJSON* create_base_message(connection_state_t* conn_state, const char* type) {
    if (!conn_state || strlen(conn_state->session_id) == 0) {
        fprintf(stderr, "Error: Cannot create message, session_id is missing.\n");
        return NULL;
    }
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        fprintf(stderr, "Error: Failed to create JSON object\n");
        return NULL;
    }
    cJSON_AddStringToObject(root, "session_id", conn_state->session_id);
    if (type) {
        cJSON_AddStringToObject(root, "type", type);
    }
    return root;
}

// Internal function to send text messages immediately
static int send_text_message_immediate(struct lws* wsi, connection_state_t* conn_state,
                                     const char* message, size_t message_len) {
    // Allocate temporary buffer with LWS_PRE space
    size_t buffer_size = LWS_PRE + message_len + 1; // +1 for null terminator
    unsigned char* temp_buffer = malloc(buffer_size);
    if (!temp_buffer) {
        fprintf(stderr, "Error: Failed to allocate temporary buffer for immediate text send\n");
        return -1;
    }

    // Copy message to buffer with LWS_PRE offset
    memcpy(temp_buffer + LWS_PRE, message, message_len);
    temp_buffer[LWS_PRE + message_len] = '\0'; // Null terminate for safety

    // Log the message we're about to send
    char preview[41] = {0};
    size_t copy_len = message_len < 37 ? message_len : 37;
    strncpy(preview, message, copy_len);
    if (message_len > 37) {
        strcpy(preview + copy_len, "...");
    }
    fprintf(stdout, "Sending WebSocket text frame immediately (%u bytes): %s\n",
            (unsigned int)message_len, preview);

    // Send immediately using lws_write
    int write_result = lws_write(wsi, temp_buffer + LWS_PRE, message_len, LWS_WRITE_TEXT);

    // Clean up temporary buffer
    free(temp_buffer);

    if (write_result < 0) {
        fprintf(stderr, "Error %d writing text message to WebSocket\n", write_result);
        return -1;
    } else if (write_result != (int)message_len) {
        fprintf(stderr, "Partial text write: %d of %zu bytes written\n", write_result, message_len);
        return -1;
    }

    fprintf(stdout, "Text message sent immediately (%zu bytes)\n", message_len);
    return 0;
}

static int send_json_object(struct lws* wsi, connection_state_t* conn_state, cJSON* root) {
    if (!wsi || !conn_state || !root) {
        fprintf(stderr, "Error: Invalid parameters for send_json_object\n");
        if (root) cJSON_Delete(root);
        return -1;
    }

    char* json_str = cJSON_PrintUnformatted(root);
    if (!json_str) {
        fprintf(stderr, "Error: Failed to convert JSON to string\n");
        cJSON_Delete(root);
        return -1;
    }

    // Text messages (JSON) are now sent immediately, no need to handle -2
    int result = send_ws_message(wsi, conn_state, json_str, strlen(json_str), 0);

    free(json_str);
    cJSON_Delete(root);

    return result;
}

int send_ws_message(struct lws* wsi, connection_state_t* conn_state,
                   const char* message, size_t message_len, int is_binary) {
    if (!wsi || !conn_state || !message) {
        fprintf(stderr, "Error: Invalid parameters for send_ws_message\n");
        return -1;
    }

    if (message_len > sizeof(conn_state->write_buf) - LWS_PRE) {
        fprintf(stderr, "Error: Message too large (%zu bytes) for send buffer\n", message_len);
        return -1;
    }

    // For text messages (JSON control commands), try to send immediately
    if (!is_binary) {
        return send_text_message_immediate(wsi, conn_state, message, message_len);
    }

    // For binary messages (audio data), use buffered approach to prevent corruption
    // Check if there's already a pending write to prevent message corruption
    if (conn_state->pending_write) {
        fprintf(stderr, "Warning: Previous binary message still pending, dropping new message to prevent corruption\n");
        return -2; // Return different error code to indicate message dropped
    }

    memcpy(conn_state->write_buf + LWS_PRE, message, message_len);
    conn_state->write_len = message_len;
    conn_state->write_is_binary = is_binary;
    conn_state->pending_write = 1;

    // Log binary frames if they're large (text frames are logged in send_text_message_immediate)
    if (message_len > 1024) {
        // Only log binary frames if they're large
        fprintf(stdout, "Sending WebSocket binary frame (%u bytes)\n", (unsigned int)message_len);
    }

    lws_callback_on_writable(wsi);
    
    // Immediately wake up the service thread to process the pending write
    if (g_context) {
        lws_cancel_service(g_context);
    }

    return 0;
}

int send_mcp_response(struct lws* wsi, connection_state_t* conn_state, int rpc_id, cJSON* result) {
    cJSON *root = create_base_message(conn_state, "mcp");
    if (!root) {
        cJSON_Delete(result);
        return -1;
    }

    cJSON *payload = cJSON_CreateObject();
    if (!payload) {
        cJSON_Delete(root);
        cJSON_Delete(result);
        return -1;
    }

    cJSON_AddStringToObject(payload, "jsonrpc", "2.0");
    cJSON_AddNumberToObject(payload, "id", rpc_id);
    cJSON_AddItemToObject(payload, "result", result); // Transfer ownership of result

    cJSON_AddItemToObject(root, "payload", payload);

    return send_json_object(wsi, conn_state, root);
}

int send_stop_listening_message(struct lws *wsi, connection_state_t *conn_state) {
    fprintf(stdout, "Sending stop listening message\n");

    cJSON *root = create_base_message(conn_state, "listen");
    if (!root) return -1;

    cJSON_AddStringToObject(root, "state", "stop");

    int result = send_json_object(wsi, conn_state, root);
    if (result == 0) {
        conn_state->listen_stopped = 1;
    }
    return result;
}

int send_detect_message(struct lws *wsi, connection_state_t *conn_state, const char *text) {
    if (!text) {
        fprintf(stderr, "Error: Invalid text for send_detect_message\n");
        return -1;
    }
    fprintf(stdout, "Sending detect message with text: %s\n", text);

    cJSON *root = create_base_message(conn_state, "listen");
    if (!root) return -1;

    cJSON_AddStringToObject(root, "state", "detect");
    cJSON_AddStringToObject(root, "text", text);

    return send_json_object(wsi, conn_state, root);
}

int send_chat_message(struct lws *wsi, connection_state_t *conn_state, const char *text) {
    if (!text) {
        fprintf(stderr, "Error: Invalid text for send_chat_message\n");
        return -1;
    }
    fprintf(stdout, "Sending text message for TTS: %s\n", text);

    cJSON *root = create_base_message(conn_state, "listen");
    if (!root) return -1;

    cJSON_AddStringToObject(root, "mode", "manual");
    cJSON_AddStringToObject(root, "state", "detect");
    cJSON_AddStringToObject(root, "text", text);

    return send_json_object(wsi, conn_state, root);
}

int send_start_listening_message(struct lws *wsi, connection_state_t *conn_state) {
    // Allow sending listen message if we're in authenticated or listening state
    // This handles cases where server sends duplicate hello messages
    if (conn_state->current_state != WS_STATE_AUTHENTICATED && 
        conn_state->current_state != WS_STATE_LISTENING) {
        fprintf(stderr, "Error: Cannot send listen message in current state: %s\n", 
               websocket_state_to_string(conn_state->current_state));
        return -1;
    }

    fprintf(stdout, "Sending 'listen' message (state: start).\n");

    cJSON *root = create_base_message(conn_state, "listen");
    if (!root) return -1;

    cJSON_AddStringToObject(root, "state", "start");

    // Add audio parameters
    cJSON *audio_params = cJSON_CreateObject();
    if (!audio_params) {
        cJSON_Delete(root);
        return -1;
    }
    cJSON_AddStringToObject(audio_params, "format", conn_state->audio_params.format);
    cJSON_AddNumberToObject(audio_params, "sample_rate", conn_state->audio_params.sample_rate);
    cJSON_AddNumberToObject(audio_params, "channels", conn_state->audio_params.channels);
    cJSON_AddNumberToObject(audio_params, "frame_duration", conn_state->audio_params.frame_duration);
    cJSON_AddItemToObject(root, "audio_params", audio_params);

    int result = send_json_object(wsi, conn_state, root);
    if (result == 0) {
        fprintf(stdout, "Listen message sent successfully\n");
    }
    return result;
}

int send_abort_message_with_reason(struct lws* wsi, connection_state_t* conn_state, const char* reason) {
    if (!wsi || !conn_state || strlen(conn_state->session_id) == 0) {
        fprintf(stderr, "Error: Invalid parameters or missing session_id for send_abort_message\n");
        return -1;
    }

    fprintf(stdout, "Sending 'abort' message%s%s.\n",
        reason ? " with reason: " : "",
        reason ? reason : "");

    cJSON* root = create_base_message(conn_state, "abort");
    if (!root) {
        return -1;
    }

    if (reason && strlen(reason) > 0) {
        cJSON_AddStringToObject(root, "reason", reason);
    }

    return send_json_object(wsi, conn_state, root);
}

int send_mcp_message(struct lws *wsi, connection_state_t *conn_state, const char *payload) {
    if (!payload) {
        fprintf(stderr, "Error: Invalid payload for send_mcp_message\n");
        return -1;
    }
    fprintf(stdout, "Sending MCP message with payload: %s\n", payload);

    cJSON *root = create_base_message(conn_state, "mcp");
    if (!root) return -1;

    cJSON *payload_json = cJSON_Parse(payload);
    if (!payload_json) {
        fprintf(stderr, "Error: Failed to parse MCP payload JSON: %s\n", cJSON_GetErrorPtr());
        cJSON_Delete(root);
        return -1;
    }

    cJSON_AddItemToObject(root, "payload", payload_json);

    return send_json_object(wsi, conn_state, root);
}

void init_connection_state(connection_state_t *conn_state) {
    if (!conn_state) return;

    memset(conn_state, 0, sizeof(connection_state_t));
    conn_state->current_state = WS_STATE_DISCONNECTED;
    conn_state->previous_state = WS_STATE_DISCONNECTED;

    // Set default audio parameters
    strncpy(conn_state->audio_params.format, "opus", sizeof(conn_state->audio_params.format) - 1);
    conn_state->audio_params.sample_rate = 16000;
    conn_state->audio_params.channels = 1;
    conn_state->audio_params.frame_duration = 60;

    // Initialize protocol compliance tracking
    conn_state->protocol_version = 1;
    conn_state->features_mcp = 1;
    conn_state->features_stt = 1;
    conn_state->features_tts = 1;
    conn_state->features_llm = 1;

    // Initialize reconnection settings with default values
    conn_state->reconnection_enabled = 1;  // Enable by default
    conn_state->max_reconnection_attempts = 5;  // Default: 5 attempts
    conn_state->initial_reconnection_delay = 1000;  // Default: 1 second
    conn_state->max_reconnection_delay = 30000;  // Default: 30 seconds
    conn_state->backoff_multiplier = 2.0;  // Default: exponential backoff
    conn_state->reconnection_delay = conn_state->initial_reconnection_delay;

    // Initialize audio playback settings
    conn_state->audio_timeout_seconds = 120;  // Default: 2 minutes timeout
}

int change_websocket_state(connection_state_t *conn_state, websocket_state_t new_state) {
    if (!conn_state) return -1;
    
    if (!is_valid_state_transition(conn_state->current_state, new_state)) {
        fprintf(stderr, "Invalid state transition from %s to %s\n", 
                websocket_state_to_string(conn_state->current_state),
                websocket_state_to_string(new_state));
        return -1;
    }
    
    conn_state->previous_state = conn_state->current_state;
    conn_state->current_state = new_state;
    
    fprintf(stdout, "State changed: %s -> %s\n", 
            websocket_state_to_string(conn_state->previous_state),
            websocket_state_to_string(conn_state->current_state));
    
    return 0;
}

const char* websocket_state_to_string(websocket_state_t state) {
    switch (state) {
        case WS_STATE_DISCONNECTED: return "DISCONNECTED";
        case WS_STATE_CONNECTING: return "CONNECTING";
        case WS_STATE_CONNECTED: return "CONNECTED";
        case WS_STATE_HELLO_SENT: return "HELLO_SENT";
        case WS_STATE_AUTHENTICATED: return "AUTHENTICATED";
        case WS_STATE_LISTENING: return "LISTENING";
        case WS_STATE_SPEAKING: return "SPEAKING";
        case WS_STATE_ERROR: return "ERROR";
        case WS_STATE_CLOSING: return "CLOSING";
        default: return "UNKNOWN";
    }
}

int is_valid_state_transition(websocket_state_t from_state, websocket_state_t to_state) {
    // Define valid state transitions based on the WebSocket protocol
    switch (from_state) {
        case WS_STATE_DISCONNECTED:
            return (to_state == WS_STATE_CONNECTING || to_state == WS_STATE_CONNECTED);
            
        case WS_STATE_CONNECTING:
            return (to_state == WS_STATE_CONNECTED || 
                    to_state == WS_STATE_ERROR || 
                    to_state == WS_STATE_DISCONNECTED);
            
        case WS_STATE_CONNECTED:
            return (to_state == WS_STATE_HELLO_SENT ||
                    to_state == WS_STATE_ERROR ||
                    to_state == WS_STATE_CLOSING ||
                    to_state == WS_STATE_DISCONNECTED);
            
        case WS_STATE_HELLO_SENT:
            return (to_state == WS_STATE_AUTHENTICATED ||
                    to_state == WS_STATE_ERROR ||
                    to_state == WS_STATE_CLOSING ||
                    to_state == WS_STATE_DISCONNECTED);

        case WS_STATE_AUTHENTICATED:
            return (to_state == WS_STATE_LISTENING ||
                    to_state == WS_STATE_SPEAKING ||
                    to_state == WS_STATE_ERROR ||
                    to_state == WS_STATE_CLOSING ||
                    to_state == WS_STATE_DISCONNECTED);

        case WS_STATE_LISTENING:
            return (to_state == WS_STATE_SPEAKING ||
                    to_state == WS_STATE_AUTHENTICATED ||
                    to_state == WS_STATE_ERROR ||
                    to_state == WS_STATE_CLOSING ||
                    to_state == WS_STATE_DISCONNECTED);

        case WS_STATE_SPEAKING:
            return (to_state == WS_STATE_LISTENING ||
                    to_state == WS_STATE_AUTHENTICATED ||
                    to_state == WS_STATE_ERROR ||
                    to_state == WS_STATE_CLOSING ||
                    to_state == WS_STATE_DISCONNECTED);
            
        case WS_STATE_ERROR:
            return (to_state == WS_STATE_CLOSING || 
                    to_state == WS_STATE_DISCONNECTED);
            
        case WS_STATE_CLOSING:
            return (to_state == WS_STATE_DISCONNECTED);
            
        default:
            return 0; // Invalid from_state
    }
}

// Reconnection management functions
void set_reconnection_policy(connection_state_t *conn_state, int enable, int max_attempts,
                           int initial_delay, int max_delay, double backoff_multiplier) {
    if (!conn_state) return;

    conn_state->reconnection_enabled = enable;
    conn_state->max_reconnection_attempts = max_attempts;
    conn_state->initial_reconnection_delay = initial_delay;
    conn_state->max_reconnection_delay = max_delay;
    conn_state->backoff_multiplier = backoff_multiplier;
    conn_state->reconnection_delay = initial_delay;

    fprintf(stdout, "Reconnection policy set: enabled=%s, max_attempts=%d, initial_delay=%dms, max_delay=%dms, backoff=%.1f\n",
            enable ? "true" : "false", max_attempts, initial_delay, max_delay, backoff_multiplier);
}

int should_attempt_reconnection(connection_state_t *conn_state) {
    if (!conn_state || !conn_state->reconnection_enabled) {
        return 0;
    }

    // Check if we've exceeded maximum attempts (0 means unlimited)
    if (conn_state->max_reconnection_attempts > 0 &&
        conn_state->reconnection_attempts >= conn_state->max_reconnection_attempts) {
        fprintf(stderr, "Maximum reconnection attempts (%d) reached\n", conn_state->max_reconnection_attempts);
        return 0;
    }

    return 1;
}

int calculate_reconnection_delay(connection_state_t *conn_state) {
    if (!conn_state) return 1000;

    // Calculate next delay using exponential backoff
    int next_delay = (int)(conn_state->reconnection_delay * conn_state->backoff_multiplier);

    // Cap at maximum delay
    if (next_delay > conn_state->max_reconnection_delay) {
        next_delay = conn_state->max_reconnection_delay;
    }

    conn_state->reconnection_delay = next_delay;
    return next_delay;
}

void reset_reconnection_state(connection_state_t *conn_state) {
    if (!conn_state) return;

    conn_state->reconnection_attempts = 0;
    conn_state->reconnection_delay = conn_state->initial_reconnection_delay;
    conn_state->connection_lost = 0;

    fprintf(stdout, "Reconnection state reset after successful connection\n");
}

// Audio playback management functions
void set_audio_timeout(connection_state_t *conn_state, int timeout_seconds) {
    if (!conn_state) return;

    conn_state->audio_timeout_seconds = timeout_seconds;
    fprintf(stdout, "Audio timeout set to %d seconds\n", timeout_seconds);
}

void start_audio_playback(connection_state_t *conn_state) {
    if (!conn_state) return;

    conn_state->audio_playing = 1;
    conn_state->audio_start_time = time(NULL);
    conn_state->audio_interrupted = 0;

    fprintf(stdout, "Audio playback started at %ld\n", (long)conn_state->audio_start_time);
}

void stop_audio_playback(connection_state_t *conn_state) {
    if (!conn_state) return;

    if (conn_state->audio_playing) {
        time_t duration = time(NULL) - conn_state->audio_start_time;
        fprintf(stdout, "Audio playback stopped after %ld seconds\n", (long)duration);
    }

    conn_state->audio_playing = 0;
    conn_state->audio_start_time = 0;
    conn_state->audio_interrupted = 0;
}

int is_audio_playback_timeout(connection_state_t *conn_state) {
    if (!conn_state || !conn_state->audio_playing || conn_state->audio_timeout_seconds <= 0) {
        return 0;
    }

    time_t current_time = time(NULL);
    time_t elapsed = current_time - conn_state->audio_start_time;

    if (elapsed >= conn_state->audio_timeout_seconds) {
        fprintf(stderr, "Audio playback timeout: %ld seconds elapsed (limit: %d)\n",
                (long)elapsed, conn_state->audio_timeout_seconds);
        return 1;
    }

    return 0;
}

void interrupt_audio_playback(connection_state_t *conn_state) {
    if (!conn_state) return;

    if (conn_state->audio_playing) {
        conn_state->audio_interrupted = 1;
        fprintf(stdout, "Audio playback interrupted by user\n");
    }
}
