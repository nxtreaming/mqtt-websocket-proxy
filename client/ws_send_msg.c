#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libwebsockets.h>
#include <stdarg.h>
#include "cjson/cJSON.h"
#include "ws_send_msg.h"

// Helper function to create a base JSON message with session_id and type.
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

// Helper function to send a cJSON object and handle cleanup.
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
    
    memcpy(conn_state->write_buf + LWS_PRE, message, message_len);
    if (!is_binary && message_len < sizeof(conn_state->write_buf) - LWS_PRE - 1) {
        conn_state->write_buf[LWS_PRE + message_len] = '\0';
    }

    conn_state->write_len = message_len;
    conn_state->write_is_binary = is_binary;
    conn_state->pending_write = 1;

    if (!is_binary) {
        fprintf(stdout, "Sending WebSocket text frame (%u bytes): %s\n",
            (unsigned int)message_len, (const char*)(conn_state->write_buf + LWS_PRE));
    }
    else {
        fprintf(stdout, "Sending WebSocket binary frame (%u bytes)\n", (unsigned int)message_len);
    }

    lws_callback_on_writable(wsi);

    return 0;
}

int send_mcp_response(struct lws* wsi, connection_state_t* conn_state, int rpc_id, cJSON* result) {
    cJSON *root = create_base_message(conn_state, "mcp");
    if (!root) {
        cJSON_Delete(result); // Cleanup result object on failure
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

int send_binary_frame(struct lws *wsi, connection_state_t *conn_state, size_t frame_size) {
    if (!wsi || !conn_state || frame_size == 0 || frame_size > 4096) {
        fprintf(stderr, "Error: Invalid parameters for send_binary_frame\n");
        return -1;
    }
    
    unsigned char buffer[4096];
    for (size_t i = 0; i < frame_size; i++) {
        buffer[i] = (unsigned char)(i & 0xFF);
    }
    
    int result = send_ws_message(wsi, conn_state, (const char*)buffer, frame_size, 1);
    
    if (result == 0) {
        fprintf(stdout, "Sent binary frame (%zu bytes)\n", frame_size);
    }
    
    return result;
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
                    to_state == WS_STATE_CLOSING);
            
        case WS_STATE_HELLO_SENT:
            return (to_state == WS_STATE_AUTHENTICATED || 
                    to_state == WS_STATE_ERROR || 
                    to_state == WS_STATE_CLOSING);
            
        case WS_STATE_AUTHENTICATED:
            return (to_state == WS_STATE_LISTENING || 
                    to_state == WS_STATE_SPEAKING ||
                    to_state == WS_STATE_ERROR || 
                    to_state == WS_STATE_CLOSING);
            
        case WS_STATE_LISTENING:
            return (to_state == WS_STATE_SPEAKING || 
                    to_state == WS_STATE_AUTHENTICATED ||
                    to_state == WS_STATE_ERROR || 
                    to_state == WS_STATE_CLOSING);
            
        case WS_STATE_SPEAKING:
            return (to_state == WS_STATE_LISTENING || 
                    to_state == WS_STATE_AUTHENTICATED ||
                    to_state == WS_STATE_ERROR || 
                    to_state == WS_STATE_CLOSING);
            
        case WS_STATE_ERROR:
            return (to_state == WS_STATE_CLOSING || 
                    to_state == WS_STATE_DISCONNECTED);
            
        case WS_STATE_CLOSING:
            return (to_state == WS_STATE_DISCONNECTED);
            
        default:
            return 0; // Invalid from_state
    }
}
