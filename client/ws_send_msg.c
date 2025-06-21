#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libwebsockets.h>
#include <stdarg.h>
#include "cjson/cJSON.h"
#include "ws_send_msg.h"

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

int send_json_message(struct lws* wsi, connection_state_t* conn_state, const char* format, ...) {
    if (!wsi || !conn_state || !format) {
        fprintf(stderr, "Error: Invalid parameters for send_json_message\n");
        return -1;
    }

    va_list args;
    va_start(args, format);

    int msg_len = vsnprintf(NULL, 0, format, args);
    va_end(args);

    if (msg_len <= 0 || (size_t)msg_len >= sizeof(conn_state->write_buf) - LWS_PRE - 1) {
        fprintf(stderr, "Error: Message formatting failed or message too long\n");
        return -1;
    }

    va_start(args, format);
    vsnprintf((char*)(conn_state->write_buf + LWS_PRE), sizeof(conn_state->write_buf) - LWS_PRE - 1, format, args);
    va_end(args);

    return send_ws_message(wsi, conn_state, (const char*)(conn_state->write_buf + LWS_PRE), (size_t)msg_len, 0);
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
    if (!wsi || !conn_state || strlen(conn_state->session_id) == 0) {
        fprintf(stderr, "Error: Invalid parameters or missing session_id for send_stop_listening_message\n");
        return -1;
    }
    
    fprintf(stdout, "Sending stop listening message\n");
    
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        fprintf(stderr, "Error: Failed to create JSON object\n");
        return -1;
    }
    
    cJSON_AddStringToObject(root, "session_id", conn_state->session_id);
    cJSON_AddStringToObject(root, "type", "listen");
    cJSON_AddStringToObject(root, "state", "stop");
    
    int result = send_json_object(wsi, conn_state, root);
    
    if (result == 0) {
        conn_state->listen_stopped = 1;
    }
    
    return result;
}

int send_detect_message(struct lws *wsi, connection_state_t *conn_state, const char *text) {
    if (!wsi || !conn_state || !text || strlen(conn_state->session_id) == 0) {
        fprintf(stderr, "Error: Invalid parameters or missing session_id for send_detect_message\n");
        return -1;
    }
    
    fprintf(stdout, "Sending detect message with text: %s\n", text);
    
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        fprintf(stderr, "Error: Failed to create JSON object\n");
        return -1;
    }
    
    cJSON_AddStringToObject(root, "session_id", conn_state->session_id);
    cJSON_AddStringToObject(root, "type", "listen");
    cJSON_AddStringToObject(root, "state", "detect");
    cJSON_AddStringToObject(root, "text", text);
    
    return send_json_object(wsi, conn_state, root);
}

int send_chat_message(struct lws *wsi, connection_state_t *conn_state, const char *text) {
    if (!wsi || !conn_state || !text || strlen(conn_state->session_id) == 0) {
        fprintf(stderr, "Error: Invalid parameters or missing session_id for send_chat_message\n");
        return -1;
    }
    
    fprintf(stdout, "Sending text message for TTS: %s\n", text);
    
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        fprintf(stderr, "Error: Failed to create JSON object\n");
        return -1;
    }
    
    cJSON_AddStringToObject(root, "session_id", conn_state->session_id);
    cJSON_AddStringToObject(root, "type", "listen");
    cJSON_AddStringToObject(root, "mode", "manual");
    cJSON_AddStringToObject(root, "state", "detect");
    cJSON_AddStringToObject(root, "text", text);
    
    return send_json_object(wsi, conn_state, root);
}

int send_start_listening_message(struct lws *wsi, connection_state_t *conn_state) {
    if (!wsi || !conn_state) {
        fprintf(stderr, "Error: Invalid parameters for send_start_listening_message\n");
        return -1;
    }

    if (strlen(conn_state->session_id) == 0) {
        fprintf(stderr, "Error: Cannot send listen message, session_id is missing.\n");
        return -1;
    }

    if (conn_state->listen_sent) {
        fprintf(stderr, "Error: Start listening message already sent, cannot send again.\n");
        return -1;
    }

    fprintf(stdout, "Sending 'listen' message (state: start).\n");

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        fprintf(stderr, "Error: Failed to create JSON object\n");
        return -1;
    }
    
    cJSON_AddStringToObject(root, "session_id", conn_state->session_id);
    cJSON_AddStringToObject(root, "type", "listen");
    cJSON_AddStringToObject(root, "mode", "manual");
    cJSON_AddStringToObject(root, "state", "start");
    
    int result = send_json_object(wsi, conn_state, root);
    
    if (result == 0) {
        conn_state->listen_sent = 1;
        conn_state->listen_sent_time = time(NULL);
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

    cJSON* root = cJSON_CreateObject();
    if (!root) {
        fprintf(stderr, "Error: Failed to create JSON object\n");
        return -1;
    }

    cJSON_AddStringToObject(root, "session_id", conn_state->session_id);
    cJSON_AddStringToObject(root, "type", "abort");

    if (reason && strlen(reason) > 0) {
        cJSON_AddStringToObject(root, "reason", reason);
    }

    return send_json_object(wsi, conn_state, root);
}

int send_mcp_message(struct lws* wsi, connection_state_t* conn_state, const char* payload) {
    if (!wsi || !conn_state || !payload || strlen(conn_state->session_id) == 0) {
        fprintf(stderr, "Error: Invalid parameters or missing session_id for send_mcp_message\n");
        return -1;
    }

    fprintf(stdout, "Sending 'mcp' message with payload.\n");

    cJSON* root = cJSON_CreateObject();
    if (!root) {
        fprintf(stderr, "Error: Failed to create JSON object\n");
        return -1;
    }

    cJSON_AddStringToObject(root, "session_id", conn_state->session_id);
    cJSON_AddStringToObject(root, "type", "mcp");

    cJSON* payload_json = cJSON_Parse(payload);
    if (!payload_json) {
        fprintf(stderr, "Error: Failed to parse payload JSON\n");
        cJSON_Delete(root);
        return -1;
    }

    cJSON_AddItemToObject(root, "payload", payload_json);

    return send_json_object(wsi, conn_state, root);
}
