#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libwebsockets.h>
#include <stdarg.h>
#include "ws_send_msg.h"

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

    // Log the message we're about to send
    if (!is_binary) {
        fprintf(stdout, "Sending WebSocket text frame (%u bytes): %s\n",
            (unsigned int)message_len, (const char*)(conn_state->write_buf + LWS_PRE));
    }
    else {
        fprintf(stdout, "Sending WebSocket binary frame (%u bytes)\n", (unsigned int)message_len);
    }

    // Schedule the write
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

    // Format the message
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
    
    // Use a local buffer for binary data
    unsigned char buffer[4096];
    
    // Fill with some dummy data
    for (size_t i = 0; i < frame_size; i++) {
        buffer[i] = (unsigned char)(i & 0xFF);
    }
    
    // Send the binary frame
    int result = send_ws_message(wsi, conn_state, (const char*)buffer, frame_size, 1);
    
    if (result == 0) {
        fprintf(stdout, "Sent binary frame (%zu bytes)\n", frame_size);
    }
    
    return result;
}

int send_stop_listening_message(struct lws *wsi, connection_state_t *conn_state) {
    if (!wsi || !conn_state) {
        fprintf(stderr, "Error: Invalid parameters for send_stop_listening_message\n");
        return -1;
    }
    
    // Ensure we have a valid session_id
    if (strlen(conn_state->session_id) == 0) {
        fprintf(stderr, "Error: No session_id available for stop listening message\n");
        return -1;
    }
    
    fprintf(stdout, "Sending stop listening message\n");
    
    char stop_msg[256];
    snprintf(stop_msg, sizeof(stop_msg), 
             "{\"session_id\":\"%s\",\"type\":\"listen\",\"state\":\"stop\"}", 
             conn_state->session_id);
    
    int result = send_ws_message(wsi, conn_state, stop_msg, strlen(stop_msg), 0);
    if (result == 0) {
        conn_state->listen_stopped = 1;
    }
    return result;
}

int send_detect_message(struct lws *wsi, connection_state_t *conn_state, const char *text) {
    if (!wsi || !conn_state || !text) {
        fprintf(stderr, "Error: Invalid parameters for send_detect_message\n");
        return -1;
    }
    
    if (strlen(conn_state->session_id) == 0) {
        fprintf(stderr, "Error: No session_id available for detect message\n");
        return -1;
    }
    
    fprintf(stdout, "Sending detect message with text: %s\n", text);
    
    char detect_msg[512];
    snprintf(detect_msg, sizeof(detect_msg), 
             "{\"session_id\":\"%s\",\"type\":\"listen\",\"state\":\"detect\",\"text\":\"%s\"}", 
             conn_state->session_id, text);
    
    int result = send_ws_message(wsi, conn_state, detect_msg, strlen(detect_msg), 0);
    if (result == 0) {
        conn_state->listen_stopped = 1;
    }
    return result;
}

int send_chat_message(struct lws *wsi, connection_state_t *conn_state, const char *text) {
    if (!wsi || !conn_state || !text) {
        fprintf(stderr, "Error: Invalid parameters for send_chat_message\n");
        return -1;
    }
    
    // Ensure we have a valid session_id
    if (strlen(conn_state->session_id) == 0) {
        fprintf(stderr, "Error: No session_id available for chat message\n");
        return -1;
    }
    
    fprintf(stdout, "Sending text message for TTS: %s\n", text);
    
    // Format according to WebSocket protocol for text-to-speech
    return send_json_message(wsi, conn_state, 
                           "{\"session_id\":\"%s\","
                           "\"type\":\"listen\","
                           "\"mode\":\"manual\","
                           "\"state\":\"detect\","
                           "\"text\":\"%s\"}",
                           conn_state->session_id, text);
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

    fprintf(stdout, "Sending 'listen' message (state: start).\n");

    int result = send_json_message(wsi, conn_state,
                                   "{\"type\":\"listen\",\"session_id\":\"%s\",\"state\":\"start\",\"mode\":\"manual\"}",
                                   conn_state->session_id);
    if (result == 0) {
        conn_state->listen_sent = 1;
        conn_state->listen_sent_time = time(NULL);
    }
    return result;
}
