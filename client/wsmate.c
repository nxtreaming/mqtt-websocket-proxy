#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>

#include <libwebsockets.h>
#include "cjson/cJSON.h"

#include "ws_send_msg.h"
#include "ws_parse_msg.h"
#include "ws_audio_utils.h"

#ifdef _WIN32
#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

#include <stdint.h>
#include <ctype.h>

#ifndef LWS_CLOSE_STATUS_GOING_AWAY
#define LWS_CLOSE_STATUS_GOING_AWAY 1001
#endif

#define MAX_PAYLOAD_SIZE 2048

// Hardcoded for now, replace with dynamic values or config
#define SERVER_ADDRESS "122.51.57.185"
#define SERVER_PORT 8000
#define SERVER_PATH "/xiaozhi/v1"

#define AUTH_TOKEN "testtoken"
#define DEVICE_ID "b8:f8:62:fc:eb:68"
#define CLIENT_ID "79667E80-D837-4E95-B6DF-31C5E3C6DF22"

// Reconnection delay chunk size (milliseconds)
#define RECONNECTION_CHUNK_DELAY 100

typedef void (*command_handler_func)(struct lws* wsi, connection_state_t* conn_state, const char* command);
// Command table entry structure
typedef struct {
    const char* name;
    command_handler_func handler;
    int requires_connection;
} command_entry_t;

typedef void (*message_handler_func)(struct lws* wsi, cJSON* json_response);
// Message handler table entry structure
typedef struct {
    const char* name;
    message_handler_func handler;
} message_handler_entry_t;

// Global context and WebSocket instance
struct lws_context *g_context = NULL;

static struct lws *g_wsi = NULL;
static int interrupted = 0;

// Forward declarations
static int callback_wsmate(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);
static struct lws* attempt_reconnection(connection_state_t *conn_state);

// Protocol definition
static struct lws_protocols protocols[] = {
    {
        "default", // Protocol name
        callback_wsmate,
        sizeof(connection_state_t), // Per session data size
        MAX_PAYLOAD_SIZE, // RX buffer size
    },
    { NULL, NULL, 0, 0 } // Terminator
};

//
// ffmpeg -i .\opus_input.ogg -ac 1 -ar 16000 -c:a libopus -b:a 16K  -vbr:a off -application voip -frame_duration 40  cbr.ogg
//
// Note：
//       The current device（W800 SoC) only supports OPUS frame_duration: 40ms
//       The client uploads *OPUS* audio to Server, but the server returns the *MP3* audio data
//       because the device only supports MP3 playback.
//
static const char *g_hello_msg = 
    "{\"type\":\"hello\","
    "\"version\":1,"
    "\"features\":{\"mcp\":true,\"llm\":true,\"stt\":true,\"tts\":true},"
    "\"transport\":\"websocket\","
    "\"audio_params\":{"
        "\"format\":\"opus\","
        "\"sample_rate\":16000,"
        "\"channels\":1,"
        "\"frame_duration\":40}}";

static void ws_sleep(int milliseconds) {
#ifdef _WIN32
    Sleep(milliseconds);
#else
    usleep(milliseconds * 1000);
#endif
}

// Interruptible sleep with progress indication for reconnection delays
static int ws_sleep_interruptible(int total_delay_ms, const char* operation) {
    int chunk_delay = RECONNECTION_CHUNK_DELAY;
    int chunks_total = (total_delay_ms + chunk_delay - 1) / chunk_delay; // Round up
    int chunk_count = 0;

    fprintf(stdout, "%s: waiting %d ms", operation, total_delay_ms);
    fflush(stdout);

    for (int elapsed = 0; elapsed < total_delay_ms && !interrupted; elapsed += chunk_delay) {
        int current_chunk = (elapsed + chunk_delay > total_delay_ms) ?
                          (total_delay_ms - elapsed) : chunk_delay;
        ws_sleep(current_chunk);

        chunk_count++;
        // Show progress every 10 chunks (1 second) or at the end
        if (chunk_count % 10 == 0 || elapsed + current_chunk >= total_delay_ms) {
            fprintf(stdout, ".");
            fflush(stdout);
        }
    }

    if (interrupted) {
        fprintf(stdout, " interrupted!\n");
        return -1; // Interrupted
    } else {
        fprintf(stdout, " done\n");
        return 0; // Completed
    }
}

static void stop_and_cleanup_audio(connection_state_t* conn_state) {
    if (!conn_state) return;

    if (ws_audio_is_playing() || conn_state->audio_playing) {
        ws_audio_interrupt();
        ws_audio_stop();
        ws_audio_clear_buffer();
        interrupt_audio_playback(conn_state);
        stop_audio_playback(conn_state);
    }
}

static void clear_global_wsi_reference(struct lws* wsi) {
    if (g_wsi == wsi) {
        g_wsi = NULL;
    }
}

static int handle_reconnection_attempt(connection_state_t* conn_state, const char* context_msg) {
    if (!conn_state || !should_attempt_reconnection(conn_state)) {
        return 0; // No reconnection attempted
    }

    int delay = calculate_reconnection_delay(conn_state);

    if (context_msg) {
        fprintf(stdout, "%s\n", context_msg);
    }

    // Use interruptible sleep with progress indication
    if (ws_sleep_interruptible(delay, "Reconnection delay") == 0) {
        struct lws *new_wsi = attempt_reconnection(conn_state);
        if (new_wsi) {
            // Don't set g_wsi here - it will be set in LWS_CALLBACK_CLIENT_ESTABLISHED
            fprintf(stdout, "Reconnection attempt initiated, waiting for establishment\n");
            return 1; // Reconnection attempted successfully
        }
    } else {
        fprintf(stdout, "Reconnection cancelled due to interruption\n");
    }

    return 0; // Reconnection failed or cancelled
}

static void sigint_handler(int sig) {
    (void)sig;
    fprintf(stdout, "\nCaught SIGINT/Ctrl+C, initiating shutdown...\n");
    interrupted = 1;
}

static struct lws* attempt_reconnection(connection_state_t *conn_state) {
    if (!conn_state || !should_attempt_reconnection(conn_state)) {
        return NULL;
    }

    conn_state->reconnection_attempts++;
    conn_state->last_reconnection_time = time(NULL);

    fprintf(stdout, "Attempting reconnection #%d to %s:%d%s\n",
            conn_state->reconnection_attempts, SERVER_ADDRESS, SERVER_PORT, SERVER_PATH);

    // Create new connection info
    struct lws_client_connect_info conn_info;
    memset(&conn_info, 0, sizeof(conn_info));
    conn_info.context = g_context;
    conn_info.address = SERVER_ADDRESS;
    conn_info.port = SERVER_PORT;
    conn_info.path = SERVER_PATH;
    conn_info.host = conn_info.address;
    conn_info.origin = conn_info.address;
    conn_info.ssl_connection = 0;
    conn_info.protocol = protocols[0].name;
    conn_info.local_protocol_name = protocols[0].name;

    struct lws *new_wsi = lws_client_connect_via_info(&conn_info);
    if (!new_wsi) {
        fprintf(stderr, "Reconnection attempt #%d failed\n", conn_state->reconnection_attempts);
        return NULL;
    }

    fprintf(stdout, "Reconnection attempt #%d initiated\n", conn_state->reconnection_attempts);
    return new_wsi;
}

static void handle_stt_wrapper(struct lws *wsi, cJSON *json) {
    handle_generic_message(wsi, json, "STT");
}

static void handle_llm_wrapper(struct lws *wsi, cJSON *json) {
    handle_generic_message(wsi, json, "LLM");
}

static const message_handler_entry_t message_handler_table[] = {
    {"hello", handle_hello_message},
    {"mcp",   handle_mcp_message},
    {"stt",   handle_stt_wrapper},
    {"llm",   handle_llm_wrapper},
    {"tts",   handle_tts_message}
};

static int callback_wsmate( struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
            fprintf(stderr, "CLIENT_CONNECTION_ERROR: %s\n", in ? (char *)in : "(null)");
            // Close the connection and update state
            if (g_wsi) {
                connection_state_t *error_state = (connection_state_t *)lws_wsi_user(g_wsi);
                if (error_state) {
                    change_websocket_state(error_state, WS_STATE_ERROR);
                    error_state->connection_lost = 1;

                    // Clear global wsi reference since connection is invalid
                    clear_global_wsi_reference(wsi);

                    // Attempt reconnection if enabled
                    if (handle_reconnection_attempt(error_state, NULL)) {
                        break; // Don't set interrupted flag if reconnection was attempted
                    }
                } else {
                    // If no connection state, still clear global reference
                    clear_global_wsi_reference(wsi);
                }
            }
            interrupted = 1;
            break;
        }

        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            fprintf(stdout, "CLIENT_ESTABLISHED\n");

            // Store the WebSocket instance
            g_wsi = wsi;

            // Get the per-connection user data allocated by libwebsockets
            connection_state_t *conn_state = (connection_state_t *)lws_wsi_user(wsi);
            if (!conn_state) {
                fprintf(stderr, "Error: No connection state available\n");
                return -1;
            }

            // Initialize connection state using the new state management
            init_connection_state(conn_state);
            change_websocket_state(conn_state, WS_STATE_CONNECTED);

            // Reset reconnection state on successful connection
            reset_reconnection_state(conn_state);

            // Send hello message
            if (send_ws_message(wsi, conn_state, g_hello_msg, strlen(g_hello_msg), 0) == 0) {
                change_websocket_state(conn_state, WS_STATE_HELLO_SENT);
                conn_state->hello_sent_time = time(NULL);
                fprintf(stdout, "Client hello message prepared\n");
            } else {
                fprintf(stderr, "Error: Failed to prepare hello message\n");
                change_websocket_state(conn_state, WS_STATE_ERROR);
                return -1;
            }

            break;
        }

        case LWS_CALLBACK_CLIENT_RECEIVE: {
            connection_state_t* conn_state = (connection_state_t*)lws_wsi_user(wsi);
            if (!conn_state) {
                fprintf(stderr, "Error: No connection state in RECEIVE\n");
                return -1;
            }

            // Check if we're still connected
            if (conn_state->current_state == WS_STATE_DISCONNECTED ||
                conn_state->current_state == WS_STATE_ERROR) {
                fprintf(stderr, "Error: Received data in invalid state: %s\n",
                       websocket_state_to_string(conn_state->current_state));
                return -1;
            }

            if (lws_frame_is_binary(wsi)) {
                // Handle binary data (audio frames)
                // Only log every 10th frame to reduce output noise
                static int frame_count = 0;
                frame_count++;

                if (frame_count % 10 == 1) {
                    fprintf(stdout, "Receiving audio frames... (frame #%d, %zu bytes)\n", frame_count, len);
                }

                 // Try to play the received audio data as MP3
                if (len > 0) {
                    // Initialize audio system if not already done
                    static int audio_init_attempted = 0;
                    if (!audio_init_attempted) {
                        if (ws_audio_init(0) == 0) {
                            fprintf(stdout, "Audio system initialized for MP3 playback\n");
                        } else {
                            fprintf(stderr, "Failed to initialize audio system\n");
                        }
                        audio_init_attempted = 1;
                    }

                    // Start audio playback tracking if not already started
                    if (!conn_state->audio_playing) {
                        start_audio_playback(conn_state);
                    }

                    // Check if audio playback was interrupted
                    if (conn_state->audio_interrupted) {
                        fprintf(stdout, "Audio playback was interrupted, skipping frames\n");
                        // Clear the audio buffer to prevent further playback
                        ws_audio_clear_buffer();
                    } else {
                        // Play the received MP3 data (remove success logging to reduce noise)
                        if (ws_audio_play_mp3(in, len) != 0) {
                            fprintf(stderr, "Failed to play received MP3 audio (frame #%d)\n", frame_count);
                        }
                        // Success case: no logging to reduce output noise
                    }
                }

                // Update last activity time for keep-alive
                conn_state->last_activity = time(NULL);
            } else {
                // Handle text data (JSON messages)
                char* terminated_msg = NULL;
                const char* msg_to_log = (const char*)in;
                
                // Ensure the message is null-terminated for logging
                if (len > 0 && ((const char*)in)[len - 1] != '\0') {
                    terminated_msg = (char*)malloc(len + 1);
                    if (terminated_msg) {
                        memcpy(terminated_msg, in, len);
                        terminated_msg[len] = '\0';
                        msg_to_log = terminated_msg;
                    }
                }
                
                fprintf(stdout, "Received raw TEXT data: %.*s\n", (int)len, msg_to_log);
                
                // Parse the JSON message
                cJSON* json_response = cJSON_ParseWithLength((const char*)in, len);
                if (json_response == NULL) {
                    fprintf(stderr, "Failed to parse JSON response: %s\n", 
                           cJSON_GetErrorPtr() ? cJSON_GetErrorPtr() : "unknown error");
                } else {
                    // Process the JSON message
                    const cJSON* type_item = cJSON_GetObjectItemCaseSensitive(json_response, "type");

                    if (cJSON_IsString(type_item) && (type_item->valuestring != NULL)) {
                        const char* msg_type = type_item->valuestring;
                        fprintf(stdout, "  Response type: %s\n", msg_type);
                        
                        // Find and call the appropriate handler
                        int handled = 0;
                        for (size_t i = 0; i < sizeof(message_handler_table) / sizeof(message_handler_table[0]); ++i) {
                            if (strcmp(msg_type, message_handler_table[i].name) == 0) {
                                message_handler_table[i].handler(wsi, json_response);
                                handled = 1;
                                break;
                            }
                        }
                        
                        if (!handled) {
                            fprintf(stdout, "  No handler for message type: %s\n", msg_type);
                        }
                    } else {
                        fprintf(stderr, "  JSON response does not have a 'type' string field or type is null.\n");
                    }
                    
                    cJSON_Delete(json_response);
                }
                
                // Free the temporary buffer if we allocated one
                if (terminated_msg) {
                    free(terminated_msg);
                }
                
                // Update last activity time for keep-alive
                conn_state->last_activity = time(NULL);
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_CLOSED: {
            fprintf(stdout, "CLIENT_CLOSED\n");

            connection_state_t *closed_state = (connection_state_t *)lws_wsi_user(wsi);
            if (closed_state) {
                closed_state->connection_lost = 1;
                change_websocket_state(closed_state, WS_STATE_DISCONNECTED);

                // Clear global wsi reference since connection is closed
                clear_global_wsi_reference(wsi);

                // Only attempt reconnection if not explicitly closing
                if (closed_state->current_state != WS_STATE_CLOSING) {
                    if (handle_reconnection_attempt(closed_state, "Connection closed unexpectedly")) {
                        break; // Don't set interrupted flag if reconnection was attempted
                    }
                }
            } else {
                // If no connection state, still clear global reference
                clear_global_wsi_reference(wsi);
            }

            interrupted = 1;
            break;
        }

        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            connection_state_t *write_state = (connection_state_t *)lws_wsi_user(wsi);
            if (!write_state) {
                fprintf(stderr, "Error: No connection state in WRITEABLE callback\n");
                return -1;
            }

            // Handle abort message with highest priority
            if (write_state->should_send_abort) {
                const char *abort_msg = "{\"type\":\"abort\"}";
                int result = send_ws_message(wsi, write_state, abort_msg, strlen(abort_msg), 0);
                if (result == 0) {
                    fprintf(stdout, "Sent abort message\n");
                    // Close the connection after sending abort
                    lws_close_reason(wsi, LWS_CLOSE_STATUS_GOING_AWAY, (unsigned char *)"Aborted by user", 14);
                    write_state->should_close = 1;
                } else {
                    fprintf(stderr, "Failed to send abort message\n");
                }

                write_state->should_send_abort = 0;
                break; // Exit after handling abort
            }

            // Handle ping frame with high priority
            if (write_state->should_send_ping) {
                // Send WebSocket ping frame for keep-alive
                // Must reserve LWS_PRE bytes before the actual payload
                unsigned char ping_buffer[LWS_PRE + 4];
                unsigned char *ping_payload = &ping_buffer[LWS_PRE];
                ping_payload[0] = 0x50; // 'P'
                ping_payload[1] = 0x49; // 'I'
                ping_payload[2] = 0x4E; // 'N'
                ping_payload[3] = 0x47; // 'G'
                int ping_result = lws_write(wsi, ping_payload, 4, LWS_WRITE_PING);
                if (ping_result >= 0) {
                    fprintf(stdout, "Sent WebSocket ping frame for keep-alive\n");
                } else {
                    fprintf(stderr, "Failed to send WebSocket ping frame\n");
                }
                write_state->should_send_ping = 0;
                // Don't break here, continue to handle pending_write if any
            }

            // Handle regular pending write messages
            if (write_state->pending_write) {
                // Get a pointer to the buffer after the LWS_PRE bytes
                unsigned char *buf = (unsigned char *)write_state->write_buf + LWS_PRE;
                size_t wlen = write_state->write_len;

                // Determine the write flags
                enum lws_write_protocol write_flags = write_state->write_is_binary ?
                    LWS_WRITE_BINARY : LWS_WRITE_TEXT;

                // Ensure we have a valid write length
                if (wlen == 0) {
                    fprintf(stderr, "Error: Attempted to send zero-length message\n");
                    write_state->pending_write = 0;
                    break;
                }

                // For text messages, ensure proper null termination for logging
                if (!write_state->write_is_binary) {
                    if (wlen < (sizeof(write_state->write_buf) - LWS_PRE - 1)) {
                        buf[wlen] = '\0';
                    } else {
                        fprintf(stderr, "Error: Message too long for buffer\n");
                        write_state->pending_write = 0;
                        break;
                    }
                }

                // Send the message with proper WebSocket framing
                int write_result = lws_write(wsi, buf, wlen, write_flags);
                if (write_result < 0) {
                    fprintf(stderr, "Error %d writing to WebSocket\n", write_result);
                    return -1;
                } else if (write_result != (int)wlen) {
                    fprintf(stderr, "Partial write: %d of %u bytes written\n", write_result, (unsigned int)wlen);
                    return -1;
                }

                // Clear the pending write flag since we've sent the message
                write_state->pending_write = 0;
                fprintf(stdout, "Successfully sent %s message\n", write_state->write_is_binary ? "binary" : "text");

                // Update connection state based on what was sent
                if (write_state->current_state == WS_STATE_CONNECTED) {
                    // This was the hello message
                    change_websocket_state(write_state, WS_STATE_HELLO_SENT);
                    write_state->hello_sent_time = time(NULL);
                    fprintf(stdout, "Client hello sent at %ld\n", (long)write_state->hello_sent_time);
                } else if (write_state->current_state == WS_STATE_LISTENING && !write_state->write_is_binary) {
                    // This was the listen message (not a binary frame)
                    fprintf(stdout, "Listen message sent successfully\n");
                }
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
            unsigned char **p = (unsigned char **)in, *end = (*p) + len;
            if (lws_add_http_header_by_name(wsi, (unsigned char *)"Authorization", (unsigned char *)("Bearer " AUTH_TOKEN), strlen("Bearer " AUTH_TOKEN) , p, end)) {
                return -1;
            }
            if (lws_add_http_header_by_name(wsi, (unsigned char *)"Protocol-Version", (unsigned char *)"1", 1, p, end)) {
                return -1;
            }
            if (lws_add_http_header_by_name(wsi, (unsigned char *)"Device-Id", (unsigned char *)DEVICE_ID, strlen(DEVICE_ID), p, end)) {
                return -1;
            }
            if (lws_add_http_header_by_name(wsi, (unsigned char *)"Client-Id", (unsigned char *)CLIENT_ID, strlen(CLIENT_ID), p, end)) {
                return -1;
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_RECEIVE_PONG: {
            connection_state_t *pong_state = (connection_state_t *)lws_wsi_user(wsi);
            if (pong_state) {
                fprintf(stdout, "Received WebSocket pong frame - connection is alive\n");
                pong_state->last_activity = time(NULL);
            }
            break;
        }

        default:
            break;
    }
    return 0;
}

static const char* extract_command_param(const char* command, const char* cmd_name) {
    const char* param = strstr(command, cmd_name);
    if (!param) return NULL;

    param += strlen(cmd_name);
    while (*param && isspace((unsigned char)*param)) {
        param++;
    }

    // This static buffer is not thread-safe, but for this single-threaded client it's acceptable.
    static char buffer[1024];
    strncpy(buffer, param, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    // Trim trailing whitespace and quotes
    char* end = buffer + strlen(buffer) - 1;
    while (end >= buffer && (isspace((unsigned char)*end) || *end == '"')) {
        *end = '\0';
        end--;
    }

    // Trim leading quote
    char* start = buffer;
    if (*start == '"') {
        start++;
    }

    return start;
}

static const char* validate_and_extract_text_param(struct lws* wsi, connection_state_t* conn_state,
                                                   const char* command, const char* cmd_name,
                                                   websocket_state_t required_state1,
                                                   websocket_state_t required_state2,
                                                   websocket_state_t required_state3) {
    const char* text = extract_command_param(command, cmd_name);
    if (!text || !*text) {
        fprintf(stderr, "Please provide text for %s command\n", cmd_name);
        return NULL;
    }

    // Check if current state is one of the allowed states
    if (conn_state->current_state != required_state1 &&
        conn_state->current_state != required_state2 &&
        conn_state->current_state != required_state3) {
        fprintf(stderr, "Cannot send %s message in current state: %s\n",
               cmd_name, websocket_state_to_string(conn_state->current_state));
        return NULL;
    }

    return text;
}

static void print_help(void) {
    fprintf(stdout, "\nAvailable commands:\n");
    fprintf(stdout, "  help                 - Show this help message\n");
    fprintf(stdout, "  hello               - Send hello message\n");
    fprintf(stdout, "  listen start        - Start listening (audio mode)\n");
    fprintf(stdout, "  listen stop         - Stop listening\n");
    fprintf(stdout, "  detect <text>       - Send detect message with text\n");
    fprintf(stdout, "  chat <message>      - Send a chat message\n");
    fprintf(stdout, "  opus <filepath>     - Send Opus audio file to server\n");
    fprintf(stdout, "  abort               - Send abort message and close connection\n");
    fprintf(stdout, "  abort-reason <reason> - Send abort message with reason\n");
    fprintf(stdout, "  mcp <payload>       - Send MCP message with JSON-RPC payload\n");
    fprintf(stdout, "  status              - Show current connection status\n");
    fprintf(stdout, "  reconnect [enable|disable|status] - Configure reconnection policy\n");
    fprintf(stdout, "  audio [timeout <sec>|stop|status] - Audio playback control and interrupt\n");
    fprintf(stdout, "  interrupt           - Interrupt current audio playback immediately\n");
    fprintf(stdout, "  exit                - Close connection and exit\n");
    fprintf(stdout, "\n");
}

static void handle_help(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    print_help();
}

static void handle_hello(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    if (send_ws_message(wsi, conn_state, g_hello_msg, strlen(g_hello_msg), 0) == 0) {
        change_websocket_state(conn_state, WS_STATE_HELLO_SENT);
        conn_state->hello_sent_time = time(NULL);
        fprintf(stdout, "Sent hello message\n");
    } else {
        change_websocket_state(conn_state, WS_STATE_ERROR);
        fprintf(stderr, "Failed to send hello message\n");
    }
}

static void handle_listen(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    const char* param = extract_command_param(command, "listen");
    if (param && strcmp(param, "start") == 0) {
        if (conn_state->current_state == WS_STATE_AUTHENTICATED || 
            conn_state->current_state == WS_STATE_LISTENING) {
            send_start_listening_message(wsi, conn_state);
            change_websocket_state(conn_state, WS_STATE_LISTENING);
        } else {
            fprintf(stderr, "Cannot start listening in current state: %s\n", 
                   websocket_state_to_string(conn_state->current_state));
        }
    } else if (param && strcmp(param, "stop") == 0) {
        if (conn_state->current_state == WS_STATE_LISTENING) {
            send_stop_listening_message(wsi, conn_state);
            change_websocket_state(conn_state, WS_STATE_AUTHENTICATED);
        } else {
            fprintf(stderr, "Cannot stop listening in current state: %s\n", 
                   websocket_state_to_string(conn_state->current_state));
        }
    } else {
        fprintf(stderr, "Unknown listen command. Use 'listen start' or 'listen stop'\n");
    }
}

static void handle_detect(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    const char* text = validate_and_extract_text_param(wsi, conn_state, command, "detect",
                                                       WS_STATE_LISTENING, WS_STATE_LISTENING, WS_STATE_LISTENING);
    if (text) {
        send_detect_message(wsi, conn_state, text);
        change_websocket_state(conn_state, WS_STATE_SPEAKING);
    }
}

static void handle_chat(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    const char* text = validate_and_extract_text_param(wsi, conn_state, command, "chat",
                                                       WS_STATE_AUTHENTICATED, WS_STATE_LISTENING, WS_STATE_SPEAKING);
    if (text) {
        send_chat_message(wsi, conn_state, text);
        // Chat doesn't change the primary state, but we could add a sub-state if needed
    }
}

static void handle_abort(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    if (conn_state->current_state == WS_STATE_LISTENING ||
        conn_state->current_state == WS_STATE_SPEAKING) {

        // Interrupt any ongoing audio playback
        stop_and_cleanup_audio(conn_state);

        conn_state->should_send_abort = 1;
        lws_callback_on_writable(wsi);
        change_websocket_state(conn_state, WS_STATE_CLOSING);
        fprintf(stdout, "Abort message queued, audio playback interrupted\n");
    } else {
        fprintf(stderr, "Cannot send abort in current state: %s\n",
               websocket_state_to_string(conn_state->current_state));
    }
}

static void handle_abort_reason(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    const char* reason = extract_command_param(command, "abort-reason");
    if (reason && *reason) {
        if (conn_state->current_state == WS_STATE_LISTENING || 
            conn_state->current_state == WS_STATE_SPEAKING) {
            send_abort_message_with_reason(wsi, conn_state, reason);
            change_websocket_state(conn_state, WS_STATE_CLOSING);
        } else {
            fprintf(stderr, "Cannot send abort in current state: %s\n", 
                   websocket_state_to_string(conn_state->current_state));
        }
    } else {
        fprintf(stderr, "Please provide a reason for abort\n");
    }
}

static void handle_mcp(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    const char* payload = extract_command_param(command, "mcp");
    if (payload && *payload) {
        send_mcp_message(wsi, conn_state, payload);
    } else {
        fprintf(stderr, "Please provide a JSON-RPC payload\n");
    }
}

static void handle_status(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    if (!conn_state) {
        fprintf(stdout, "Status: No connection state available\n");
        return;
    }
    
    fprintf(stdout, "=== Connection Status ===\n");
    fprintf(stdout, "Current State: %s\n", websocket_state_to_string(conn_state->current_state));
    fprintf(stdout, "Previous State: %s\n", websocket_state_to_string(conn_state->previous_state));
    fprintf(stdout, "Protocol Version: %d\n", conn_state->protocol_version);
    fprintf(stdout, "Session ID: %s\n", conn_state->session_id[0] ? conn_state->session_id : "(none)");
    fprintf(stdout, "Features: MCP=%s, STT=%s, TTS=%s, LLM=%s\n",
            conn_state->features_mcp ? "yes" : "no",
            conn_state->features_stt ? "yes" : "no", 
            conn_state->features_tts ? "yes" : "no",
            conn_state->features_llm ? "yes" : "no");
    fprintf(stdout, "Audio Format: %s, Sample Rate: %d Hz, Channels: %d\n",
            conn_state->audio_params.format,
            conn_state->audio_params.sample_rate,
            conn_state->audio_params.channels);
    fprintf(stdout, "========================\n");
}

static int detect_opus_frame_duration(const unsigned char* opus_data, size_t data_len) {
    if (data_len < 1) return 40; // Default to 40ms
    
    unsigned char toc = opus_data[0];
    int config = (toc >> 3) & 0x1F;
    
    // Frame duration lookup table based on config
    const char* durations[] = {"10ms", "20ms", "40ms", "60ms"};
    int duration_values[] = {10, 20, 40, 60};
    
    int frame_idx = config % 4;
    
    if (config >= 20 && config <= 31) {
        // CELT modes have different durations
        const int celt_durations[] = {3, 5, 10, 20}; // 2.5ms rounded to 3ms
        return celt_durations[frame_idx];
    } else {
        // SILK and Hybrid modes
        return duration_values[frame_idx];
    }
}

static void handle_opus(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    const char* filename = extract_command_param(command, "opus");
    if (!filename || !*filename) {
        fprintf(stderr, "Please provide an Opus file path\n");
        return;
    }
    
    if (conn_state->current_state != WS_STATE_LISTENING) {
        fprintf(stderr, "Cannot send Opus audio in current state: %s\n", 
               websocket_state_to_string(conn_state->current_state));
        return;
    }
    
    FILE* file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open Opus file: %s\n", filename);
        return;
    }
    
    fprintf(stdout, "Reading Opus file: %s\n", filename);
    
    // Before sending Opus data, first send a listen message with state=start
    // This tells the server we are starting to send audio data
    if (send_start_listening_message(wsi, conn_state) == 0) {
        change_websocket_state(conn_state, WS_STATE_LISTENING);
        // Add a small delay to ensure the server processes the message
        ws_sleep(100); // 100 milliseconds
    } else {
        fprintf(stderr, "Failed to send start listening message\n");
    }
    
    uint32_t frame_length;
    unsigned char opus_buffer[4096];
    int frames_sent = 0;
    int frame_duration_ms = 40; // Default
    int duration_detected = 0;
    
    // Read Opus frames from file and send them
    while (fread(&frame_length, sizeof(uint32_t), 1, file) == 1) {
        // File data is in little endian format
        // On Windows (little endian), no conversion needed
        // Only convert if we're on a big endian system
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
        frame_length = ((frame_length & 0xFF) << 24) | 
                      (((frame_length >> 8) & 0xFF) << 16) | 
                      (((frame_length >> 16) & 0xFF) << 8) | 
                      ((frame_length >> 24) & 0xFF);
#elif defined(_WIN32)
        // Windows is always little endian, no conversion needed
        // frame_length is already correct
#endif
        
        if (frame_length == 0 || frame_length > sizeof(opus_buffer)) {
            fprintf(stderr, "Invalid Opus frame length: %u\n", frame_length);
            break;
        }
        
        // Read the Opus frame data
        if (fread(opus_buffer, 1, frame_length, file) != frame_length) {
            fprintf(stderr, "Failed to read complete Opus frame\n");
            break;
        }
        
        // Detect frame duration from first frame
        if (!duration_detected && frame_length > 0) {
            frame_duration_ms = detect_opus_frame_duration(opus_buffer, frame_length);
            duration_detected = 1;
            fprintf(stdout, "Detected Opus frame duration: %dms\n", frame_duration_ms);
        }
        
        // Send the Opus frame via WebSocket binary message
        int send_result = send_ws_message(wsi, conn_state, (const char*)opus_buffer, frame_length, 1);
        if (send_result == -2) {
            fprintf(stderr, "Warning: Opus frame dropped due to pending write, skipping frame\n");
            // Continue to next frame instead of breaking
        } else if (send_result != 0) {
            fprintf(stderr, "Failed to send Opus frame\n");
            break;
        }
        
        frames_sent++;
        // Only log every 10th frame to reduce output
        if (frames_sent % 10 == 0) {
            fprintf(stdout, "Sent Opus frame %d (%u bytes)\n", frames_sent, frame_length);
        }
        
        // Delay based on detected frame duration
        ws_sleep(frame_duration_ms);
    }
    
    fclose(file);
    fprintf(stdout, "Finished sending %d Opus frames from %s (frame duration: %dms)\n", 
            frames_sent, filename, frame_duration_ms);
    
    // After sending all Opus frames, send a stop message to indicate we've finished sending audio
    if (send_stop_listening_message(wsi, conn_state) != 0) {
        fprintf(stderr, "Failed to send stop message\n");
    }
}

static void handle_reconnect(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    const char* param = extract_command_param(command, "reconnect");
    if (param && strcmp(param, "enable") == 0) {
        set_reconnection_policy(conn_state, 1, 5, 1000, 30000, 1.5);
        fprintf(stdout, "Reconnection enabled with default settings\n");
    } else if (param && strcmp(param, "disable") == 0) {
        set_reconnection_policy(conn_state, 0, 0, 0, 0, 1.0);
        fprintf(stdout, "Reconnection disabled\n");
    } else if (param && strcmp(param, "status") == 0) {
        fprintf(stdout, "Reconnection status: %s\n", conn_state->reconnection_enabled ? "enabled" : "disabled");
        if (conn_state->reconnection_enabled) {
            fprintf(stdout, "  Max attempts: %d\n", conn_state->max_reconnection_attempts);
            fprintf(stdout, "  Current attempts: %d\n", conn_state->reconnection_attempts);
            fprintf(stdout, "  Initial delay: %dms\n", conn_state->initial_reconnection_delay);
            fprintf(stdout, "  Max delay: %dms\n", conn_state->max_reconnection_delay);
            fprintf(stdout, "  Current delay: %dms\n", conn_state->reconnection_delay);
            fprintf(stdout, "  Backoff multiplier: %.1f\n", conn_state->backoff_multiplier);
        }
    } else {
        fprintf(stderr, "Usage: reconnect [enable|disable|status]\n");
    }
}

static void handle_audio(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    const char* param = extract_command_param(command, "audio");
    if (param && strncmp(param, "timeout", 7) == 0) {
        const char* timeout_str = param + 7;
        while (*timeout_str && isspace((unsigned char)*timeout_str)) timeout_str++;

        if (*timeout_str) {
            int timeout = atoi(timeout_str);
            set_audio_timeout(conn_state, timeout);
        } else {
            fprintf(stdout, "Current audio timeout: %d seconds\n", conn_state->audio_timeout_seconds);
        }
    } else if (param && strcmp(param, "stop") == 0) {
        if (ws_audio_is_playing() || conn_state->audio_playing) {
            // Stop audio playback immediately
            stop_and_cleanup_audio(conn_state);

            // Send abort message to stop server-side processing
            conn_state->should_send_abort = 1;
            lws_callback_on_writable(wsi);
            fprintf(stdout, "Audio playback stopped and abort message queued\n");
        } else {
            fprintf(stdout, "No audio currently playing\n");
        }
    } else if (param && strcmp(param, "status") == 0) {
        fprintf(stdout, "Audio status:\n");
        fprintf(stdout, "  Playing (system): %s\n", ws_audio_is_playing() ? "yes" : "no");
        fprintf(stdout, "  Playing (connection): %s\n", conn_state->audio_playing ? "yes" : "no");
        fprintf(stdout, "  Timeout: %d seconds\n", conn_state->audio_timeout_seconds);
        if (conn_state->audio_playing) {
            time_t elapsed = time(NULL) - conn_state->audio_start_time;
            fprintf(stdout, "  Elapsed: %ld seconds\n", (long)elapsed);
            fprintf(stdout, "  Interrupted: %s\n", conn_state->audio_interrupted ? "yes" : "no");
        }
    } else {
        fprintf(stderr, "Usage: audio [timeout <seconds>|stop|status]\n");
    }
}

static void handle_interrupt(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    if (ws_audio_is_playing() || conn_state->audio_playing) {
        fprintf(stdout, "Interrupting current audio playback...\n");

        // Stop audio playback immediately
        stop_and_cleanup_audio(conn_state);

        // Send abort message to stop server-side processing
        conn_state->should_send_abort = 1;
        lws_callback_on_writable(wsi);

        fprintf(stdout, "Audio playback interrupted, ready for next recording\n");
    } else {
        fprintf(stdout, "No audio currently playing to interrupt\n");
    }
}

static void handle_exit(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    interrupted = 1;
    if (conn_state && wsi) {
        // Stop any ongoing audio playback
        stop_and_cleanup_audio(conn_state);
        change_websocket_state(conn_state, WS_STATE_CLOSING);
        lws_close_reason(wsi, LWS_CLOSE_STATUS_NORMAL, (unsigned char*)"User exit", 9);
    }
}

static const command_entry_t command_table[] = {
    {"help",         handle_help,         0},
    {"hello",        handle_hello,        1},
    {"listen",       handle_listen,       1},
    {"detect",       handle_detect,       1},
    {"chat",         handle_chat,         1},
    {"opus",         handle_opus,         1},
    {"abort",        handle_abort,        1},
    {"abort-reason", handle_abort_reason, 1},
    {"mcp",          handle_mcp,          1},
    {"status",       handle_status,       1},
    {"reconnect",    handle_reconnect,    0},
    {"audio",        handle_audio,        1},
    {"interrupt",    handle_interrupt,    1},
    {"exit",         handle_exit,         0}
};

static void process_command(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    if (!command || !*command) return;

    char cmd[256] = { 0 };
    const char* space = strchr(command, ' ');
    size_t cmd_len = space ? (size_t)(space - command) : strlen(command);
    if (cmd_len >= sizeof(cmd)) cmd_len = sizeof(cmd) - 1;
    strncpy(cmd, command, cmd_len);
    cmd[cmd_len] = '\0';

    for (size_t i = 0; i < sizeof(command_table) / sizeof(command_table[0]); ++i) {
        if (strcmp(cmd, command_table[i].name) == 0) {
            if (command_table[i].requires_connection && (!conn_state ||
                conn_state->current_state == WS_STATE_DISCONNECTED ||
                conn_state->current_state == WS_STATE_ERROR)) {
                fprintf(stderr, "Not connected to server. Command '%s' requires a connection.\n", cmd);
                return;
            }
            command_table[i].handler(wsi, conn_state, command);
            return;
        }
    }

    fprintf(stderr, "Unknown command: %s. Type 'help' for available commands.\n", cmd);
}

static void handle_interactive_mode() {
    static int first_run = 1;
    char input[1024] = {0};
    
    if (first_run) {
        fprintf(stdout, "\n=== Interactive Mode ===\n");
        fprintf(stdout, "Type 'help' for available commands\n");
        first_run = 0;
    }
    
    fprintf(stdout, "\n> ");
    fflush(stdout);
    
#ifdef _WIN32
    // Use Windows console API to read input properly on Chinese systems
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    
    // Enable line input and echo input
    SetConsoleMode(hStdin, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
    
    wchar_t wide_input[1024] = {0};
    DWORD chars_read = 0;
    
    if (!ReadConsoleW(hStdin, wide_input, sizeof(wide_input)/sizeof(wchar_t) - 1, &chars_read, NULL)) {
        // Handle error or EOF
        fprintf(stdout, "\n");
        interrupted = 1;
        return;
    }
    
    // Convert wide characters to UTF-8
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, wide_input, chars_read, input, sizeof(input) - 1, NULL, NULL);
    if (utf8_len <= 0) {
        fprintf(stderr, "Error converting input to UTF-8\n");
        return;
    }
    input[utf8_len] = '\0';
    
    // Restore original console mode
    SetConsoleMode(hStdin, mode);
#else
    // On Unix systems, use standard fgets
    if (fgets(input, sizeof(input), stdin) == NULL) {
        // Handle EOF (Ctrl+D)
        fprintf(stdout, "\n");
        interrupted = 1;
        return;
    }
#endif
    
    // Remove trailing newline and carriage return
    input[strcspn(input, "\r\n")] = 0;
    
    if (strlen(input) == 0) {
        return;
    }
    
    // Process the command
    connection_state_t *conn_state = NULL;
    if (g_wsi) {
        conn_state = (connection_state_t *)lws_wsi_user(g_wsi);
        if (conn_state) {
            process_command(g_wsi, conn_state, input);
        }
    }
}

#ifdef _WIN32
static DWORD WINAPI service_thread_func(LPVOID arg)
#else
static void *service_thread_func(void *arg)
#endif
{
    struct lws_context *context = (struct lws_context *)arg;
    lwsl_user("WebSocket service thread started.\n");
    
    // Main WebSocket service loop
    while (!interrupted && context) {
        int result = lws_service(context, 50);        
        if (result < 0) {
            lwsl_err("lws_service returned error: %d\n", result);
            break;
        }
    }
    
    lwsl_user("WebSocket service thread exiting.\n");
    return 0;
}

int main(int argc, char **argv) {
#ifdef _WIN32
    // Set console to UTF-8 for both input and output to handle Chinese characters correctly
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
#endif
    // Initialize random number generator with current time
    srand((unsigned int)time(NULL));
       
    fprintf(stdout, "Interactive WebSocket Client\n");
    fprintf(stdout, "==========================\n");
    fprintf(stdout, "Connecting to %s:%d%s\n", SERVER_ADDRESS, SERVER_PORT, SERVER_PATH);
    fprintf(stdout, "Type 'help' for available commands\n\n");
        
    // Register signal handler for SIGINT (Ctrl+C)
    signal(SIGINT, sigint_handler);
    struct lws_context_creation_info info;
    struct lws_client_connect_info conn_info;

    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    // Enable client SSL/TLS options if connecting to wss://
    // info.options |= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    // info.ssl_cert_filepath = NULL;
    // info.ssl_private_key_filepath = NULL;
    // info.ssl_ca_filepath = "path/to/ca-cert.pem"; // Optional: for self-signed certs

    g_context = lws_create_context(&info);
    if (!g_context) {
        fprintf(stderr, "lws_create_context failed\n");
        return 1;
    }

    memset(&conn_info, 0, sizeof(conn_info));
    conn_info.context = g_context;
    conn_info.address = SERVER_ADDRESS;
    conn_info.port = SERVER_PORT;
    conn_info.path = SERVER_PATH;
    conn_info.host = conn_info.address; // For SNI and Host header
    conn_info.origin = conn_info.address; // Origin header
    conn_info.ssl_connection = 0; // Set to LCCSCF_USE_SSL for wss://
    conn_info.protocol = protocols[0].name;
    conn_info.local_protocol_name = protocols[0].name; // For older LWS versions
    // Note: We don't need to manually allocate connection_state_t here
    // as libwebsockets will handle it based on the per_session_data_size in protocols[]
    
    fprintf(stdout, "Connecting to %s:%d%s\n", conn_info.address, conn_info.port, conn_info.path);
    struct lws *client_wsi = lws_client_connect_via_info(&conn_info);
    if (!client_wsi) {
        fprintf(stderr, "lws_client_connect_via_info failed\n");
        lws_context_destroy(g_context);
        g_context = NULL;
        return 1;
    }

    // Start service thread for WebSocket handling
#ifdef _WIN32
    HANDLE service_thread_handle = CreateThread(NULL, 0, service_thread_func, (LPVOID)g_context, 0, NULL);
    if (!service_thread_handle) {
        fprintf(stderr, "Error creating service thread\n");
        lws_context_destroy(g_context);
        return 1;
    }
#else
    pthread_t service_thread_id;
    if (pthread_create(&service_thread_id, NULL, service_thread_func, (void *)g_context) != 0) {
        fprintf(stderr, "Error creating service thread\n");
        lws_context_destroy(g_context);
        return 1;
    }
    pthread_detach(service_thread_id);
#endif

    while (!interrupted) {
        // Check for hello timeout (10 seconds)
        if (g_wsi) {
            connection_state_t *conn_state = (connection_state_t *)lws_wsi_user(g_wsi);
            if (conn_state) {
                // Check hello timeout
                if (conn_state->current_state == WS_STATE_HELLO_SENT) {
                    time_t current_time = time(NULL);
                    if (current_time - conn_state->hello_sent_time > 10) {
                        fprintf(stderr, "Timeout: No server hello response within 10 seconds\n");
                        change_websocket_state(conn_state, WS_STATE_ERROR);
                        interrupted = 1;
                        break;
                    }
                }

                // Check audio playback timeout
                if (is_audio_playback_timeout(conn_state)) {
                    fprintf(stderr, "Audio playback timeout detected, stopping playback\n");

                    // Stop audio system immediately
                    stop_and_cleanup_audio(conn_state);

                    // Send abort message to stop current session
                    conn_state->should_send_abort = 1;
                    lws_callback_on_writable(g_wsi);
                }

                // Check for keep-alive timeout (if no activity for 60 seconds)
                time_t current_time = time(NULL);
                if (conn_state->last_activity > 0 &&
                    (current_time - conn_state->last_activity) > 60) {
                    fprintf(stderr, "Keep-alive timeout: no activity for %ld seconds\n",
                            (long)(current_time - conn_state->last_activity));

                    // Use WebSocket standard ping frame instead of custom JSON message
                    // Set flag to send ping in the next writable callback
                    conn_state->should_send_ping = 1;
                    lws_callback_on_writable(g_wsi);
                    conn_state->last_activity = current_time;
                    fprintf(stdout, "Requesting WebSocket ping for keep-alive\n");
                }
            }
        }

        // Process user input from the console
        handle_interactive_mode();
    }

    fprintf(stdout, "Exiting main loop. Cleaning up...\n");

    // Signal the service thread to stop and wait for it
    if (g_context) {
        lwsl_user("Shutting down WebSocket service...\n");

        // Note: g_wsi will be managed by libwebsockets callbacks
        // No need to manually clear it here to avoid race conditions

        // Wake up lws_service in the other thread
        lws_cancel_service(g_context);
        
        // Set interrupted flag to signal the service thread to exit
        interrupted = 1;
    }

    // Wait for service thread to exit
#ifdef _WIN32
    if (service_thread_handle) {
        lwsl_user("Waiting for service thread to join (Windows)...\n");
        DWORD wait_result = WaitForSingleObject(service_thread_handle, 5000);  // Wait up to 5 seconds
        if (wait_result == WAIT_OBJECT_0) {
            CloseHandle(service_thread_handle);
            lwsl_user("Service thread joined (Windows).\n");
        } else {
            lwsl_err("Service thread did not exit in time\n");
            // Force terminate the thread if it's stuck
            TerminateThread(service_thread_handle, 1);
            CloseHandle(service_thread_handle);
        }
        service_thread_handle = NULL;
    }
#else
    if (service_thread_id) {
        lwsl_user("Waiting for service thread to join (POSIX)...\n");
        void* res;
        pthread_join(service_thread_id, &res);
        service_thread_id = 0;
        lwsl_user("Service thread joined (POSIX).\n");
    }
#endif

    // Clean up libwebsockets context
    if (g_context) {
        lws_context_destroy(g_context);
        g_context = NULL;
        lwsl_user("WebSocket context destroyed.\n");
    }

    fprintf(stdout, "wsmate finished.\n");
    return 0;
}
