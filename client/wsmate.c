#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libwebsockets.h>
#include <stdarg.h>

#include "ws_send_msg.h"
#include "ws_parse_msg.h"

#ifdef _WIN32
#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

#include "cjson/cJSON.h"
#include <signal.h>

#ifndef LWS_CLOSE_STATUS_GOING_AWAY
#define LWS_CLOSE_STATUS_GOING_AWAY 1001
#endif

#define MAX_PAYLOAD_SIZE 1024

// Hardcoded for now, replace with dynamic values or config
#define SERVER_ADDRESS "122.51.57.185"
#define SERVER_PORT 8000
#define SERVER_PATH "/xiaozhi/v1"

#define AUTH_TOKEN "testtoken"
//#define DEVICE_ID "74:3A:F4:36:F2:D2"
#define DEVICE_ID "b8:f8:62:fc:eb:68"
#define CLIENT_ID "79667E80-D837-4E95-B6DF-31C5E3C6DF22"

static int interrupted = 0;

#ifdef _WIN32
static HANDLE service_thread_handle = NULL;
#else
static pthread_t service_thread_id;
#endif

// Global context and WebSocket instance
static struct lws_context *g_context = NULL;
static struct lws *g_wsi = NULL;

static const char *hello_msg = 
    "{\"type\":\"hello\","
    "\"version\":1,"
    "\"features\":{\"mcp\":true,\"llm\":true,\"stt\":true,\"tts\":true},"
    "\"transport\":\"websocket\","
    "\"audio_params\":{"
        "\"format\":\"opus\","
        "\"sample_rate\":16000,"
        "\"channels\":1,"
        "\"frame_duration\":60}}";

static void sigint_handler(int sig) {
    (void)sig;
    fprintf(stdout, "\nCaught SIGINT/Ctrl+C, initiating shutdown...\n");
    interrupted = 1;
}

static uint64_t get_current_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

// Message handler function pointer type
typedef void (*message_handler_func)(struct lws *wsi, cJSON *json_response);

// Wrapper functions for generic handlers
static void handle_stt_wrapper(struct lws *wsi, cJSON *json) {
    handle_generic_message(wsi, json, "STT");
}

static void handle_llm_wrapper(struct lws *wsi, cJSON *json) {
    handle_generic_message(wsi, json, "LLM");
}

// Message handler table entry structure
typedef struct {
    const char* name;
    message_handler_func handler;
} message_handler_entry_t;

// Message handler table
static const message_handler_entry_t message_handler_table[] = {
    {"hello", handle_hello_message},
    {"mcp",   handle_mcp_message},
    {"stt",   handle_stt_wrapper},
    {"llm",   handle_llm_wrapper},
    {"tts",   handle_tts_message}
};

static int callback_wsmate( struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            fprintf(stderr, "CLIENT_CONNECTION_ERROR: %s\n", in ? (char *)in : "(null)");
            // Try to get connection state and update it to error state
            if (g_wsi) {
                connection_state_t *error_state = (connection_state_t *)lws_wsi_user(g_wsi);
                if (error_state) {
                    change_websocket_state(error_state, WS_STATE_ERROR);
                }
            }
            interrupted = 1;
            break;

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
            
            // Send hello message
            if (send_ws_message(wsi, conn_state, hello_msg, strlen(hello_msg), 0) == 0) {
                change_websocket_state(conn_state, WS_STATE_HELLO_SENT);
                conn_state->hello_sent_time = time(NULL);
                fprintf(stdout, "Client hello message prepared\n");
            } else {
                fprintf(stderr, "Error: Failed to prepare hello message\n");
                change_websocket_state(conn_state, WS_STATE_ERROR);
            }
                
            break;
        }

        case LWS_CALLBACK_CLIENT_RECEIVE: {
            connection_state_t* conn_state = (connection_state_t*)lws_wsi_user(wsi);
            if (!conn_state) {
                fprintf(stderr, "Error: No connection state in RECEIVE\n");
                return -1;
            }

            if (lws_frame_is_binary(wsi)) {
                fprintf(stdout, "Received BINARY audio frame: %zu bytes\n", len);
            } else {
                char* terminated_msg = NULL;
                char* msg_to_log = (char*)in;
                if (len > 0 && ((char*)in)[len - 1] != '\0') {
                    terminated_msg = (char*)malloc(len + 1);
                    if (terminated_msg) {
                        memcpy(terminated_msg, in, len);
                        terminated_msg[len] = '\0';
                        msg_to_log = terminated_msg;
                    }
                }
                fprintf(stdout, "Received raw TEXT data: %.*s\n", (int)len, msg_to_log);
                if (terminated_msg) free(terminated_msg);

                cJSON* json_response = cJSON_ParseWithLength((const char*)in, len);
                if (json_response == NULL) {
                    fprintf(stderr, "Failed to parse JSON response: %s\n", cJSON_GetErrorPtr());
                } else {
                    fprintf(stdout, "Successfully parsed JSON response.\n");
                    const cJSON* type_item = cJSON_GetObjectItemCaseSensitive(json_response, "type");

                    if (cJSON_IsString(type_item) && (type_item->valuestring != NULL)) {
                        const char* msg_type = type_item->valuestring;
                        fprintf(stdout, "  Response type: %s\n", msg_type);
                        
                        int handled = 0;
                        for (size_t i = 0; i < sizeof(message_handler_table) / sizeof(message_handler_table[0]); ++i) {
                            if (strcmp(msg_type, message_handler_table[i].name) == 0) {
                                message_handler_table[i].handler(wsi, json_response);
                                handled = 1;
                                break;
                            }
                        }
                        if (!handled) {
                            fprintf(stdout, "  Received unknown JSON message type: %s\n", msg_type);
                        }
                    } else {
                        fprintf(stderr, "  JSON response does not have a 'type' string field or type is null.\n");
                    }
                    cJSON_Delete(json_response);
                }
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_CLOSED: {
            fprintf(stdout, "CLIENT_CLOSED\n");
            g_wsi = NULL;
            connection_state_t *closed_state = (connection_state_t *)lws_wsi_user(wsi);
            if (closed_state) {
                change_websocket_state(closed_state, WS_STATE_DISCONNECTED);
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
                if (!write_state->hello_sent) {
                    // This was the hello message
                    write_state->hello_sent = 1;
                    write_state->hello_sent_time = time(NULL);
                    fprintf(stdout, "Client hello sent at %ld\n", (long)write_state->hello_sent_time);
                } else if (write_state->listen_sent && !write_state->write_is_binary) {
                    // This was the listen message (not a binary frame)
                    fprintf(stdout, "Listen message sent successfully\n");                    
                }
            } 
            else if (write_state->should_send_abort) {
                // Send abort message
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
                write_state->should_send_abort = 0;  // Reset the flag
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

// Forward declarations for command handlers
static void handle_help(struct lws* wsi, connection_state_t* conn_state, const char* command);
static void handle_hello(struct lws* wsi, connection_state_t* conn_state, const char* command);
static void handle_listen(struct lws* wsi, connection_state_t* conn_state, const char* command);
static void handle_detect(struct lws* wsi, connection_state_t* conn_state, const char* command);
static void handle_chat(struct lws* wsi, connection_state_t* conn_state, const char* command);
static void handle_abort(struct lws* wsi, connection_state_t* conn_state, const char* command);
static void handle_abort_reason(struct lws* wsi, connection_state_t* conn_state, const char* command);
static void handle_mcp(struct lws* wsi, connection_state_t* conn_state, const char* command);
static void handle_exit(struct lws* wsi, connection_state_t* conn_state, const char* command);
static void handle_status(struct lws* wsi, connection_state_t* conn_state, const char* command);

// Command handler function pointer type
typedef void (*command_handler_func)(struct lws* wsi, connection_state_t* conn_state, const char* command);

// Command table entry structure
typedef struct {
    const char* name;
    command_handler_func handler;
    int requires_connection;
} command_entry_t;

// Command table
static const command_entry_t command_table[] = {
    {"help",         handle_help,         0},
    {"hello",        handle_hello,        1},
    {"listen",       handle_listen,       1},
    {"detect",       handle_detect,       1},
    {"chat",         handle_chat,         1},
    {"abort",        handle_abort,        1},
    {"abort-reason", handle_abort_reason, 1},
    {"mcp",          handle_mcp,          1},
    {"status",       handle_status,       1},
    {"exit",         handle_exit,         0}
};

static void print_help(void) {
    fprintf(stdout, "\nAvailable commands:\n");
    fprintf(stdout, "  help                 - Show this help message\n");
    fprintf(stdout, "  hello               - Send hello message\n");
    fprintf(stdout, "  listen start        - Start listening (audio mode)\n");
    fprintf(stdout, "  listen stop         - Stop listening\n");
    fprintf(stdout, "  detect <text>       - Send detect message with text\n");
    fprintf(stdout, "  chat <message>      - Send a chat message\n");
    fprintf(stdout, "  abort               - Send abort message and close connection\n");
    fprintf(stdout, "  abort-reason <reason> - Send abort message with reason\n");
    fprintf(stdout, "  mcp <payload>       - Send MCP message with JSON-RPC payload\n");
    fprintf(stdout, "  status              - Show current connection status\n");
    fprintf(stdout, "  exit                - Close connection and exit\n");
    fprintf(stdout, "\n");
}

// Command handler implementations
static void handle_help(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    print_help();
}

static void handle_hello(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    if (send_ws_message(wsi, conn_state, hello_msg, strlen(hello_msg), 0) == 0) {
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
    const char* text = extract_command_param(command, "detect");
    if (text && *text) {
        if (conn_state->current_state == WS_STATE_LISTENING) {
            send_detect_message(wsi, conn_state, text);
            change_websocket_state(conn_state, WS_STATE_SPEAKING);
        } else {
            fprintf(stderr, "Cannot send detect message in current state: %s\n", 
                   websocket_state_to_string(conn_state->current_state));
        }
    } else {
        fprintf(stderr, "Please provide text to detect\n");
    }
}

static void handle_chat(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    const char* text = extract_command_param(command, "chat");
    if (text && *text) {
        if (conn_state->current_state == WS_STATE_AUTHENTICATED || 
            conn_state->current_state == WS_STATE_LISTENING ||
            conn_state->current_state == WS_STATE_SPEAKING) {
            send_chat_message(wsi, conn_state, text);
            // Chat doesn't change the primary state, but we could add a sub-state if needed
        } else {
            fprintf(stderr, "Cannot send chat message in current state: %s\n", 
                   websocket_state_to_string(conn_state->current_state));
        }
    } else {
        fprintf(stderr, "Please provide a message to send\n");
    }
}

static void handle_abort(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    if (conn_state->current_state == WS_STATE_LISTENING || 
        conn_state->current_state == WS_STATE_SPEAKING) {
        conn_state->should_send_abort = 1;
        lws_callback_on_writable(wsi);
        change_websocket_state(conn_state, WS_STATE_CLOSING);
        fprintf(stdout, "Abort message queued\n");
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

static void handle_exit(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    interrupted = 1;
    if (conn_state && wsi) {
        change_websocket_state(conn_state, WS_STATE_CLOSING);
        lws_close_reason(wsi, LWS_CLOSE_STATUS_NORMAL, (unsigned char*)"User exit", 9);
    }
}

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

// Function to handle a single interactive command
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
    
    if (fgets(input, sizeof(input), stdin) == NULL) {
        // Handle EOF (Ctrl+D)
        fprintf(stdout, "\n");
        interrupted = 1;
        return;
    }
    
    // Remove trailing newline
    input[strcspn(input, "\n")] = 0;
    
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
        // Process WebSocket events with a 50ms timeout
        int result = lws_service(context, 50);        
        if (result < 0) {
            lwsl_err("lws_service returned error: %d\n", result);
            break;
        }
    }
    
    lwsl_user("WebSocket service thread exiting.\n");
    return 0;
}

static struct lws_protocols protocols[] = {
    {
        "default", // Protocol name
        callback_wsmate,
        sizeof(connection_state_t), // Per session data size
        MAX_PAYLOAD_SIZE, // RX buffer size
    },
    { NULL, NULL, 0, 0 } // Terminator
};

int main(int argc, char **argv) {
#ifdef _WIN32
    // Set console to UTF-8 for both input and output to handle Chinese characters correctly
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
    
    // We'll use the standard console mode instead of wide character mode
    // as it's more compatible with the rest of our code
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
    
    // Initialize the global WebSocket instance for state tracking
    g_wsi = client_wsi;

    // Start service thread for WebSocket handling
#ifdef _WIN32
    service_thread_handle = CreateThread(NULL, 0, service_thread_func, (LPVOID)g_context, 0, NULL);
    if (!service_thread_handle) {
        fprintf(stderr, "Error creating service thread\n");
        lws_context_destroy(g_context);
        return 1;
    }
#else
    if (pthread_create(&service_thread_id, NULL, service_thread_func, (void *)g_context) != 0) {
        fprintf(stderr, "Error creating service thread\n");
        lws_context_destroy(g_context);
        return 1;
    }
    pthread_detach(service_thread_id);
#endif

    // Main loop for the program. This loop only handles user input.
    // All WebSocket I/O is handled by the lws service thread.
    while (!interrupted) {
        // Check for hello timeout (10 seconds)
        if (g_wsi) {
            connection_state_t *conn_state = (connection_state_t *)lws_wsi_user(g_wsi);
            if (conn_state && conn_state->current_state == WS_STATE_HELLO_SENT) {
                time_t current_time = time(NULL);
                if (current_time - conn_state->hello_sent_time > 10) {
                    fprintf(stderr, "Timeout: No server hello response within 10 seconds\n");
                    change_websocket_state(conn_state, WS_STATE_ERROR);
                    interrupted = 1;
                    break;
                }
            }
        }
        
        // Process user input from the console
        handle_interactive_mode();

        // A short sleep to prevent this loop from consuming 100% CPU.
#ifdef _WIN32
        Sleep(50); // 50 ms
#else
        usleep(50000); // 50 ms
#endif
    }

    fprintf(stdout, "Exiting main loop. Cleaning up...\n");

    // Signal the service thread to stop and wait for it
    if (g_context) {
        lwsl_user("Shutting down WebSocket service...\n");
        // Wake up lws_service in the other thread
        lws_cancel_service(g_context);
        
        // Set interrupted flag to signal the service thread to exit
        interrupted = 1;
    }

#ifdef _WIN32
    if (service_thread_handle) {
        lwsl_user("Waiting for service thread to join (Windows)...\n");
        WaitForSingleObject(service_thread_handle, INFINITE);
        CloseHandle(service_thread_handle);
        service_thread_handle = NULL;
        lwsl_user("Service thread joined (Windows).\n");
    }
#else
    if (g_context && service_thread_id != 0) {
        lwsl_user("Waiting for service thread to join (POSIX)...\n");
        void* res;
        pthread_join(service_thread_id, &res);
        // service_thread_id = 0; // Mark as joined, optional for pthreads
        lwsl_user("Service thread joined (POSIX).\n");
    }
#endif

    if (g_context) {
        lws_context_destroy(g_context);
        g_context = NULL;
        fprintf(stdout, "lws_context_destroyed\n");
    }

    fprintf(stdout, "wsmate finished.\n");
    return 0;
}
