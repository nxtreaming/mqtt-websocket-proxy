#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libwebsockets.h>
#include <stdarg.h>

#include "ws_send_msg.h"
#include "ws_handle_msg.h"

#ifdef _WIN32
#include <Windows.h>
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
    "\"features\":{\"mcp\":true},"
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

static int callback_wsmate( struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            fprintf(stderr, "CLIENT_CONNECTION_ERROR: %s\n", in ? (char *)in : "(null)");
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
            
            // Initialize connection state
            memset(conn_state, 0, sizeof(connection_state_t));
            conn_state->connected = 1;
            
            // Send hello message
            if (send_ws_message(wsi, conn_state, hello_msg, strlen(hello_msg), 0) == 0) {
                conn_state->hello_sent = 1;
                fprintf(stdout, "Client hello message prepared\n");
            } else {
                fprintf(stderr, "Error: Failed to prepare hello message\n");
            }
                
            break;
        }

        case LWS_CALLBACK_CLIENT_RECEIVE: {
            // Get connection state
            connection_state_t* conn_state = (connection_state_t*)lws_wsi_user(wsi);
            if (!conn_state) {
                fprintf(stderr, "Error: No connection state in RECEIVE\n");
                return -1;
            }

            if (lws_frame_is_binary(wsi)) {
                fprintf(stdout, "Received BINARY audio frame: %zu bytes\n", len);
            }
            else {
                // Ensure the received data is properly null-terminated for logging
                char* msg = (char*)in;
                size_t msg_len = len;
                char* terminated_msg = NULL;

                // Check if the message is already null-terminated
                if (msg_len > 0 && msg[msg_len - 1] != '\0') {
                    // Make a null-terminated copy for safe printing
                    terminated_msg = (char*)malloc(msg_len + 1);
                    if (terminated_msg) {
                        memcpy(terminated_msg, msg, msg_len);
                        terminated_msg[msg_len] = '\0';
                        msg = terminated_msg;
                    }
                }

                fprintf(stdout, "Received raw TEXT data: %.*s\n", (int)msg_len, msg);

                // Free the temporary buffer if we allocated one
                if (terminated_msg) {
                    free(terminated_msg);
                }

                cJSON* json_response = cJSON_ParseWithLength((const char*)in, len);
                if (json_response == NULL) {
                    const char* error_ptr = cJSON_GetErrorPtr();
                    if (error_ptr != NULL) {
                        fprintf(stderr, "Error before: %s\n", error_ptr);
                    }
                    fprintf(stderr, "Failed to parse JSON response\n");
                }
                else {
                    fprintf(stdout, "Successfully parsed JSON response.\n");
                    const cJSON* type_item = cJSON_GetObjectItemCaseSensitive(json_response, "type");

                    if (cJSON_IsString(type_item) && (type_item->valuestring != NULL)) {
                        char* msg_type = type_item->valuestring;
                        fprintf(stdout, "  Response type: %s\n", msg_type);

                        if (strcmp(msg_type, "hello") == 0) {
                            handle_hello_message(wsi, json_response);
                        }
                        else if (strcmp(msg_type, "mcp") == 0) {
                            handle_mcp_message(wsi, json_response);
                        }
                        else if (strcmp(msg_type, "stt") == 0) {
                            handle_generic_message(wsi, json_response, "STT");
                        }
                        else if (strcmp(msg_type, "llm") == 0) {
                            handle_generic_message(wsi, json_response, "LLM");
                        }
                        else if (strcmp(msg_type, "tts") == 0) {
                            handle_tts_message(wsi, json_response);
                        }
                        else {
                            fprintf(stdout, "  Received unknown JSON message type: %s\n", msg_type);
                        }
                    }
                    else {
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
                closed_state->connected = 0;
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
                // Handle pending write if needed
                // Currently no implementation as we're not using pending writes in this mode
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

static void print_help(void) {
    fprintf(stdout, "\nAvailable commands:\n");
    fprintf(stdout, "  help                 - Show this help message\n");
    fprintf(stdout, "  hello               - Send hello message\n");
    fprintf(stdout, "  listen start        - Start listening (audio mode)\n");
    fprintf(stdout, "  listen stop         - Stop listening\n");
    fprintf(stdout, "  detect <text>       - Send detect message with text\n");
    fprintf(stdout, "  chat <message>      - Send a chat message\n");
    fprintf(stdout, "  abort               - Send abort message and close connection\n");
    fprintf(stdout, "  exit                - Close connection and exit\n");
    fprintf(stdout, "\n");
}

static void process_command(struct lws *wsi, connection_state_t *conn_state, const char *command) {
    if (!command || !*command) return;
    
    char cmd[256] = {0};
    char param[1024] = {0};
    
    // Simple command parsing
    int num_matched = sscanf(command, "%255s %1023[^\n]", cmd, param);
    
    if (strcmp(cmd, "help") == 0) {
        print_help();
    } 
    else if (strcmp(cmd, "hello") == 0) {
        if (!conn_state->connected) {
            fprintf(stderr, "Not connected to server\n");
            return;
        }
        if (send_ws_message(wsi, conn_state, hello_msg, strlen(hello_msg), 0) == 0) {
            conn_state->hello_sent = 1;
            fprintf(stdout, "Sent hello message\n");
        }
    }
    else if (strcmp(cmd, "listen") == 0) {
        if (!conn_state->connected) {
            fprintf(stderr, "Not connected to server\n");
            return;
        }
        
        if (strcmp(param, "start") == 0) {
            send_start_listening_message(wsi, conn_state);
        } 
        else if (strcmp(param, "stop") == 0) {
            send_stop_listening_message(wsi, conn_state);
        } 
        else {
            fprintf(stderr, "Unknown listen command. Use 'listen start' or 'listen stop'\n");
        }
    }
    else if (strcmp(cmd, "detect") == 0) {
        if (!conn_state->connected) {
            fprintf(stderr, "Not connected to server\n");
            return;
        }
        if (strlen(param) == 0) {
            fprintf(stderr, "Please provide text to detect\n");
            return;
        }
        send_detect_message(wsi, conn_state, param);
    }
    else if (strcmp(cmd, "chat") == 0) {
        if (!conn_state->connected) {
            fprintf(stderr, "Not connected to server\n");
            return;
        }
        if (strlen(param) == 0) {
            fprintf(stderr, "Please provide a message to send\n");
            return;
        }
        send_chat_message(wsi, conn_state, param);
    }
    else if (strcmp(cmd, "abort") == 0) {
        if (!conn_state->connected) {
            fprintf(stderr, "Not connected to server\n");
            return;
        }
        conn_state->should_send_abort = 1;
        lws_callback_on_writable(wsi);
        fprintf(stdout, "Abort message queued\n");
    }
    else if (strcmp(cmd, "exit") == 0) {
        interrupted = 1;
        if (conn_state->connected && wsi) {
            lws_close_reason(wsi, LWS_CLOSE_STATUS_NORMAL, (unsigned char *)"User exit", 9);
        }
    }
    else {
        fprintf(stderr, "Unknown command: %s. Type 'help' for available commands.\n", cmd);
    }
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
    // Set console to UTF-8 to display Chinese characters correctly
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
    if (!lws_client_connect_via_info(&conn_info)) {
        fprintf(stderr, "lws_client_connect_via_info failed\n");
        lws_context_destroy(g_context);
        g_context = NULL;
        return 1;
    }

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

    // Main loop for the program
    int no_connection_printed = 0;
    
    while (!interrupted) {
        // Process user input
        handle_interactive_mode();
        
        // Check if we need to send any pending messages
        if (g_wsi) {
            connection_state_t *conn_state = (connection_state_t *)lws_wsi_user(g_wsi);
            if (conn_state && conn_state->connected) {
                lws_callback_on_writable(g_wsi);
            }
        }

        unsigned long current_ms = get_current_ms();

        // Get connection state from the active WebSocket instance
        connection_state_t *conn_state = NULL;
        if (g_wsi)
            conn_state = (connection_state_t *)lws_wsi_user(g_wsi);
        if (!conn_state) {
            if (!no_connection_printed) {
                fprintf(stderr, "Error: No connection state in main loop, trying...\n");
                no_connection_printed = 1;
            }
            continue;
        }
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
