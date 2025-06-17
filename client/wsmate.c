#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libwebsockets.h>
#include "cjson/cJSON.h"
#include <signal.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

//
// Note:
// 
// there is 10s timeout if server hello is not received
// there is 180s timeout if no any message is received
//

#define MAX_PAYLOAD_SIZE 1024
#define HELLO_TIMEOUT_SECONDS 10
#define WAKE_WORD_SEND_OFFSET_SECONDS 3
#define ABORT_SEND_OFFSET_SECONDS 6 // Must be > WAKE_WORD_SEND_OFFSET_SECONDS

#define MAX_BINARY_FRAMES_TO_SEND 5
#define DUMMY_BINARY_FRAME_SIZE 20
#define BINARY_FRAME_SEND_INTERVAL_MS 100 // Send a frame every 100ms

// Hardcoded for now, replace with dynamic values or config
#define SERVER_ADDRESS "ws.transock.net"
#define SERVER_PORT 8000
#define SERVER_PATH "/xiaozhi/v1"

#define AUTH_TOKEN "testtoken"
#define DEVICE_ID "00:11:22:33:44:55"
#define CLIENT_ID "testclient"

static int interrupted = 0;
static struct lws *wsi_global = NULL;
static time_t hello_sent_time = 0;
static int server_hello_received = 0;
static int listen_sent = 0;
static time_t listen_sent_time = 0;
static int wake_word_sent = 0;
static int abort_sent = 0;
static int binary_frames_sent_count = 0;
static unsigned long last_binary_frame_send_time_ms = 0;
static char g_session_id[64] = {0};

// Signal handler function
static void sigint_handler(int sig) {
    (void)sig; // Unused parameter
    fprintf(stdout, "\nCaught SIGINT/Ctrl+C, initiating shutdown...\n");
    interrupted = 1;
}

// Thread specific
#ifdef _WIN32
static HANDLE service_thread_handle = NULL;
#else
static pthread_t service_thread_id;
#endif
static struct lws_context *g_context = NULL;

static const char *client_hello_json =
    "{"
    "\"type\": \"hello\","
    "\"version\": 1,"
    "\"features\": {"
    "    \"mcp\": true"
    "},"
    "\"transport\": \"websocket\","
    "\"audio_params\": {"
    "    \"format\": \"opus\","
    "    \"sample_rate\": 16000,"
    "    \"channels\": 1,"
    "    \"frame_duration\": 60"
    "}"
    "}";

// Helper for time in milliseconds
static unsigned long get_current_ms(void) {
    return lws_now_usecs() / 1000;
}

// Forward declarations for message handlers
static void handle_hello_message(struct lws *wsi, cJSON *json_response);
static void handle_mcp_message(struct lws *wsi, cJSON *json_response);
static void handle_stt_message(cJSON *json_response);
static void handle_llm_message(cJSON *json_response);
static void handle_tts_message(cJSON *json_response);

static int callback_wsmate(
    struct lws *wsi,
    enum lws_callback_reasons reason,
    void *user,
    void *in,
    size_t len)
{
    switch (reason) {
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            fprintf(stderr, "CLIENT_CONNECTION_ERROR: %s\n", in ? (char *)in : "(null)");
            interrupted = 1;
            wsi_global = NULL;
            break;

        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            fprintf(stdout, "CLIENT_ESTABLISHED\n");
            // Send the client hello message
            unsigned char buf[LWS_PRE + MAX_PAYLOAD_SIZE];
            size_t client_hello_len = strlen(client_hello_json);
            memcpy(&buf[LWS_PRE], client_hello_json, client_hello_len);
            fprintf(stdout, "Sending client hello:\n%s\n", client_hello_json);
            if (lws_write(wsi, &buf[LWS_PRE], client_hello_len, LWS_WRITE_TEXT) < 0) {
                fprintf(stderr, "Error sending client hello\n");
                interrupted = 1;
                return -1;
            }
            hello_sent_time = time(NULL);
            server_hello_received = 0;
            listen_sent = 0;
            g_session_id[0] = '\0'; // Clear session_id on new connection
            break;

        case LWS_CALLBACK_CLIENT_RECEIVE:
            if (lws_frame_is_binary(wsi)) {
                fprintf(stdout, "Received BINARY data: %zu bytes\n", len);
                // For a test client, we just log receipt of binary data.
                // In a real application, this would be processed (e.g., as audio data).
            } else {
                fprintf(stdout, "Received raw TEXT data: %.*s\n", (int)len, (char *)in);

                cJSON *json_response = cJSON_ParseWithLength((const char *)in, len);
                if (json_response == NULL) {
                    const char *error_ptr = cJSON_GetErrorPtr();
                    if (error_ptr != NULL) {
                        fprintf(stderr, "Error before: %s\n", error_ptr);
                    }
                    fprintf(stderr, "Failed to parse JSON response\n");
                } else {
                    fprintf(stdout, "Successfully parsed JSON response.\n");
                    const cJSON *type_item = cJSON_GetObjectItemCaseSensitive(json_response, "type");

                    if (cJSON_IsString(type_item) && (type_item->valuestring != NULL)) {
                        char *msg_type = type_item->valuestring;
                        fprintf(stdout, "  Response type: %s\n", msg_type);

                        if (strcmp(msg_type, "hello") == 0) {
                            handle_hello_message(wsi, json_response);
                        } else if (strcmp(msg_type, "mcp") == 0) {
                            handle_mcp_message(wsi, json_response);
                        } else if (strcmp(msg_type, "stt") == 0) {
                            handle_stt_message(json_response);
                        } else if (strcmp(msg_type, "llm") == 0) {
                            handle_llm_message(json_response);
                        } else if (strcmp(msg_type, "tts") == 0) {
                            handle_tts_message(json_response);
                        } else {
                            fprintf(stdout, "  Received unknown JSON message type: %s\n", msg_type);
                        }
                    } else {
                        fprintf(stderr, "  JSON response does not have a 'type' string field or type is null.\n");
                    }
                    cJSON_Delete(json_response);
                }
            }
            break;

        case LWS_CALLBACK_CLIENT_CLOSED:
            fprintf(stdout, "CLIENT_CLOSED\n");
            wsi_global = NULL; // Mark as disconnected
            interrupted = 1; // Signal to exit main loop
            break;

        case LWS_CALLBACK_CLIENT_WRITEABLE:
            // This callback is called when the connection is ready to send more data.
            // We send our initial message in LWS_CALLBACK_CLIENT_ESTABLISHED.
            // For continuous data sending, you might manage a send queue here.
            break;

        case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
        {
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

static void handle_hello_message(struct lws *wsi, cJSON *json_response) {
    const cJSON *transport_item = cJSON_GetObjectItemCaseSensitive(json_response, "transport");
    const cJSON *session_id_item = cJSON_GetObjectItemCaseSensitive(json_response, "session_id");
    if (cJSON_IsString(session_id_item) && (session_id_item->valuestring != NULL)) {
        strncpy(g_session_id, session_id_item->valuestring, sizeof(g_session_id) - 1);
        g_session_id[sizeof(g_session_id) - 1] = '\0'; // Ensure null termination
        fprintf(stdout, "  Session ID: %s (stored)\n", g_session_id);
    } else {
        fprintf(stdout, "  No session_id in hello message or not a string.\n");
    }

    if (cJSON_IsString(transport_item) && strcmp(transport_item->valuestring, "websocket") == 0) {
        if (!server_hello_received) { // Process only if hello not already marked as received
            server_hello_received = 1;
            fprintf(stdout, "Server HELLO received and validated.\n");

            if (!listen_sent) {
                char formatted_listen_message[256];
                int listen_msg_len;
                if (strlen(g_session_id) > 0) {
                    listen_msg_len = snprintf(formatted_listen_message, sizeof(formatted_listen_message),
                             "{\"type\": \"listen\", \"session_id\": \"%s\", \"state\": \"start\", \"mode\": \"manual\"}",
                             g_session_id);
                } else {
                    listen_msg_len = snprintf(formatted_listen_message, sizeof(formatted_listen_message),
                             "{\"type\": \"listen\", \"state\": \"start\", \"mode\": \"manual\"}");
                }

                if (listen_msg_len > 0 && listen_msg_len < sizeof(formatted_listen_message)) {
                    unsigned char listen_buf[LWS_PRE + MAX_PAYLOAD_SIZE];
                    memcpy(&listen_buf[LWS_PRE], formatted_listen_message, listen_msg_len);
                    fprintf(stdout, "Attempting to send 'listen' message: %s\n", formatted_listen_message);
                    if (lws_write(wsi, &listen_buf[LWS_PRE], listen_msg_len, LWS_WRITE_TEXT) < 0) {
                        fprintf(stderr, "Error sending 'listen' message\n");
                    } else {
                        fprintf(stdout, "'listen' message sent successfully.\n");
                        listen_sent = 1;
                        listen_sent_time = time(NULL); // For second-precision wake_word and abort timing
                        last_binary_frame_send_time_ms = get_current_ms(); // Initialize for millisecond-precision binary frame timing
                    }
                } else {
                    fprintf(stderr, "Error: Could not format 'listen' message or it's too long.\n");
                }
            }
        }
    } else {
         fprintf(stderr, "Server HELLO received, but transport is not 'websocket' or invalid. Ignoring.\n");
    }
}

static void handle_mcp_message(struct lws *wsi, cJSON *json_response) {
    const cJSON *payload = cJSON_GetObjectItemCaseSensitive(json_response, "payload");
    if (payload) {
        char *payload_str = cJSON_PrintUnformatted(payload);
        fprintf(stdout, "  MCP Payload: %s\n", payload_str ? payload_str : "(null)");

        const cJSON *mcp_id_item = cJSON_GetObjectItemCaseSensitive(payload, "id");
        if (mcp_id_item && (cJSON_IsNumber(mcp_id_item) || cJSON_IsString(mcp_id_item))) {
            char rpc_id_component[48];
            if (cJSON_IsString(mcp_id_item)) {
                snprintf(rpc_id_component, sizeof(rpc_id_component), "\"%s\"", mcp_id_item->valuestring);
            } else { // IsNumber
                snprintf(rpc_id_component, sizeof(rpc_id_component), "%d", mcp_id_item->valueint);
            }
            fprintf(stdout, "MCP request received (id: %s), sending wrapped MCP success response...\n", rpc_id_component);

            char inner_rpc_response_payload_str[128];
            const cJSON *method_item = cJSON_GetObjectItemCaseSensitive(payload, "method");
            if (method_item && cJSON_IsString(method_item) && strcmp(method_item->valuestring, "tools/list") == 0) {
                snprintf(inner_rpc_response_payload_str, sizeof(inner_rpc_response_payload_str),
                     "{\"jsonrpc\": \"2.0\", \"id\": %s, \"result\": {\"tools\": []}}", rpc_id_component);
                fprintf(stdout, "Responding to 'tools/list' with empty tool list.\n");
            } else {
                snprintf(inner_rpc_response_payload_str, sizeof(inner_rpc_response_payload_str),
                     "{\"jsonrpc\": \"2.0\", \"id\": %s, \"result\": {}}", rpc_id_component);
                // For other methods like 'initialize', a generic empty result is fine for this client.
                if (method_item && cJSON_IsString(method_item)) {
                    fprintf(stdout, "Responding to '%s' with generic success.\n", method_item->valuestring);
                } else {
                    fprintf(stdout, "Responding to MCP request with generic success.\n");
                }
            }

            char full_mcp_response_str[LWS_PRE + MAX_PAYLOAD_SIZE];
            int written_len;
            if (strlen(g_session_id) > 0) {
                written_len = snprintf(full_mcp_response_str, sizeof(full_mcp_response_str),
                         "{\"type\": \"mcp\", \"session_id\": \"%s\", \"payload\": %s}",
                         g_session_id, inner_rpc_response_payload_str);
            } else {
                written_len = snprintf(full_mcp_response_str, sizeof(full_mcp_response_str),
                         "{\"type\": \"mcp\", \"payload\": %s}",
                         inner_rpc_response_payload_str);
            }

            if (written_len > 0 && written_len < sizeof(full_mcp_response_str)) {
                unsigned char mcp_resp_buf[LWS_PRE + MAX_PAYLOAD_SIZE];
                memcpy(&mcp_resp_buf[LWS_PRE], full_mcp_response_str, written_len);
                fprintf(stdout, "Sending JSON message:\n%s\n", full_mcp_response_str);
                if (lws_write(wsi, &mcp_resp_buf[LWS_PRE], written_len, LWS_WRITE_TEXT) < 0) {
                    fprintf(stderr, "Error sending MCP response\n");
                }
            } else {
                fprintf(stderr, "Error: MCP response message too long or snprintf error.\n");
            }
        }
        if (payload_str) free(payload_str);
    }
}

static void handle_stt_message(cJSON *json_response) {
    fprintf(stdout, "  Received STT message.\n");
    const cJSON *text_item = cJSON_GetObjectItemCaseSensitive(json_response, "text");
    if (cJSON_IsString(text_item) && text_item->valuestring) {
        fprintf(stdout, "    STT Text: %s\n", text_item->valuestring);
    }
}

static void handle_llm_message(cJSON *json_response) {
    fprintf(stdout, "  Received LLM message.\n");
    const cJSON *text_item = cJSON_GetObjectItemCaseSensitive(json_response, "text");
    const cJSON *emotion_item = cJSON_GetObjectItemCaseSensitive(json_response, "emotion");
    if (cJSON_IsString(text_item) && text_item->valuestring) {
        fprintf(stdout, "    LLM Text: %s\n", text_item->valuestring);
    }
    if (cJSON_IsString(emotion_item) && emotion_item->valuestring) {
        fprintf(stdout, "    LLM Emotion: %s\n", emotion_item->valuestring);
    }
}

static void handle_tts_message(cJSON *json_response) {
    fprintf(stdout, "  Received TTS message.\n");
    const cJSON *state_item = cJSON_GetObjectItemCaseSensitive(json_response, "state");
    if (cJSON_IsString(state_item) && state_item->valuestring) {
        fprintf(stdout, "    TTS State: %s\n", state_item->valuestring);
    }
    const cJSON *text_item = cJSON_GetObjectItemCaseSensitive(json_response, "text");
    if (cJSON_IsString(text_item) && text_item->valuestring) {
        fprintf(stdout, "    TTS Text (e.g. for sentence_start): %s\n", text_item->valuestring);
    }
}

// Service thread function
static void *service_thread_func(void *arg) {
    struct lws_context *context = (struct lws_context *)arg;
    lwsl_user("Service thread started.\n");
    while (!interrupted && context) {
        lws_service(context, 50);
    }
    lwsl_user("Service thread exiting.\n");
    return NULL;
}

static struct lws_protocols protocols[] = {
    {
        "default", // Protocol name
        callback_wsmate,
        0, // Per session data size
        MAX_PAYLOAD_SIZE, // RX buffer size
    },
    { NULL, NULL, 0, 0 } // Terminator
};

int main(int argc, char **argv) {
#ifdef _WIN32
    // Set console to UTF-8 to display Chinese characters correctly
    SetConsoleOutputCP(CP_UTF8);
#endif
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
    conn_info.pwsi = &wsi_global;

    fprintf(stdout, "Connecting to %s:%d%s\n", conn_info.address, conn_info.port, conn_info.path);
    if (!lws_client_connect_via_info(&conn_info)) {
        fprintf(stderr, "lws_client_connect_via_info failed\n");
        lws_context_destroy(g_context);
        g_context = NULL;
        return 1;
    }

    wsi_global = *conn_info.pwsi; // Ensure wsi_global is set immediately if connect_via_info doesn't block

    // Start the service thread
#ifdef _WIN32
    service_thread_handle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)service_thread_func, g_context, 0, NULL);
    if (service_thread_handle == NULL) {
        fprintf(stderr, "Failed to create service thread: %ld\n", GetLastError());
        lws_context_destroy(g_context);
        g_context = NULL;
        return 1;
    }
#else
    if (pthread_create(&service_thread_id, NULL, service_thread_func, g_context) != 0) {
        perror("Failed to create service thread");
        lws_context_destroy(g_context);
        g_context = NULL;
        return 1;
    }
#endif

    while (!interrupted && wsi_global) {
        // Add a small delay to prevent busy-waiting in the main loop.
#if defined(_WIN32)
        Sleep(10);
#else
        usleep(10000);
#endif

        unsigned long current_ms = get_current_ms();

        if (wsi_global && hello_sent_time > 0 && !server_hello_received) {
            if (time(NULL) - hello_sent_time > HELLO_TIMEOUT_SECONDS) {
                fprintf(stderr, "Timeout: Server HELLO not received within %d seconds. Closing connection.\n", HELLO_TIMEOUT_SECONDS);
                lws_close_reason(wsi_global, 1001 /* LWS_CLOSE_STATUS_GOING_AWAY */, (unsigned char *)"Hello timeout", 13);
                interrupted = 1;
                wsi_global = NULL; // Important to prevent further use of closed wsi
            }
        }

        // Send dummy binary frames after 'listen' is sent and before 'wake word'
        if (wsi_global && listen_sent && server_hello_received &&
            binary_frames_sent_count < MAX_BINARY_FRAMES_TO_SEND &&
            !wake_word_sent) { // Send binary frames during the "active listening" phase before wake word
            if (current_ms - last_binary_frame_send_time_ms >= BINARY_FRAME_SEND_INTERVAL_MS) {
                unsigned char binary_buf[LWS_PRE + DUMMY_BINARY_FRAME_SIZE];
                // Fill with some dummy data
                for (int i = 0; i < DUMMY_BINARY_FRAME_SIZE; ++i) {
                    binary_buf[LWS_PRE + i] = (unsigned char)((i + binary_frames_sent_count) % 256);
                }
                fprintf(stdout, "Sending dummy binary frame #%d (%d bytes)\n", binary_frames_sent_count + 1, DUMMY_BINARY_FRAME_SIZE);
                if (lws_write(wsi_global, &binary_buf[LWS_PRE], DUMMY_BINARY_FRAME_SIZE, LWS_WRITE_BINARY) < 0) {
                    fprintf(stderr, "Error sending dummy binary frame\n");
                } else {
                    binary_frames_sent_count++;
                    last_binary_frame_send_time_ms = current_ms;
                }
            }
        }

        // Check if it's time to send a 'wake word detected' message
        if (wsi_global && listen_sent && !wake_word_sent && server_hello_received) {
            if (time(NULL) - listen_sent_time > WAKE_WORD_SEND_OFFSET_SECONDS) { // Check time for wake word
                fprintf(stdout, "Sending 'listen state:detect' (wake word) message after delay...\n");
                char formatted_ww_message[256];
                int ww_msg_len;
                if (strlen(g_session_id) > 0) {
                    ww_msg_len = snprintf(formatted_ww_message, sizeof(formatted_ww_message),
                                             "{\"type\": \"listen\", \"session_id\": \"%s\", \"state\": \"detect\", \"text\": \"\xE4\xBD\xA0\xE5\xA5\xBD\xE5\xB0\x8F\xE6\x98\x8E\"}", // "你好小明" in UTF-8
                                             g_session_id);
                } else {
                    // Fallback if session_id wasn't received - less ideal
                    ww_msg_len = snprintf(formatted_ww_message, sizeof(formatted_ww_message),
                                             "{\"type\": \"listen\", \"state\": \"detect\", \"text\": \"\xE4\xBD\xA0\xE5\xA5\xBD\xE5\xB0\x8F\xE6\x98\x8E\"}"); // "你好小明" in UTF-8
                }

                if (ww_msg_len > 0 && ww_msg_len < sizeof(formatted_ww_message)) {
                    unsigned char ww_buf[LWS_PRE + MAX_PAYLOAD_SIZE];
                    memcpy(&ww_buf[LWS_PRE], formatted_ww_message, ww_msg_len);
                    if (lws_write(wsi_global, &ww_buf[LWS_PRE], ww_msg_len, LWS_WRITE_TEXT) < 0) {
                        fprintf(stderr, "Error sending 'listen state:detect' message\n");
                    } else {
                        fprintf(stdout, "'listen state:detect' message sent successfully: %s\n", formatted_ww_message);
                        wake_word_sent = 1;
                    }
                } else {
                    fprintf(stderr, "Error: Could not format 'listen state:detect' message or it's too long.\n");
                }
            }
        }

        // Check if it's time to send an abort message
        if (wsi_global && listen_sent && wake_word_sent && !abort_sent && server_hello_received) {
            if (time(NULL) - listen_sent_time > ABORT_SEND_OFFSET_SECONDS) {
                fprintf(stdout, "Sending 'abort' message after delay...\n");
                char formatted_abort_message[256];
                int abort_msg_len;
                if (strlen(g_session_id) > 0) {
                    abort_msg_len = snprintf(formatted_abort_message, sizeof(formatted_abort_message),
                                             "{\"type\": \"abort\", \"session_id\": \"%s\", \"reason\": \"client_initiated_test\"}",
                                             g_session_id);
                } else {
                    // Fallback if session_id wasn't received - less ideal for abort
                    abort_msg_len = snprintf(formatted_abort_message, sizeof(formatted_abort_message),
                                             "{\"type\": \"abort\", \"reason\": \"client_initiated_test\"}");
                }

                if (abort_msg_len > 0 && abort_msg_len < sizeof(formatted_abort_message)) {
                    unsigned char abort_buf[LWS_PRE + MAX_PAYLOAD_SIZE];
                    memcpy(&abort_buf[LWS_PRE], formatted_abort_message, abort_msg_len);
                    if (lws_write(wsi_global, &abort_buf[LWS_PRE], abort_msg_len, LWS_WRITE_TEXT) < 0) {
                        fprintf(stderr, "Error sending 'abort' message\n");
                    } else {
                        fprintf(stdout, "'abort' message sent successfully: %s\n", formatted_abort_message);
                        abort_sent = 1;
                        fprintf(stdout, "Closing connection after sending abort.\n");
                        lws_close_reason(wsi_global, LWS_CLOSE_STATUS_NORMAL, (unsigned char *)"Client abort", 12);
                        interrupted = 1; // Signal to exit main loop
                    }
                } else {
                    fprintf(stderr, "Error: Could not format 'abort' message or it's too long.\n");
                }
            }
        }
    }

    fprintf(stdout, "Exiting main loop. Cleaning up...\n");

    // Signal the service thread to stop and wait for it
    interrupted = 1; // Ensure it's set for the service thread

    if (g_context) {
        lwsl_user("Cancelling service for context from main thread.\n");
        lws_cancel_service(g_context); // Wake up lws_service in the other thread
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
    // Check if service_thread_id was initialized (i.e., thread creation was attempted)
    // and g_context was valid when pthread_create was called.
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
