#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libwebsockets.h>
#include "cjson/cJSON.h"

//
// Note:
// 
// there is 10s timeout if server hello is not received
// there is 180s timeout if no any message is received
//

#define MAX_PAYLOAD_SIZE 1024

static int interrupted = 0;
static struct lws *wsi_global = NULL;
static time_t hello_sent_time = 0;
static int server_hello_received = 0;
static int listen_sent = 0;
static char g_session_id[64] = {0}; // Global to store session_id

#define HELLO_TIMEOUT_SECONDS 10

// Hardcoded for now, replace with dynamic values or config
#define SERVER_ADDRESS "localhost"
#define SERVER_PORT 8000
#define SERVER_PATH "/xiaozhi/v1"

#define AUTH_TOKEN "testtoken"
#define DEVICE_ID "00:11:22:33:44:55"
#define CLIENT_ID "testclient"

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
            fprintf(stdout, "Received raw data: %.*s\n", (int)len, (char *)in);

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
                    fprintf(stdout, "  Response type: %s\n", type_item->valuestring);
                    if (strcmp(type_item->valuestring, "hello") == 0) {
                        const cJSON *transport_item = cJSON_GetObjectItemCaseSensitive(json_response, "transport");
                        const cJSON *session_id_item = cJSON_GetObjectItemCaseSensitive(json_response, "session_id");
                        if (cJSON_IsString(session_id_item) && (session_id_item->valuestring != NULL)) {
                            strncpy(g_session_id, session_id_item->valuestring, sizeof(g_session_id) - 1);
                            g_session_id[sizeof(g_session_id) - 1] = '\0'; // Ensure null termination
                            fprintf(stdout, "  Session ID: %s (stored)\n", g_session_id);
                        } else {
                            fprintf(stdout, "  No session_id in hello message or not a string.\n");
                            // g_session_id remains empty or as before
                        }

                        if (cJSON_IsString(transport_item) && strcmp(transport_item->valuestring, "websocket") == 0) {
                            if (!server_hello_received) { // Process only if hello not already marked as received
                                server_hello_received = 1;
                                fprintf(stdout, "Server HELLO received and validated.\n");

                                // Now, send the 'listen' message if not already sent
                                // g_session_id should be populated by now
                                if (!listen_sent) {
                                    char formatted_listen_message[256];
                                    int listen_msg_len;
                                    if (strlen(g_session_id) > 0) {
                                        listen_msg_len = snprintf(formatted_listen_message, sizeof(formatted_listen_message),
                                                 "{\"type\": \"listen\", \"session_id\": \"%s\", \"state\": \"start\", \"mode\": \"manual\"}",
                                                 g_session_id);
                                    } else {
                                        // Fallback if session_id wasn't received - this might not be ideal for the server
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
                }

            if (type_item && cJSON_IsString(type_item) && strcmp(type_item->valuestring, "mcp") == 0) {
                    const cJSON *payload = cJSON_GetObjectItemCaseSensitive(json_response, "payload");
                    if (payload) {
                        char *payload_str = cJSON_PrintUnformatted(payload); // Use Unformatted for easier parsing if needed later
                        fprintf(stdout, "  MCP Payload: %s\n", payload_str ? payload_str : "(null)");

                        // Check if this MCP message is a request (has an 'id')
                        const cJSON *mcp_id_item = cJSON_GetObjectItemCaseSensitive(payload, "id");
                        if (mcp_id_item && (cJSON_IsNumber(mcp_id_item) || cJSON_IsString(mcp_id_item))) {
                            char mcp_id_str[32];
                            if (cJSON_IsNumber(mcp_id_item)) {
                                snprintf(mcp_id_str, sizeof(mcp_id_str), "%d", mcp_id_item->valueint);
                            } else { // IsString
                                strncpy(mcp_id_str, mcp_id_item->valuestring, sizeof(mcp_id_str) - 1);
                                mcp_id_str[sizeof(mcp_id_str) - 1] = '\0';
                            }

                            fprintf(stdout, "MCP request received (id: %s), sending wrapped MCP success response...\n", mcp_id_str);

                            char inner_rpc_response_payload_str[128];
                            // Corrected snprintf for id: if it's a string, it needs quotes in JSON.
                            // Simpler: always treat id as number for response as per many RPC specs, or ensure quotes if string.
                            // For now, let's assume numeric or string ID is fine in response if formatted correctly.
                            // Re-simplifying for numeric ID as it's most common for JSON-RPC id.
                            // If server sends string ID, it expects string ID back. Let's handle that.
                            
                            char rpc_id_component[48]; // Buffer for the ID part of JSON-RPC, including quotes if string
                            if (cJSON_IsString(mcp_id_item)) {
                                snprintf(rpc_id_component, sizeof(rpc_id_component), "\"%s\"", mcp_id_item->valuestring);
                            } else { // IsNumber
                                snprintf(rpc_id_component, sizeof(rpc_id_component), "%d", mcp_id_item->valueint);
                            }

                            const cJSON *method_item = cJSON_GetObjectItemCaseSensitive(payload, "method");
                            if (method_item && cJSON_IsString(method_item) && strcmp(method_item->valuestring, "tools/list") == 0) {
                                snprintf(inner_rpc_response_payload_str, sizeof(inner_rpc_response_payload_str),
                                     "{\"jsonrpc\": \"2.0\", \"id\": %s, \"result\": {\"tools\": []}}", rpc_id_component);
                                fprintf(stdout, "Responding to 'tools/list' with empty tool list.\n");
                            } else {
                                snprintf(inner_rpc_response_payload_str, sizeof(inner_rpc_response_payload_str),
                                     "{\"jsonrpc\": \"2.0\", \"id\": %s, \"result\": {}}", rpc_id_component);
                            }


                            char full_mcp_response_str[LWS_PRE + MAX_PAYLOAD_SIZE]; // Reuse MAX_PAYLOAD_SIZE for outer message too
                            int written_len;
                            if (strlen(g_session_id) > 0) {
                                written_len = snprintf(full_mcp_response_str, sizeof(full_mcp_response_str),
                                         "{\"type\": \"mcp\", \"session_id\": \"%s\", \"payload\": %s}",
                                         g_session_id, inner_rpc_response_payload_str);
                            } else { // Fallback if session_id somehow wasn't captured (should not happen if server sends it)
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
                cJSON_Delete(json_response);
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
    struct lws_context_creation_info info;
    struct lws_client_connect_info conn_info;
    struct lws_context *context;

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

    context = lws_create_context(&info);
    if (!context) {
        fprintf(stderr, "lws_create_context failed\n");
        return 1;
    }

    memset(&conn_info, 0, sizeof(conn_info));
    conn_info.context = context;
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
        lws_context_destroy(context);
        return 1;
    }

    wsi_global = *conn_info.pwsi; // Ensure wsi_global is set immediately if connect_via_info doesn't block

    while (!interrupted && wsi_global) {
        lws_service(context, 50);

        if (wsi_global && hello_sent_time > 0 && !server_hello_received) {
            if (time(NULL) - hello_sent_time > HELLO_TIMEOUT_SECONDS) {
                fprintf(stderr, "Timeout: Server HELLO not received within %d seconds. Closing connection.\n", HELLO_TIMEOUT_SECONDS);
                lws_close_reason(wsi_global, 1001 /* LWS_CLOSE_STATUS_GOING_AWAY */, (unsigned char *)"Hello timeout", 13);
                interrupted = 1;
                wsi_global = NULL; // Important to prevent further use of closed wsi
            }
        }
    }

    fprintf(stdout, "Exiting...\n");
    lws_context_destroy(context);
    return 0;
}
