#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> // For time()
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
                        if (cJSON_IsString(transport_item) && strcmp(transport_item->valuestring, "websocket") == 0) {
                            if (!server_hello_received) { // Process only if hello not already marked as received
                                server_hello_received = 1;
                                fprintf(stdout, "Server HELLO received and validated.\n");
                            }
                        } else {
                             fprintf(stderr, "Server HELLO received, but transport is not 'websocket' or invalid. Ignoring.\n");
                        }
                    }
                }

                const cJSON *session_id_item = cJSON_GetObjectItemCaseSensitive(json_response, "session_id");
                if (cJSON_IsString(session_id_item) && (session_id_item->valuestring != NULL)) {
                    fprintf(stdout, "  Session ID: %s\n", session_id_item->valuestring);
                }
                
                if (type_item && cJSON_IsString(type_item) && strcmp(type_item->valuestring, "mcp") == 0) {
                    const cJSON *payload = cJSON_GetObjectItemCaseSensitive(json_response, "payload");
                    if (payload) {
                        char *payload_str = cJSON_Print(payload);
                        fprintf(stdout, "  MCP Payload: %s\n", payload_str);
                        free(payload_str);
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
