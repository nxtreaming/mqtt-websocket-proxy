#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libwebsockets.h>
#include <stdarg.h>

#ifdef _WIN32
#include <Windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

#include "cjson/cJSON.h"
#include <signal.h>

//
// Note:
// 
// There is 10s timeout if server hello is not received
// There is 180s timeout if no any message is received:
//   Client need not implement this feature, websocket server will handle it
//

#ifndef LWS_CLOSE_STATUS_GOING_AWAY
#define LWS_CLOSE_STATUS_GOING_AWAY 1001
#endif

//#define ENABLE_WEBSOCKET_VERBOSE 1

#define MAX_PAYLOAD_SIZE 1024
#define HELLO_TIMEOUT_SECONDS 10


#define AUDIO_SEND_DURATION_MS 3000  // 发送音频的持续时间（毫秒）
#define AUDIO_SEND_DURATION_SECONDS (AUDIO_SEND_DURATION_MS / 1000)  // 向后兼容
#define WAIT_FOR_RESPONSE_SECONDS 30   // Wait for server response (increased to 30s)
#define TEST_MODE_AUDIO 0              // Test audio recognition
#define TEST_MODE_TEXT 1               // Test text to speech
#define TEST_MODE TEST_MODE_TEXT      // Change this to switch test modes

#define MAX_BINARY_FRAMES_TO_SEND 5
#define DUMMY_BINARY_FRAME_SIZE 20
#define BINARY_FRAME_SEND_INTERVAL_MS 100 // Send a frame every 100ms

// Opus音频配置
#define OPUS_INPUT_FILE "d:/temp/opus_raw.bin"
#define OPUS_OUTPUT_FILE "d:/temp/opus_output.bin"

// Opus帧头定义
#define OPUS_MAX_FRAME_SIZE 4096  // Opus单帧最大大小（根据RFC6716标准）
#define OPUS_MAX_PACKET_DURATION 120  // Opus最大包持续时间(ms)

#define OPUS_FRAME_DURATION_MS 60  // 每帧音频时长（毫秒）
#define MAX_OPUS_FRAMES 50   // 最大发送帧数（约3秒）

// Statistics
static int g_total_audio_bytes_sent = 0;
static int g_total_audio_bytes_received = 0;

// Hardcoded for now, replace with dynamic values or config
#define SERVER_ADDRESS "122.51.57.185"
#define SERVER_PORT 8000
#define SERVER_PATH "/xiaozhi/v1"

#define AUTH_TOKEN "testtoken"
//#define DEVICE_ID "74:3A:F4:36:F2:D2"
#define DEVICE_ID "b8:f8:62:fc:eb:68"
#define CLIENT_ID "79667E80-D837-4E95-B6DF-31C5E3C6DF22"

static int interrupted = 0;
// Audio parameters structure
typedef struct {
    char format[32];           // Audio format (e.g., "opus")
    int sample_rate;           // Sample rate in Hz (e.g., 16000, 24000)
    int channels;              // Number of audio channels (e.g., 1, 2)
    int frame_duration;        // Frame duration in ms (e.g., 60)
} audio_params_t;

// Connection state structure
typedef struct {
    int connected;
    int hello_sent;
    int server_hello_received;
    int listen_sent;
    int listen_stopped;
    int test_message_sent;
    time_t listen_sent_time;
    time_t audio_start_time;
    int binary_frames_sent;
    uint64_t last_binary_frame_send_time_ms;
    int binary_frames_sent_count;
    
    // Message state
    int pending_write;
    size_t write_len;
    int write_is_binary;
    unsigned char write_buf[LWS_PRE + 4096];  // Buffer for outgoing messages
    
    // Session information
    char session_id[64];  // Store session ID from server hello
    char stt_text[1024];  // Store STT recognized text
    
    // Connection control
    int should_close;        // Flag to indicate connection should be closed
    
    // Audio control
    int should_send_audio;  // Flag to control audio frame sending
    int should_send_abort;  // Flag to control when to send abort message
    
    // Audio parameters
    audio_params_t audio_params;
    
    // Timeout handling
    time_t hello_sent_time;
    
    // Opus音频状态
    FILE *opus_input_file;          // Opus音频输入文件句柄
    FILE *opus_output_file;         // 解码后的音频输出文件句柄
    int opus_frames_sent;           // 已发送的Opus帧数
    int opus_test_mode;             // 1=使用Opus文件, 0=使用模拟数据
    size_t opus_frame_size;         // 当前Opus帧的实际大小
    unsigned char opus_frame_buffer[OPUS_MAX_FRAME_SIZE];  // Opus帧缓冲区
} connection_state_t;

#ifdef _WIN32
static HANDLE service_thread_handle = NULL;
#else
static pthread_t service_thread_id;
#endif

// Global context and WebSocket instance
static struct lws_context *g_context = NULL;
static struct lws *g_wsi = NULL;  // Global WebSocket instance pointer

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

static int send_ws_message(struct lws* wsi, connection_state_t* conn_state, const char* message, size_t message_len, int is_binary) {
    if (!wsi || !conn_state || !message) {
        fprintf(stderr, "Error: Invalid parameters for send_ws_message\n");
        return -1;
    }
    
    // 确保缓冲区足够大
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

static int send_json_message(struct lws* wsi, connection_state_t* conn_state, const char* format, ...) {
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
    vsnprintf((char*)(conn_state->write_buf + LWS_PRE),
        sizeof(conn_state->write_buf) - LWS_PRE - 1, format, args);
    va_end(args);

    return send_ws_message(wsi, conn_state,
        (const char*)(conn_state->write_buf + LWS_PRE),
        (size_t)msg_len, 0);
}

static int send_binary_frame(struct lws *wsi, connection_state_t *conn_state, size_t frame_size) {
    if (!wsi || !conn_state || frame_size == 0 || 
        frame_size > sizeof(conn_state->write_buf) - LWS_PRE) {
        fprintf(stderr, "Error: Invalid parameters for send_binary_frame\n");
        return -1;
    }
    
    // Create a dummy binary frame with random data
    unsigned char *binary_data = conn_state->write_buf + LWS_PRE;
    for (size_t i = 0; i < frame_size; i++) {
        binary_data[i] = (unsigned char)(rand() % 256);
    }
    
    return send_ws_message(wsi, conn_state, (const char *)binary_data, frame_size, 1);
}

static int send_opus_frame(struct lws *wsi, connection_state_t *conn_state) {
    if (!wsi || !conn_state) {
        fprintf(stderr, "Error: Invalid parameters for send_opus_frame\n");
        return -1;
    }
    
    if (conn_state->opus_test_mode && conn_state->opus_input_file) {
        size_t bytes_read = fread(conn_state->opus_frame_buffer, 1, OPUS_MAX_FRAME_SIZE, conn_state->opus_input_file);
        if (bytes_read > 0) {
            if (conn_state->opus_frames_sent == 0 && bytes_read >= 4) {
                if (memcmp(conn_state->opus_frame_buffer, "OggS", 4) == 0) {
                    fprintf(stderr, "ERROR: 输入文件似乎是OGG封装的Opus！\n");
                    fprintf(stderr, "服务器期望接收原始的Opus帧，而不是OGG容器格式。\n");
                    fprintf(stderr, "请先从OGG文件中提取原始的Opus帧。\n");
                    return -1;
                }
            }
            conn_state->opus_frame_size = bytes_read;

            fprintf(stdout, "发送Opus帧 #%d (%zu 字节)\n", conn_state->opus_frames_sent + 1, bytes_read);
            int result = send_ws_message(wsi, conn_state, (const char*)conn_state->opus_frame_buffer, bytes_read, 1);
            if (result == 0) {
                conn_state->opus_frames_sent++;
                g_total_audio_bytes_sent += bytes_read;
            }
            return result;
        }
        return -1;
    } else {
        // Fall back to dummy data
        return send_binary_frame(wsi, conn_state, DUMMY_BINARY_FRAME_SIZE);
    }
}

static int send_stop_listening_message(struct lws *wsi, connection_state_t *conn_state) {
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
        // Log the total audio duration
        if (conn_state->audio_start_time > 0) {
            uint64_t duration_ms = get_current_ms() - conn_state->audio_start_time;
            fprintf(stdout, "Total audio transmission time: %llu ms (%.1f seconds)\n", 
                   duration_ms, (double)duration_ms / 1000.0);
        }
    }
    return result;
}

static int send_detect_message(struct lws *wsi, connection_state_t *conn_state, const char *text) {
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

static int send_chat_message(struct lws *wsi, connection_state_t *conn_state, const char *text) {
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

static int send_start_listening_message(struct lws *wsi, connection_state_t *conn_state) {
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

static void print_audio_params(const audio_params_t *params) {
    if (!params) return;
    
    fprintf(stdout, "Audio Parameters:\n");
    fprintf(stdout, "  Format: %s\n", params->format);
    fprintf(stdout, "  Sample Rate: %d Hz\n", params->sample_rate);
    fprintf(stdout, "  Channels: %d\n", params->channels);
    fprintf(stdout, "  Frame Duration: %d ms\n", params->frame_duration);
}

static void handle_hello_message(struct lws *wsi, cJSON *json_response) {
    // Get connection state from the user parameter
    connection_state_t *conn_state = (connection_state_t *)lws_wsi_user(wsi);
    if (!conn_state) {
        fprintf(stderr, "Error: No connection state in handle_hello_message\n");
        return;
    }

    const cJSON *transport_item = cJSON_GetObjectItemCaseSensitive(json_response, "transport");
    const cJSON *session_id_item = cJSON_GetObjectItemCaseSensitive(json_response, "session_id");
    const cJSON *audio_params_item = cJSON_GetObjectItemCaseSensitive(json_response, "audio_params");
    
    // Parse session ID
    if (cJSON_IsString(session_id_item) && (session_id_item->valuestring != NULL)) {
        strncpy(conn_state->session_id, session_id_item->valuestring, sizeof(conn_state->session_id) - 1);
        conn_state->session_id[sizeof(conn_state->session_id) - 1] = '\0'; // Ensure null termination
        fprintf(stdout, "  Session ID: %s (stored)\n", conn_state->session_id);
    } else {
        fprintf(stdout, "  No session_id in hello message or not a string.\n");
    }
    
    // Parse audio parameters if available
    if (cJSON_IsObject(audio_params_item)) {
        const cJSON *format = cJSON_GetObjectItemCaseSensitive(audio_params_item, "format");
        const cJSON *sample_rate = cJSON_GetObjectItemCaseSensitive(audio_params_item, "sample_rate");
        const cJSON *channels = cJSON_GetObjectItemCaseSensitive(audio_params_item, "channels");
        const cJSON *frame_duration = cJSON_GetObjectItemCaseSensitive(audio_params_item, "frame_duration");
        
        // Set default values first
        strncpy(conn_state->audio_params.format, "opus", sizeof(conn_state->audio_params.format));
        conn_state->audio_params.sample_rate = 16000;
        conn_state->audio_params.channels = 1;
        conn_state->audio_params.frame_duration = 60;
        
        // Override with server values if provided
        if (cJSON_IsString(format) && format->valuestring != NULL) {
            strncpy(conn_state->audio_params.format, format->valuestring, 
                   sizeof(conn_state->audio_params.format) - 1);
            conn_state->audio_params.format[sizeof(conn_state->audio_params.format) - 1] = '\0';
        }
        
        if (cJSON_IsNumber(sample_rate)) {
            conn_state->audio_params.sample_rate = sample_rate->valueint;
        }
        
        if (cJSON_IsNumber(channels)) {
            conn_state->audio_params.channels = channels->valueint;
        }
        
        if (cJSON_IsNumber(frame_duration)) {
            conn_state->audio_params.frame_duration = frame_duration->valueint;
        }
        
        // Print the received audio parameters
        fprintf(stdout, "Received audio parameters from server:\n");
        print_audio_params(&conn_state->audio_params);
    } else {
        fprintf(stdout, "  No audio_params in hello message, using defaults.\n");
        print_audio_params(&conn_state->audio_params);
    }
    
    // Validate transport type
    if (cJSON_IsString(transport_item) && strcmp(transport_item->valuestring, "websocket") == 0) {
        fprintf(stdout, "Server hello message is valid.\n");
        conn_state->server_hello_received = 1;

        // Per protocol, send 'listen' message after receiving server hello
        send_start_listening_message(wsi, conn_state);
    } else {
        fprintf(stderr, "Error: Invalid or missing transport type in server hello.\n");
        conn_state->should_close = 1;
    }
}

static void handle_mcp_message(struct lws *wsi, cJSON *json_response) {
    // Get connection state from the user parameter
    connection_state_t *conn_state = (connection_state_t *)lws_wsi_user(wsi);
    if (!conn_state) {
        fprintf(stderr, "Error: No connection state in handle_mcp_message\n");
        return;
    }
    
    fprintf(stdout, "  Received MCP message.\n");
    
    // Parse the payload as JSON-RPC
    const cJSON *payload = cJSON_GetObjectItemCaseSensitive(json_response, "payload");
    if (!cJSON_IsObject(payload)) {
        fprintf(stderr, "  No payload in MCP message or not an object\n");
        return;
    }
    
    // Log the MCP message
    char *payload_str = cJSON_PrintUnformatted(payload);
    if (payload_str) {
        fprintf(stdout, "  MCP Payload: %s\n", payload_str);
        free(payload_str);
    }
    
    // Handle JSON-RPC method
    const cJSON *method = cJSON_GetObjectItemCaseSensitive(payload, "method");
    const cJSON *id = cJSON_GetObjectItemCaseSensitive(payload, "id");
    
    if (cJSON_IsString(method) && cJSON_IsNumber(id)) {
        const char *method_str = method->valuestring;
        int id_num = id->valueint;
        
        fprintf(stdout, "  JSON-RPC Method: %s, ID: %d\n", method_str, id_num);
        
        // Handle known methods
        if (strcmp(method_str, "initialize") == 0) {
            // Ensure we have a valid session_id
            if (strlen(conn_state->session_id) == 0) {
                fprintf(stderr, "Error: No session_id available for MCP response\n");
                return;
            }
            
            // Send formatted response
            if (send_json_message(wsi, conn_state, 
                "{\"session_id\":\"%s\",\"type\":\"mcp\",\"payload\":{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{}}}", 
                conn_state->session_id, id_num) != 0) {
                fprintf(stderr, "Error: Failed to send MCP response\n");
            }
        } else if (strcmp(method_str, "tools/list") == 0) {
            // Ensure we have a valid session_id
            if (strlen(conn_state->session_id) == 0) {
                fprintf(stderr, "Error: No session_id available for tools/list response\n");
                return;
            }
            
            // Send formatted response
            if (send_json_message(wsi, conn_state, 
                "{\"session_id\":\"%s\",\"type\":\"mcp\",\"payload\":{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"tools\":[]}}}", 
                conn_state->session_id, id_num) != 0) {
                fprintf(stderr, "Error: Failed to send tools/list response\n");
            }
        } else {
            fprintf(stdout, "  Unhandled MCP method: %s\n", method_str);
        }
    }
}

// Generic handler for simple message types (STT, LLM) that just need logging
static void handle_generic_message(struct lws *wsi, cJSON *json_response, const char *msg_type) {
    connection_state_t *conn_state = (connection_state_t *)lws_wsi_user(wsi);
    if (!conn_state) {
        fprintf(stderr, "Error: No connection state in handle_%s_message\n", msg_type);
        return;
    }
    
    fprintf(stdout, "  Received %s message.\n", msg_type);
    
    // Log the message
    char *json_str = cJSON_PrintUnformatted(json_response);
    if (json_str) {
        fprintf(stdout, "  %s Message: %s\n", msg_type, json_str);
        free(json_str);
    }
    
    // For STT messages, extract and display the recognized text
    if (strcmp(msg_type, "STT") == 0) {
        const cJSON *text_item = cJSON_GetObjectItemCaseSensitive(json_response, "text");
        if (cJSON_IsString(text_item) && text_item->valuestring) {
            // Save the recognized text in the connection state
            strncpy(conn_state->stt_text, text_item->valuestring, sizeof(conn_state->stt_text) - 1);
            conn_state->stt_text[sizeof(conn_state->stt_text) - 1] = '\0'; // Ensure null termination
            fprintf(stdout, "  >>> STT Recognized Text: %s\n", conn_state->stt_text);
        }
    }
}

static void handle_tts_message(struct lws *wsi, cJSON *json_response) {
    // First use the generic handler for basic logging
    handle_generic_message(wsi, json_response, "TTS");
    
    // Get connection state
    connection_state_t *conn_state = (connection_state_t *)lws_wsi_user(wsi);
    if (!conn_state) {
        fprintf(stderr, "Error: No connection state in handle_tts_message\n");
        return;
    }
    
    // TTS messages are control messages only
    // Actual audio data comes through binary frames
    
    // Check for state information
    const cJSON *state_item = cJSON_GetObjectItemCaseSensitive(json_response, "state");
    if (cJSON_IsString(state_item) && state_item->valuestring) {
        fprintf(stdout, "    TTS State: %s\n", state_item->valuestring);
        
        // Handle different TTS states
        if (strcmp(state_item->valuestring, "start") == 0) {
            fprintf(stdout, "    TTS playback starting, audio will come via binary frames\n");
        } else if (strcmp(state_item->valuestring, "stop") == 0) {
            fprintf(stdout, "    TTS playback stopped\n");
        }
    }
    
    const cJSON *text_item = cJSON_GetObjectItemCaseSensitive(json_response, "text");
    if (cJSON_IsString(text_item) && text_item->valuestring) {
        fprintf(stdout, "    TTS Text (e.g. for sentence_start): %s\n", text_item->valuestring);
    }
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
            
            // Try to open Opus input file
            conn_state->opus_input_file = fopen(OPUS_INPUT_FILE, "rb");
            if (conn_state->opus_input_file) {
                // Get file size
                fseek(conn_state->opus_input_file, 0, SEEK_END);
                long file_size = ftell(conn_state->opus_input_file);
                fseek(conn_state->opus_input_file, 0, SEEK_SET);
                
                fprintf(stdout, "Opened Opus input file: %s (size: %ld bytes)\n", OPUS_INPUT_FILE, file_size);
                conn_state->opus_test_mode = 1;
                
                // Open output file for received audio
                conn_state->opus_output_file = fopen(OPUS_OUTPUT_FILE, "wb");
                if (conn_state->opus_output_file) {
                    fprintf(stdout, "Opened Opus output file: %s\n", OPUS_OUTPUT_FILE);
                } else {
                    fprintf(stderr, "Warning: Could not open Opus output file: %s\n", OPUS_OUTPUT_FILE);
                }
            } else {
                fprintf(stdout, "No Opus input file found (%s), will use dummy data\n", OPUS_INPUT_FILE);
                conn_state->opus_test_mode = 0;
            }
                
            // Only send hello if not already sent
            if (!conn_state->hello_sent) {
                if (send_ws_message(wsi, conn_state, hello_msg, strlen(hello_msg), 0) == 0) {
                    conn_state->hello_sent = 1;
                    fprintf(stdout, "Client hello message prepared\n");
                } else {
                    fprintf(stderr, "Error: Failed to prepare hello message\n");
                }
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
                
                // Binary frames contain Opus audio data from server
                // Save to output file if available
                if (conn_state->opus_output_file && len > 0) {
                    size_t written = fwrite(in, 1, len, conn_state->opus_output_file);
                    fprintf(stdout, "Saved %zu bytes of Opus audio to output file\n", written);
                    g_total_audio_bytes_received += written;
                    
                    if (written != len) {
                        fprintf(stderr, "Warning: Only wrote %zu of %zu bytes to output file\n", written, len);
                    }
                    
                    // Flush to ensure data is written
                    fflush(conn_state->opus_output_file);
                }
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
            g_wsi = NULL;  // Clear the WebSocket instance
            connection_state_t *closed_state = (connection_state_t *)lws_wsi_user(wsi);
            if (closed_state) {
                closed_state->connected = 0;
                
                // Close any open files
                if (closed_state->opus_input_file) {
                    fclose(closed_state->opus_input_file);
                    closed_state->opus_input_file = NULL;
                }
                if (closed_state->opus_output_file) {
                    fclose(closed_state->opus_output_file);
                    closed_state->opus_output_file = NULL;
                }
            }
            interrupted = 1; // Signal to exit main loop
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
                    
                    // After sending listen message, initialize audio timing and request callback
                    if (write_state->should_send_audio) {
                        write_state->last_binary_frame_send_time_ms = get_current_ms();
                        lws_callback_on_writable(wsi);
                    }
                }
            } else if (write_state->should_send_audio && 
                      !write_state->listen_stopped && 
                      write_state->server_hello_received) {
                // If we haven't sent the listen start message yet, send it first
                if (!write_state->listen_sent) {
                    char listen_start_msg[256];
                    snprintf(listen_start_msg, sizeof(listen_start_msg),
                            "{\"type\":\"listen\","
                            "\"session_id\":\"%s\","
                            "\"state\":\"start\","
                            "\"mode\":\"manual\"}",
                            write_state->session_id);
                            
                    int result = send_ws_message(wsi, write_state, listen_start_msg, 
                                              strlen(listen_start_msg), 0);
                    if (result == 0) {
                        write_state->listen_sent = 1;
                        fprintf(stdout, "Sent listen start message, preparing to send audio frames\n");
                        // Request another callback to send the first audio frame
                        lws_callback_on_writable(wsi);
                    } else {
                        fprintf(stderr, "Error sending listen start message\n");
                    }
                    break;
                }
                
                // Check if we need to send abort message
                if (write_state->should_send_abort) {
                    write_state->should_send_abort = 0;
                    char abort_msg[512];
                    snprintf(abort_msg, sizeof(abort_msg),
                            "{\"type\":\"abort\",\"session_id\":\"%s\",\"reason\":\"client_initiated_test\"}",
                            write_state->session_id);
                    fprintf(stdout, "Sending abort message...\n");
                    send_ws_message(wsi, write_state, abort_msg, strlen(abort_msg), 0);
                    // Close connection after a short delay
                    write_state->should_close = 1;
                    lws_callback_on_writable(wsi);
                    break;
                }
                
                // Check if we should close the connection
                if (write_state->should_close) {
                    fprintf(stdout, "Closing WebSocket connection...\n");
                    // Return -1 to close the connection
                    return -1;
                }
                
                // If we get here, we've already sent the listen start message
                // and are ready to send audio frames
                // Send audio frames
                uint64_t current_ms = get_current_ms();
                
                // Check if it's time to send the next audio frame
                if (current_ms - write_state->last_binary_frame_send_time_ms >= BINARY_FRAME_SEND_INTERVAL_MS) {
                    // Send an audio frame first
                    int send_result;
                    
                    if (write_state->opus_test_mode) {
                        // Send Opus frames from file
                        if (write_state->opus_input_file && !feof(write_state->opus_input_file)) {
                            send_result = send_opus_frame(wsi, write_state);
                        } else {
                            // If we've reached EOF, rewind to beginning
                            if (write_state->opus_input_file) {
                                rewind(write_state->opus_input_file);
                                fprintf(stdout, "Rewinding Opus input file to continue sending\n");
                                send_result = send_opus_frame(wsi, write_state);
                            } else {
                                send_result = -1;
                            }
                        }
                    } else {
                        // Send dummy frames
                        send_result = send_binary_frame(wsi, write_state, DUMMY_BINARY_FRAME_SIZE);
                        if (send_result == 0) {
                            write_state->binary_frames_sent_count++;
                        }
                    }
                    
                    if (send_result == 0) {
                        // If this is the first audio frame, set the start time
                        if (write_state->audio_start_time == 0) {
                            write_state->audio_start_time = current_ms;
                            fprintf(stdout, "Started audio transmission at %llu ms\n", write_state->audio_start_time);
                            fprintf(stdout, "  Will send audio for %d ms\n", AUDIO_SEND_DURATION_MS);
                        }
                        
                        // Update the last frame send time
                        write_state->last_binary_frame_send_time_ms = current_ms;
                        
                        // Calculate elapsed time in milliseconds
                        uint64_t elapsed_ms = current_ms - write_state->audio_start_time;
                        
                        // Log frame information
                        fprintf(stdout, "  Sent audio frame: total_sent=%u, remaining_time=%llums\n",
                                (unsigned int)write_state->binary_frames_sent_count,
                                AUDIO_SEND_DURATION_MS > elapsed_ms ? AUDIO_SEND_DURATION_MS - elapsed_ms : 0);
                        uint64_t elapsed_seconds = elapsed_ms / 1000;
                        fprintf(stdout, "Audio timing: elapsed=%llu ms (%llu seconds)\n", 
                                elapsed_ms, elapsed_seconds);
                        
                        // 检查是否已经发送了足够时长的音频
                        if (elapsed_ms >= AUDIO_SEND_DURATION_MS) {
                            // Stop sending audio
                            if (!write_state->listen_stopped) {
                                fprintf(stdout, "Finished sending audio for %d ms (%.1f seconds)\n", 
                                        AUDIO_SEND_DURATION_MS, (float)AUDIO_SEND_DURATION_MS/1000.0f);
                                write_state->should_send_audio = 0;  // Stop audio sending
                                
                                // Send detect message with recognized text
                                // Use the STT recognized text if available, otherwise use a default message
                                const char *detect_text = (write_state->stt_text[0] != '\0') ? 
                                    write_state->stt_text : "[No speech detected]";
                                    
                                if (send_detect_message(wsi, write_state, detect_text) == 0) {
                                    write_state->listen_stopped = 1;
                                    write_state->should_send_abort = 1;  // Schedule abort message
                                    fprintf(stdout, "Sent detect message, scheduling abort message...\n");
                                    lws_callback_on_writable(wsi);  // Request another callback for abort
                                } else {
                                    fprintf(stderr, "Error sending detect message\n");
                                }
                            }
                        } else {
                            // Request another writeable callback to continue sending
                            lws_callback_on_writable(wsi);
                        }
                    } else {
                        fprintf(stderr, "Error preparing audio frame\n");
                    }
                } else {
                    // Not time yet, request another callback
                    lws_callback_on_writable(wsi);
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

        default:
            break;
    }
    return 0;
}

#ifdef _WIN32
static DWORD WINAPI service_thread_func(LPVOID arg)
#else
static void *service_thread_func(void *arg)
#endif
{
    struct lws_context *context = (struct lws_context *)arg;
    lwsl_user("Service thread started.\n");
    while (!interrupted && context) {
        lws_service(context, 50);
    }
    lwsl_user("Service thread exiting.\n");
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

#ifdef ENABLE_WEBSOCKET_VERBOSE
static void lws_log_emit_cb(int level, const char* line)
{
   fprintf(stderr, "%s", line);               
}
#endif

int main(int argc, char **argv) {
#ifdef ENABLE_WEBSOCKET_VERBOSE
    lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_PARSER |
        LLL_HEADER | LLL_INFO | LLL_CLIENT, lws_log_emit_cb);
#endif

#ifdef _WIN32
    // Set console to UTF-8 to display Chinese characters correctly
    SetConsoleOutputCP(CP_UTF8);
#endif
    // Initialize random number generator with current time
    srand((unsigned int)time(NULL));
    
    // Print usage information
    fprintf(stdout, "WebSocket Audio Test Client\n");
    fprintf(stdout, "===========================\n");
    
#if TEST_MODE == TEST_MODE_TEXT
    fprintf(stdout, "Test Mode: TEXT TO SPEECH\n");
    fprintf(stdout, "Test Flow:\n");
    fprintf(stdout, "1. Connect to WebSocket server and exchange hello messages\n");
    fprintf(stdout, "2. Send a chat message to trigger TTS response\n");
    fprintf(stdout, "3. Wait up to %d seconds for TTS audio\n", WAIT_FOR_RESPONSE_SECONDS);
    fprintf(stdout, "4. Close connection\n\n");
#else
    fprintf(stdout, "Test Mode: AUDIO RECOGNITION\n");
    fprintf(stdout, "Test Flow:\n");
    fprintf(stdout, "1. Connect to WebSocket server and exchange hello messages\n");
    fprintf(stdout, "2. Send 'listen start' message to begin audio streaming\n");
    fprintf(stdout, "3. Send audio data for %d seconds\n", AUDIO_SEND_DURATION_SECONDS);
    fprintf(stdout, "4. Send 'listen stop' message to end audio streaming\n");
    fprintf(stdout, "5. Wait up to %d seconds for server responses (STT, TTS, etc.)\n", WAIT_FOR_RESPONSE_SECONDS);
    fprintf(stdout, "6. Close connection\n\n");
#endif
    
    fprintf(stdout, "Audio Files:\n");
    fprintf(stdout, "- Input: '%s' (Opus audio to send)\n", OPUS_INPUT_FILE);
    fprintf(stdout, "- Output: '%s' (Opus audio received from server)\n", OPUS_OUTPUT_FILE);
    
    fprintf(stdout, "\n!!! IMPORTANT: Audio Format Requirements !!!\n");
    fprintf(stdout, "The input file must contain RAW Opus frames, NOT OGG-encapsulated Opus!\n");
    fprintf(stdout, "- Expected: Raw Opus frames (60ms duration, ~960 bytes each at 16kHz)\n");
    fprintf(stdout, "- NOT supported: .opus files (OGG container), .ogg files, or other containers\n");
    fprintf(stdout, "\nTo extract raw Opus frames from an OGG Opus file:\n");
    fprintf(stdout, "1. Use opusdec to decode to PCM: opusdec input.opus output.wav\n");
    fprintf(stdout, "2. Use opusenc to encode raw frames: opusenc --raw --raw-rate 16000 --framesize 60 output.wav raw_opus.bin\n");
    fprintf(stdout, "Or use FFmpeg: ffmpeg -i input.opus -f s16le -ar 16000 -ac 1 - | opusenc --raw --raw-rate 16000 --framesize 60 - raw_opus.bin\n");
    
#if TEST_MODE == TEST_MODE_TEXT
    fprintf(stdout, "\nTo switch to audio recognition mode, change TEST_MODE to TEST_MODE_AUDIO in the code.\n\n");
#else
    fprintf(stdout, "\nIf no input file is found, dummy data will be sent instead.\n");
    fprintf(stdout, "To test text-to-speech, change TEST_MODE to TEST_MODE_TEXT in the code.\n\n");
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
    // Note: We don't need to manually allocate connection_state_t here
    // as libwebsockets will handle it based on the per_session_data_size in protocols[]
    
    fprintf(stdout, "Connecting to %s:%d%s\n", conn_info.address, conn_info.port, conn_info.path);
    if (!lws_client_connect_via_info(&conn_info)) {
        fprintf(stderr, "lws_client_connect_via_info failed\n");
        lws_context_destroy(g_context);
        g_context = NULL;
        return 1;
    }

    // Start service thread
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
#endif

    int no_connection_printed = 0;

    while (!interrupted) {
        // Add a small delay to prevent busy-waiting in the main loop.
#if defined(_WIN32)
        Sleep(10);
#else
        usleep(10000);
#endif

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

        if (conn_state->hello_sent_time > 0 && !conn_state->server_hello_received) {
            if (time(NULL) - conn_state->hello_sent_time > HELLO_TIMEOUT_SECONDS) {
                fprintf(stderr, "Timeout: Server HELLO not received within %d seconds. Closing connection.\n", HELLO_TIMEOUT_SECONDS);
                if (g_context) {
                    if (g_wsi) {
                        lws_close_reason(g_wsi, LWS_CLOSE_STATUS_GOING_AWAY, (unsigned char *)"Hello timeout", 13);
                    }
                }
                interrupted = 1;
                if (conn_state) {
                    conn_state->connected = 0;
                }
            }
        }

#if TEST_MODE == TEST_MODE_TEXT
        // In text test mode, just wait for responses
        if (conn_state->connected && conn_state->test_message_sent) {
            // Check if we've waited long enough for responses
            if (time(NULL) - conn_state->audio_start_time >= WAIT_FOR_RESPONSE_SECONDS) {
                fprintf(stdout, "\nText Test Summary:\n");
                fprintf(stdout, "- Total audio bytes received: %d\n", g_total_audio_bytes_received);
                fprintf(stdout, "- Waited %d seconds for server responses\n", WAIT_FOR_RESPONSE_SECONDS);
                
                if (g_total_audio_bytes_received == 0) {
                    fprintf(stdout, "\nNote: No audio data received from server.\n");
                    fprintf(stdout, "The server may not support chat messages or TTS generation.\n");
                }
                
                fprintf(stdout, "\nClosing connection...\n");
                
                // Close connection
                lws_close_reason(g_wsi, LWS_CLOSE_STATUS_NORMAL, 
                               (unsigned char *)"Test completed", 14);
                interrupted = 1; // Signal to exit main loop
            }
        }
#else
        // Just trigger writeable callback if we need to send audio
        if (conn_state->connected && conn_state->should_send_audio && 
            !conn_state->pending_write && g_wsi) {
            lws_callback_on_writable(g_wsi);
        }

        // After stopping audio, wait for server responses
        if (conn_state->connected && conn_state->listen_stopped) {
            // Check if we've waited long enough for responses
            if (time(NULL) - conn_state->audio_start_time >= 
                (AUDIO_SEND_DURATION_SECONDS + WAIT_FOR_RESPONSE_SECONDS)) {
                fprintf(stdout, "\nTest Summary:\n");
                fprintf(stdout, "- Total audio bytes sent: %d\n", g_total_audio_bytes_sent);
                fprintf(stdout, "- Total audio bytes received: %d\n", g_total_audio_bytes_received);
                fprintf(stdout, "- Waited %d seconds for server responses\n", WAIT_FOR_RESPONSE_SECONDS);
                
                if (g_total_audio_bytes_received == 0) {
                    fprintf(stdout, "\nNote: No audio data received from server.\n");
                    fprintf(stdout, "This could mean:\n");
                    fprintf(stdout, "1. The server didn't recognize any speech in the audio\n");
                    fprintf(stdout, "2. The server needs more audio data or different format\n");
                    fprintf(stdout, "3. The server is still processing\n");
                }
                
                fprintf(stdout, "\nClosing connection...\n");
                
                // Close connection
                lws_close_reason(g_wsi, LWS_CLOSE_STATUS_NORMAL, 
                               (unsigned char *)"Test completed", 14);
                interrupted = 1; // Signal to exit main loop
            }
        }
#endif
    }

    fprintf(stdout, "Exiting main loop. Cleaning up...\n");

    // Signal the service thread to stop and wait for it
    interrupted = 1;

    if (g_context) {
        lwsl_user("Cancelling service for context from main thread.\n");
        // Wake up lws_service in the other thread
        lws_cancel_service(g_context);
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
