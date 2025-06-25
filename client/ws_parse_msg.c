#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ws_parse_msg.h"

static void print_audio_params(const audio_params_t *params) {
    if (!params) return;
    
    fprintf(stdout, "Audio Parameters:\n");
    fprintf(stdout, "  Format: %s\n", params->format);
    fprintf(stdout, "  Sample Rate: %d Hz\n", params->sample_rate);
    fprintf(stdout, "  Channels: %d\n", params->channels);
    fprintf(stdout, "  Frame Duration: %d ms\n", params->frame_duration);
}

void handle_hello_message(struct lws *wsi, cJSON *json_response) {
    connection_state_t *conn_state = (connection_state_t *)lws_wsi_user(wsi);
    if (!conn_state) {
        fprintf(stderr, "Error: No connection state in handle_hello_message\n");
        return;
    }

    const cJSON *transport_item = cJSON_GetObjectItemCaseSensitive(json_response, "transport");
    const cJSON *session_id_item = cJSON_GetObjectItemCaseSensitive(json_response, "session_id");
    const cJSON *audio_params_item = cJSON_GetObjectItemCaseSensitive(json_response, "audio_params");
    const cJSON *version_item = cJSON_GetObjectItemCaseSensitive(json_response, "version");
    const cJSON *features_item = cJSON_GetObjectItemCaseSensitive(json_response, "features");
    
    // Parse protocol version
    if (cJSON_IsNumber(version_item)) {
        conn_state->protocol_version = version_item->valueint;
        fprintf(stdout, "  Protocol version: %d\n", conn_state->protocol_version);
    }
    
    // Parse server features
    if (cJSON_IsObject(features_item)) {
        const cJSON *mcp_feature = cJSON_GetObjectItemCaseSensitive(features_item, "mcp");
        const cJSON *stt_feature = cJSON_GetObjectItemCaseSensitive(features_item, "stt");
        const cJSON *tts_feature = cJSON_GetObjectItemCaseSensitive(features_item, "tts");
        const cJSON *llm_feature = cJSON_GetObjectItemCaseSensitive(features_item, "llm");
        
        conn_state->features_mcp = cJSON_IsTrue(mcp_feature) ? 1 : 0;
        conn_state->features_stt = cJSON_IsTrue(stt_feature) ? 1 : 0;
        conn_state->features_tts = cJSON_IsTrue(tts_feature) ? 1 : 0;
        conn_state->features_llm = cJSON_IsTrue(llm_feature) ? 1 : 0;
        
        fprintf(stdout, "  Server features: MCP=%s, STT=%s, TTS=%s, LLM=%s\n",
                conn_state->features_mcp ? "yes" : "no",
                conn_state->features_stt ? "yes" : "no", 
                conn_state->features_tts ? "yes" : "no",
                conn_state->features_llm ? "yes" : "no");
    }
    
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
        
#ifdef WS_ENABLE_DEBUG
        // Print the received audio parameters only in debug mode
        print_audio_params(&conn_state->audio_params);
#endif
    } else {
        fprintf(stdout, "  No audio_params in hello message, using defaults.\n");
    }
    
    // Validate transport type
    if (cJSON_IsString(transport_item) && strcmp(transport_item->valuestring, "websocket") == 0) {
        change_websocket_state(conn_state, WS_STATE_AUTHENTICATED);

        // MUST enter listening state: start, otherwise the connection will be closed after 10s
        send_start_listening_message(wsi, conn_state);
        change_websocket_state(conn_state, WS_STATE_LISTENING);
    } else {
        fprintf(stderr, "Error: Invalid or missing transport type in server hello.\n");
        change_websocket_state(conn_state, WS_STATE_ERROR);
        conn_state->should_close = 1;
    }
}

void handle_mcp_message(struct lws *wsi, cJSON *json_response) {
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
            cJSON* result = cJSON_CreateObject();
            if (send_mcp_response(wsi, conn_state, id_num, result) != 0) {
                fprintf(stderr, "Error: Failed to send MCP response\n");
            }
        } else if (strcmp(method_str, "tools/list") == 0) {
            // Ensure we have a valid session_id
            if (strlen(conn_state->session_id) == 0) {
                fprintf(stderr, "Error: No session_id available for tools/list response\n");
                return;
            }
            
            // Send formatted response
            cJSON* result = cJSON_CreateObject();
            cJSON* tools_array = cJSON_CreateArray();
            cJSON_AddItemToObject(result, "tools", tools_array);
            if (send_mcp_response(wsi, conn_state, id_num, result) != 0) {
                fprintf(stderr, "Error: Failed to send tools/list response\n");
            }
        } else {
            fprintf(stdout, "  Unhandled MCP method: %s\n", method_str);
        }
    }
}

// Generic handler for simple message types (STT, LLM) that just need logging
void handle_generic_message(struct lws *wsi, cJSON *json_response, const char *msg_type) {
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

void handle_tts_message(struct lws *wsi, cJSON *json_response) {
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
