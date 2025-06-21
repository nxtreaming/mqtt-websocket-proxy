/**
 * @file ws_handle_msg.h
 * @brief Header file for WebSocket message handling functions
 */

#ifndef WS_HANDLE_MSG_H
#define WS_HANDLE_MSG_H

#include <libwebsockets.h>
#include "cjson/cJSON.h"
#include "ws_send_msg.h"

/**
 * @brief Handle hello message from server
 * @param wsi WebSocket instance
 * @param json_response JSON message from server
 */
void handle_hello_message(struct lws *wsi, cJSON *json_response);

/**
 * @brief Handle MCP message from server
 * @param wsi WebSocket instance
 * @param json_response JSON message from server
 */
void handle_mcp_message(struct lws *wsi, cJSON *json_response);

/**
 * @brief Handle generic message types like STT and LLM
 * @param wsi WebSocket instance
 * @param json_response JSON message from server
 * @param msg_type Type of message (e.g., "STT", "LLM")
 */
void handle_generic_message(struct lws *wsi, cJSON *json_response, const char *msg_type);

/**
 * @brief Handle TTS message from server
 * @param wsi WebSocket instance
 * @param json_response JSON message from server
 */
void handle_tts_message(struct lws *wsi, cJSON *json_response);

#endif /* WS_HANDLE_MSG_H */
