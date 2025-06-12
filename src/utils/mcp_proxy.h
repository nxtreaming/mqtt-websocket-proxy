#pragma once

#include "common/types.h"
#include "common/error_codes.h"
#include "common/constants.h"
#include "utils/logger.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <memory>
#include <atomic>

namespace xiaozhi {
namespace mcp {

/**
 * @brief MCP request structure
 */
struct MCPRequest {
    uint32_t id;
    std::string method;
    nlohmann::json params;
    std::function<void(const nlohmann::json&)> resolve;
    std::function<void(const std::string&)> reject;
    std::chrono::steady_clock::time_point timestamp;
};

/**
 * @brief MCP tool information
 */
struct MCPTool {
    std::string name;
    std::string description;
    nlohmann::json input_schema;

    // Construct from JSON
    static MCPTool FromJson(const nlohmann::json& json);

    // Convert to JSON
    nlohmann::json ToJson() const;
};

/**
 * @brief MCP proxy class
 *
 * Implements simplified MCP proxy functionality compatible with JavaScript version:
 * - Tool caching and management
 * - MCP request/response handling
 * - Device tool initialization
 *
 * JavaScript compatible methods:
 * - initializeDeviceTools()
 * - sendMcpRequest()
 * - onMcpMessageFromBridge()
 */
class MCPProxy {
public:
    // Callback types
    using SendMessageCallback = std::function<void(const std::string&)>;
    using SendJsonCallback = std::function<void(const nlohmann::json&)>;

    /**
     * @brief Constructor
     */
    MCPProxy();

    /**
     * @brief Destructor
     */
    ~MCPProxy();

    /**
     * @brief Initialize MCP proxy
     * @param config Server configuration
     * @return Error code, 0 indicates success
     */
    int Initialize(const ServerConfig& config);

    /**
     * @brief Set callback for sending MQTT messages
     * @param callback Send message callback
     */
    void SetSendMqttMessageCallback(SendMessageCallback callback) {
        send_mqtt_message_callback_ = std::move(callback);
    }

    /**
     * @brief Set callback for sending WebSocket JSON messages
     * @param callback Send JSON callback
     */
    void SetSendWebSocketJsonCallback(SendJsonCallback callback) {
        send_websocket_json_callback_ = std::move(callback);
    }

    /**
     * @brief Initialize device tools (JavaScript version: initializeDeviceTools)
     * @return Error code, 0 indicates success
     */
    int InitializeDeviceTools();

    /**
     * @brief Send MCP request (JavaScript version: sendMcpRequest)
     * @param method MCP method name
     * @param params Request parameters
     * @param resolve Success callback
     * @param reject Failure callback
     * @return Request ID
     */
    uint32_t SendMcpRequest(const std::string& method,
                           const nlohmann::json& params,
                           std::function<void(const nlohmann::json&)> resolve,
                           std::function<void(const std::string&)> reject);

    /**
     * @brief Handle MCP message from bridge (JavaScript version: onMcpMessageFromBridge)
     * @param message MCP message
     */
    void OnMcpMessageFromBridge(const nlohmann::json& message);

    /**
     * @brief Handle MCP response message
     * @param message MCP response message
     */
    void HandleMcpResponse(const nlohmann::json& message);

    /**
     * @brief Check if tools are cached
     * @return true if tools are cached
     */
    bool HasCachedTools() const {
        return !mcp_cached_tools_.empty();
    }

    /**
     * @brief Get cached tools list
     * @return Tools list
     */
    const std::vector<MCPTool>& GetCachedTools() const {
        return mcp_cached_tools_;
    }

    /**
     * @brief Get cached initialization result
     * @return Initialization result
     */
    const nlohmann::json& GetCachedInitialize() const {
        return mcp_cached_initialize_;
    }

    /**
     * @brief Check if MCP is enabled
     * @return true if enabled
     */
    bool IsEnabled() const {
        return config_.mcp.enabled;
    }

    /**
     * @brief Clean up timeout requests
     */
    void CleanupTimeoutRequests();

private:
    /**
     * @brief Generate next request ID
     * @return Request ID
     */
    uint32_t GenerateRequestId() {
        return mcp_request_id_.fetch_add(1);
    }

    /**
     * @brief Create MCP message
     * @param method Method name
     * @param id Request ID
     * @param params Parameters
     * @return MCP message JSON
     */
    nlohmann::json CreateMcpMessage(const std::string& method,
                                   uint32_t id,
                                   const nlohmann::json& params);

    /**
     * @brief Create MCP response message
     * @param id Request ID
     * @param result Result
     * @return MCP response JSON
     */
    nlohmann::json CreateMcpResponse(uint32_t id, const nlohmann::json& result);

    /**
     * @brief Request tools list (JavaScript version: tools/list with pagination)
     * @param cursor Pagination cursor
     */
    void RequestToolsList(const std::string& cursor = "");

private:
    ServerConfig config_;

    // MCP state (JavaScript version compatible)
    std::atomic<uint32_t> mcp_request_id_{constants::MCP_INITIAL_REQUEST_ID};
    std::unordered_map<uint32_t, std::unique_ptr<MCPRequest>> mcp_pending_requests_;
    std::vector<MCPTool> mcp_cached_tools_;
    nlohmann::json mcp_cached_initialize_;

    // Callback functions
    SendMessageCallback send_mqtt_message_callback_;
    SendJsonCallback send_websocket_json_callback_;

    // Initialization state
    bool initialized_ = false;
    bool tools_initialized_ = false;
};

} // namespace mcp
} // namespace xiaozhi
