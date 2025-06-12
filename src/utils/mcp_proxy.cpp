#include "utils/mcp_proxy.h"
#include "common/constants.h"

#include <chrono>

namespace xiaozhi {
namespace mcp {

// MCPTool implementation
MCPTool MCPTool::FromJson(const nlohmann::json& json) {
    MCPTool tool;
    
    if (json.contains("name")) {
        tool.name = json["name"].get<std::string>();
    }
    
    if (json.contains("description")) {
        tool.description = json["description"].get<std::string>();
    }
    
    if (json.contains("inputSchema")) {
        tool.input_schema = json["inputSchema"];
    }
    
    return tool;
}

nlohmann::json MCPTool::ToJson() const {
    nlohmann::json json;
    json["name"] = name;
    json["description"] = description;
    json["inputSchema"] = input_schema;
    return json;
}

// MCPProxy implementation
MCPProxy::MCPProxy() = default;

MCPProxy::~MCPProxy() = default;

int MCPProxy::Initialize(const ServerConfig& config) {
    config_ = config;
    
    if (!config_.mcp.enabled) {
        LOG_INFO("MCP proxy disabled in configuration");
        return error::SUCCESS;
    }
    
    LOG_INFO("MCP proxy initialized with max_tools_count: " + std::to_string(config_.mcp.max_tools_count));
    initialized_ = true;
    
    return error::SUCCESS;
}

int MCPProxy::InitializeDeviceTools() {
    if (!IsEnabled()) {
        LOG_DEBUG("MCP not enabled, skipping device tools initialization");
        return error::SUCCESS;
    }
    
    if (tools_initialized_) {
        LOG_DEBUG("Device tools already initialized");
        return error::SUCCESS;
    }
    
    LOG_INFO("Initializing device tools (MCP proxy)...");
    
    // Reset state (JavaScript version: this.mcpRequestId = 10000)
    mcp_request_id_.store(constants::MCP_INITIAL_REQUEST_ID);
    mcp_pending_requests_.clear();
    mcp_cached_tools_.clear();

    try {
        // Send initialize request (JavaScript version: this.mcpCachedInitialize = await this.sendMcpRequest('initialize', {...}))
        nlohmann::json init_params;
        init_params["protocolVersion"] = "2024-11-05";
        init_params["capabilities"] = nlohmann::json::object();
        init_params["clientInfo"] = {
            {"name", "xiaozhi-mqtt-client"},
            {"version", "1.0.0"}
        };

        // Send initialize request
        SendMcpRequest("initialize", init_params,
            [this](const nlohmann::json& result) {
                mcp_cached_initialize_ = result;
                LOG_INFO("MCP initialize successful");

                // Send notifications/initialized (JavaScript version)
                if (send_mqtt_message_callback_) {
                    nlohmann::json notify_msg;
                    notify_msg["type"] = "mcp";
                    notify_msg["payload"] = {
                        {"jsonrpc", "2.0"},
                        {"method", "notifications/initialized"}
                    };
                    send_mqtt_message_callback_(notify_msg.dump());
                }

                // Start getting tools list
                RequestToolsList();
            },
            [this](const std::string& error) {
                LOG_ERROR("MCP initialize failed: " + error);
            }
        );
        
        tools_initialized_ = true;
        return error::SUCCESS;
        
    } catch (const std::exception& e) {
        LOG_ERROR("Error initializing device tools: " + std::string(e.what()));
        return error::MCP_INITIALIZATION_FAILED;
    }
}

uint32_t MCPProxy::SendMcpRequest(const std::string& method, 
                                 const nlohmann::json& params,
                                 std::function<void(const nlohmann::json&)> resolve,
                                 std::function<void(const std::string&)> reject) {
    if (!IsEnabled()) {
        if (reject) {
            reject("MCP not enabled");
        }
        return 0;
    }
    
    uint32_t id = GenerateRequestId();
    
    // Create request record (JavaScript version: this.mcpPendingRequests[id] = { resolve, reject })
    auto request = std::make_unique<MCPRequest>();
    request->id = id;
    request->method = method;
    request->params = params;
    request->resolve = std::move(resolve);
    request->reject = std::move(reject);
    request->timestamp = std::chrono::steady_clock::now();

    mcp_pending_requests_[id] = std::move(request);

    // Send MCP message (JavaScript version: this.sendMqttMessage(JSON.stringify({...})))
    if (send_mqtt_message_callback_) {
        nlohmann::json message = CreateMcpMessage(method, id, params);
        send_mqtt_message_callback_(message.dump());

        LOG_DEBUG("Sent MCP request: method=" + method + ", id=" + std::to_string(id));
    } else {
        LOG_ERROR("No MQTT message callback set for MCP request");
        if (mcp_pending_requests_[id]->reject) {
            mcp_pending_requests_[id]->reject("No MQTT callback");
        }
        mcp_pending_requests_.erase(id);
    }
    
    return id;
}

void MCPProxy::OnMcpMessageFromBridge(const nlohmann::json& message) {
    if (!IsEnabled()) {
        return;
    }
    
    try {
        const auto& payload = message["payload"];
        std::string method = payload.value("method", "");
        uint32_t id = payload.value("id", 0);
        
        LOG_DEBUG("Handling MCP message from bridge: method=" + method + ", id=" + std::to_string(id));
        
        // JavaScript version processing logic
        if (method == "initialize") {
            // Return cached initialization result
            if (send_websocket_json_callback_) {
                nlohmann::json response;
                response["type"] = "mcp";
                response["payload"] = CreateMcpResponse(id, mcp_cached_initialize_);
                send_websocket_json_callback_(response);
                LOG_DEBUG("Sent cached initialize result");
            }
        } else if (method == "tools/list") {
            // Return cached tools list
            if (send_websocket_json_callback_) {
                nlohmann::json tools_array = nlohmann::json::array();
                for (const auto& tool : mcp_cached_tools_) {
                    tools_array.push_back(tool.ToJson());
                }

                nlohmann::json result;
                result["tools"] = tools_array;

                nlohmann::json response;
                response["type"] = "mcp";
                response["payload"] = CreateMcpResponse(id, result);
                send_websocket_json_callback_(response);
                LOG_DEBUG("Sent cached tools list: " + std::to_string(mcp_cached_tools_.size()) + " tools");
            }
        } else if (method == "notifications/initialized") {
            // JavaScript version: do nothing
            LOG_DEBUG("Received notifications/initialized - no action needed");
        } else {
            LOG_WARN("Unknown MCP method from bridge: " + method);
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR("Error handling MCP message from bridge: " + std::string(e.what()));
    }
}

void MCPProxy::HandleMcpResponse(const nlohmann::json& message) {
    if (!IsEnabled()) {
        return;
    }
    
    try {
        const auto& payload = message["payload"];
        uint32_t id = payload.value("id", 0);
        
        auto it = mcp_pending_requests_.find(id);
        if (it == mcp_pending_requests_.end()) {
            LOG_WARN("Received MCP response for unknown request ID: " + std::to_string(id));
            return;
        }
        
        auto& request = it->second;
        
        if (payload.contains("error")) {
            // Handle error response
            std::string error_msg = payload["error"].value("message", "Unknown error");
            LOG_ERROR("MCP request failed: method=" + request->method + ", error=" + error_msg);

            if (request->reject) {
                request->reject(error_msg);
            }
        } else if (payload.contains("result")) {
            // Handle success response
            LOG_DEBUG("MCP request successful: method=" + request->method + ", id=" + std::to_string(id));

            if (request->resolve) {
                request->resolve(payload["result"]);
            }
        } else {
            LOG_WARN("MCP response missing both error and result: id=" + std::to_string(id));
        }

        // Clean up request
        mcp_pending_requests_.erase(it);
        
    } catch (const std::exception& e) {
        LOG_ERROR("Error handling MCP response: " + std::string(e.what()));
    }
}

void MCPProxy::CleanupTimeoutRequests() {
    if (!IsEnabled()) {
        return;
    }
    
    auto now = std::chrono::steady_clock::now();
    auto timeout_duration = std::chrono::milliseconds(constants::MCP_REQUEST_TIMEOUT_MS);
    
    for (auto it = mcp_pending_requests_.begin(); it != mcp_pending_requests_.end();) {
        if (now - it->second->timestamp > timeout_duration) {
            LOG_WARN("MCP request timeout: method=" + it->second->method + ", id=" + std::to_string(it->first));
            
            if (it->second->reject) {
                it->second->reject("Request timeout");
            }
            
            it = mcp_pending_requests_.erase(it);
        } else {
            ++it;
        }
    }
}

nlohmann::json MCPProxy::CreateMcpMessage(const std::string& method, 
                                         uint32_t id, 
                                         const nlohmann::json& params) {
    nlohmann::json message;
    message["type"] = "mcp";
    message["payload"] = {
        {"jsonrpc", "2.0"},
        {"method", method},
        {"id", id},
        {"params", params}
    };
    return message;
}

nlohmann::json MCPProxy::CreateMcpResponse(uint32_t id, const nlohmann::json& result) {
    return {
        {"jsonrpc", "2.0"},
        {"id", id},
        {"result", result}
    };
}

void MCPProxy::RequestToolsList(const std::string& cursor) {
    // JavaScript version tools list retrieval logic
    nlohmann::json params;
    if (!cursor.empty()) {
        params["cursor"] = cursor;
    }

    SendMcpRequest("tools/list", params,
        [this](const nlohmann::json& result) {
            try {
                // Parse tools list
                if (result.contains("tools") && result["tools"].is_array()) {
                    const auto& tools_json = result["tools"];

                    for (const auto& tool_json : tools_json) {
                        // Check if maximum tools count limit is exceeded
                        if (mcp_cached_tools_.size() >= config_.mcp.max_tools_count) {
                            LOG_WARN("Reached maximum tools count: " + std::to_string(config_.mcp.max_tools_count));
                            break;
                        }

                        MCPTool tool = MCPTool::FromJson(tool_json);
                        mcp_cached_tools_.push_back(tool);
                    }

                    LOG_INFO("Loaded " + std::to_string(tools_json.size()) + " tools, total: " +
                             std::to_string(mcp_cached_tools_.size()));
                }

                // Check if there are more tools (JavaScript version: cursor = nextCursor)
                if (result.contains("nextCursor") && !result["nextCursor"].is_null()) {
                    std::string next_cursor = result["nextCursor"].get<std::string>();

                    // Check if we can still load more tools
                    if (mcp_cached_tools_.size() < config_.mcp.max_tools_count) {
                        LOG_DEBUG("Requesting more tools with cursor: " + next_cursor);
                        RequestToolsList(next_cursor);
                    } else {
                        LOG_INFO("Reached maximum tools limit, stopping pagination");
                    }
                } else {
                    LOG_INFO("Device tools initialization completed: " + std::to_string(mcp_cached_tools_.size()) + " tools cached");
                }

            } catch (const std::exception& e) {
                LOG_ERROR("Error processing tools list: " + std::string(e.what()));
            }
        },
        [this](const std::string& error) {
            LOG_ERROR("Failed to get tools list: " + error);
        }
    );
}

} // namespace mcp
} // namespace xiaozhi
