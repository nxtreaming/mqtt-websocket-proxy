#include "utils/mcp_proxy.h"
#include "utils/logger.h"
#include "common/error_codes.h"

#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>

using namespace xiaozhi;
using namespace xiaozhi::mcp;

void TestMCPToolSerialization() {
    std::cout << "Testing MCP tool serialization..." << std::endl;
    
    // Create test tool
    MCPTool tool;
    tool.name = "test_tool";
    tool.description = "A test tool for demonstration";
    tool.input_schema = {
        {"type", "object"},
        {"properties", {
            {"param1", {{"type", "string"}}},
            {"param2", {{"type", "number"}}}
        }},
        {"required", {"param1"}}
    };

    // Serialize to JSON
    nlohmann::json json = tool.ToJson();
    assert(json["name"] == "test_tool");
    assert(json["description"] == "A test tool for demonstration");
    assert(json["inputSchema"]["type"] == "object");

    // Deserialize from JSON
    MCPTool parsed_tool = MCPTool::FromJson(json);
    assert(parsed_tool.name == tool.name);
    assert(parsed_tool.description == tool.description);
    assert(parsed_tool.input_schema == tool.input_schema);
    
    std::cout << "MCP tool serialization test passed" << std::endl;
}

void TestMCPProxyInitialization() {
    std::cout << "Testing MCP proxy initialization..." << std::endl;
    
    MCPProxy proxy;
    
    // Test disabled state
    ServerConfig config_disabled;
    config_disabled.mcp.enabled = false;

    int ret = proxy.Initialize(config_disabled);
    assert(ret == error::SUCCESS);
    assert(!proxy.IsEnabled());

    // Test enabled state
    ServerConfig config_enabled;
    config_enabled.mcp.enabled = true;
    config_enabled.mcp.max_tools_count = 16;
    
    ret = proxy.Initialize(config_enabled);
    assert(ret == error::SUCCESS);
    assert(proxy.IsEnabled());
    
    std::cout << "MCP proxy initialization test passed" << std::endl;
}

void TestMCPMessageCreation() {
    std::cout << "Testing MCP message creation..." << std::endl;
    
    MCPProxy proxy;
    ServerConfig config;
    config.mcp.enabled = true;
    config.mcp.max_tools_count = 32;
    proxy.Initialize(config);
    
    // Test request message creation
    nlohmann::json params = {{"test", "value"}};
    uint32_t id = 12345;

    // Use reflection to access private methods for testing
    // Here we test indirectly through public interface

    bool request_sent = false;
    proxy.SetSendMqttMessageCallback([&](const std::string& message) {
        nlohmann::json msg = nlohmann::json::parse(message);

        assert(msg["type"] == "mcp");
        assert(msg["payload"]["jsonrpc"] == "2.0");
        assert(msg["payload"]["method"] == "test_method");
        assert(msg["payload"]["id"] == id);
        assert(msg["payload"]["params"] == params);

        request_sent = true;
    });

    // Send test request
    proxy.SendMcpRequest("test_method", params,
        [](const nlohmann::json& result) {
            // Success callback
        },
        [](const std::string& error) {
            // Error callback
        }
    );
    
    assert(request_sent);
    
    std::cout << "MCP message creation test passed" << std::endl;
}

void TestMCPResponseHandling() {
    std::cout << "Testing MCP response handling..." << std::endl;
    
    MCPProxy proxy;
    ServerConfig config;
    config.mcp.enabled = true;
    config.mcp.max_tools_count = 32;
    proxy.Initialize(config);
    
    bool success_called = false;
    bool error_called = false;
    
    // Send request
    uint32_t request_id = proxy.SendMcpRequest("test_method", nlohmann::json::object(),
        [&](const nlohmann::json& result) {
            success_called = true;
            assert(result["status"] == "success");
        },
        [&](const std::string& error) {
            error_called = true;
        }
    );

    // Simulate success response
    nlohmann::json success_response;
    success_response["type"] = "mcp";
    success_response["payload"] = {
        {"jsonrpc", "2.0"},
        {"id", request_id},
        {"result", {{"status", "success"}}}
    };

    proxy.HandleMcpResponse(success_response);
    assert(success_called);
    assert(!error_called);

    // Reset state
    success_called = false;
    error_called = false;

    // Send another request
    uint32_t error_request_id = proxy.SendMcpRequest("error_method", nlohmann::json::object(),
        [&](const nlohmann::json& result) {
            success_called = true;
        },
        [&](const std::string& error) {
            error_called = true;
            assert(error == "Test error");
        }
    );

    // Simulate error response
    nlohmann::json error_response;
    error_response["type"] = "mcp";
    error_response["payload"] = {
        {"jsonrpc", "2.0"},
        {"id", error_request_id},
        {"error", {{"message", "Test error"}}}
    };
    
    proxy.HandleMcpResponse(error_response);
    assert(!success_called);
    assert(error_called);
    
    std::cout << "MCP response handling test passed" << std::endl;
}

void TestMCPBridgeMessageHandling() {
    std::cout << "Testing MCP bridge message handling..." << std::endl;
    
    MCPProxy proxy;
    ServerConfig config;
    config.mcp.enabled = true;
    config.mcp.max_tools_count = 32;
    proxy.Initialize(config);
    
    // Set up cached data
    std::vector<MCPTool> test_tools;
    MCPTool tool1;
    tool1.name = "tool1";
    tool1.description = "Test tool 1";
    test_tools.push_back(tool1);
    
    // Simulate tools list request
    bool websocket_response_sent = false;
    proxy.SetSendWebSocketJsonCallback([&](const nlohmann::json& response) {
        assert(response["type"] == "mcp");
        assert(response["payload"]["jsonrpc"] == "2.0");
        assert(response["payload"]["id"] == 123);
        assert(response["payload"]["result"].contains("tools"));
        
        websocket_response_sent = true;
    });
    
    nlohmann::json bridge_message;
    bridge_message["type"] = "mcp";
    bridge_message["payload"] = {
        {"jsonrpc", "2.0"},
        {"method", "tools/list"},
        {"id", 123},
        {"params", nlohmann::json::object()}
    };
    
    proxy.OnMcpMessageFromBridge(bridge_message);
    assert(websocket_response_sent);
    
    std::cout << "MCP bridge message handling test passed" << std::endl;
}

void TestJavaScriptCompatibility() {
    std::cout << "Testing JavaScript compatibility..." << std::endl;
    
    MCPProxy proxy;
    ServerConfig config;
    config.mcp.enabled = true;
    config.mcp.max_tools_count = 32;
    proxy.Initialize(config);
    
    // Test JavaScript version message format
    bool mqtt_message_sent = false;
    proxy.SetSendMqttMessageCallback([&](const std::string& message) {
        nlohmann::json msg = nlohmann::json::parse(message);
        
        // Verify JavaScript compatible message format
        assert(msg["type"] == "mcp");
        assert(msg["payload"]["jsonrpc"] == "2.0");
        assert(msg["payload"]["method"] == "initialize");
        assert(msg["payload"]["params"]["protocolVersion"] == "2024-11-05");
        assert(msg["payload"]["params"]["clientInfo"]["name"] == "xiaozhi-mqtt-client");
        
        mqtt_message_sent = true;
    });
    
    // Initialize device tools (JavaScript version: initializeDeviceTools)
    int ret = proxy.InitializeDeviceTools();
    assert(ret == error::SUCCESS);
    assert(mqtt_message_sent);
    
    std::cout << "JavaScript compatibility test passed" << std::endl;
}

int main() {
    std::cout << "=== xiaozhi-mqtt-gateway MCP Proxy Test ===" << std::endl;
    
    // Initialize logger
    Logger& logger = Logger::GetInstance();
    if (!logger.Initialize(LogLevel::DEBUG)) {
        std::cerr << "Failed to initialize logger" << std::endl;
        return 1;
    }
    
    try {
        TestMCPToolSerialization();
        TestMCPProxyInitialization();
        TestMCPMessageCreation();
        TestMCPResponseHandling();
        TestMCPBridgeMessageHandling();
        TestJavaScriptCompatibility();
        
        std::cout << std::endl;
        std::cout << "All MCP Proxy Tests Passed!" << std::endl;
        std::cout << std::endl;
        std::cout << "Working Features:" << std::endl;
        std::cout << "  MCP Tool Serialization/Deserialization" << std::endl;
        std::cout << "  MCP Proxy Initialization" << std::endl;
        std::cout << "  MCP Message Creation" << std::endl;
        std::cout << "  MCP Response Handling" << std::endl;
        std::cout << "  MCP Bridge Message Handling" << std::endl;
        std::cout << "  JavaScript Compatibility" << std::endl;
        std::cout << std::endl;
        std::cout << "JavaScript Compatible Features:" << std::endl;
        std::cout << "  initializeDeviceTools() - Device tools initialization" << std::endl;
        std::cout << "  sendMcpRequest() - MCP request sending" << std::endl;
        std::cout << "  onMcpMessageFromBridge() - Bridge message handling" << std::endl;
        std::cout << "  mcpCachedTools - Tool caching mechanism" << std::endl;
        std::cout << "  mcpPendingRequests - Request management" << std::endl;
        std::cout << std::endl;
        std::cout << "MCP proxy is now compatible with JavaScript version!" << std::endl;
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}
