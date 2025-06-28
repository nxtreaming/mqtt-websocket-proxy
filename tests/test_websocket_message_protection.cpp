// Fix Windows header conflicts
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <iostream>
#include <cassert>
#include <cstring>
#include <cstdlib>

// Mock function counters
static int mock_lws_callback_on_writable_called = 0;
static int mock_lws_cancel_service_called = 0;
static int mock_lws_write_called = 0;

// Include the C headers we want to test
extern "C" {
    // Include libwebsockets first to get the real types
    #include <libwebsockets.h>

    // Include the actual header we want to test
    #include "ws_send_msg.h"

    // Override the libwebsockets functions with our mocks
    #undef lws_callback_on_writable
    #undef lws_cancel_service
    #undef lws_write

    // Mock libwebsockets functions
    int lws_callback_on_writable(struct lws* wsi) {
        (void)wsi;
        mock_lws_callback_on_writable_called++;
        return 0;
    }

    void lws_cancel_service(struct lws_context* context) {
        (void)context;
        mock_lws_cancel_service_called++;
    }

    int lws_write(struct lws* wsi, unsigned char* buf, size_t len, enum lws_write_protocol protocol) {
        (void)wsi;
        (void)buf;
        (void)protocol;
        mock_lws_write_called++;
        std::cout << "Mock lws_write called: " << len << " bytes, protocol: " << protocol << std::endl;
        return static_cast<int>(len); // Mock successful write
    }

    // Mock global context
    struct lws_context* g_context = reinterpret_cast<struct lws_context*>(0x12345678);
}

using namespace std;

class WebSocketMessageProtectionTest {
private:
    struct lws* mock_wsi;
    connection_state_t conn_state;

public:
    WebSocketMessageProtectionTest() {
        // Reset mock counters
        mock_lws_callback_on_writable_called = 0;
        mock_lws_cancel_service_called = 0;
        mock_lws_write_called = 0;

        // Initialize test objects
        mock_wsi = nullptr; // We'll use nullptr as a mock WebSocket instance
        init_connection_state(&conn_state);
    }
    
    void test_text_message_immediate_send() {
        cout << "\n=== 测试 Text 消息立即发送 ===" << endl;
        
        // Test 1: Send text message (should be sent immediately)
        cout << "\n测试1: 发送 text 消息（立即发送）" << endl;
        const char* text_msg1 = "{\"type\":\"hello\",\"session_id\":\"123\"}";
        int result1 = send_ws_message(mock_wsi, &conn_state, text_msg1, strlen(text_msg1), 0);
        
        cout << "第一个 text 消息发送结果: " << result1 << " (期望: 0)" << endl;
        cout << "pending_write 状态: " << conn_state.pending_write << " (期望: 0 - text 消息立即发送)" << endl;
        
        assert(result1 == 0);
        assert(conn_state.pending_write == 0); // text messages are sent immediately
        
        // Test 2: Send multiple text messages consecutively (all should succeed)
        cout << "\n测试2: 连续发送多个 text 消息" << endl;
        const char* text_msg2 = "{\"type\":\"listen\",\"state\":\"start\"}";
        const char* text_msg3 = "{\"type\":\"chat\",\"text\":\"Hello\"}";
        
        int result2 = send_ws_message(mock_wsi, &conn_state, text_msg2, strlen(text_msg2), 0);
        int result3 = send_ws_message(mock_wsi, &conn_state, text_msg3, strlen(text_msg3), 0);
        
        cout << "第二个 text 消息发送结果: " << result2 << " (期望: 0)" << endl;
        cout << "第三个 text 消息发送结果: " << result3 << " (期望: 0)" << endl;
        
        assert(result2 == 0);
        assert(result3 == 0);
        assert(conn_state.pending_write == 0); // Still should be 0
        
        cout << "✓ Text 消息立即发送测试通过" << endl;
    }
    
    void test_binary_message_buffered_send() {
        cout << "\n=== 测试 Binary 消息缓冲发送 ===" << endl;
        
        // Test 1: Send binary message (should use buffering)
        cout << "\n测试1: 发送 binary 消息（使用缓冲机制）" << endl;
        const char* binary_msg1 = "binary_data_1";
        int result1 = send_ws_message(mock_wsi, &conn_state, binary_msg1, strlen(binary_msg1), 1);
        
        cout << "第一个 binary 消息发送结果: " << result1 << " (期望: 0)" << endl;
        cout << "pending_write 状态: " << conn_state.pending_write << " (期望: 1 - binary 消息使用缓冲)" << endl;
        cout << "write_len: " << conn_state.write_len << " (期望: " << strlen(binary_msg1) << ")" << endl;
        
        assert(result1 == 0);
        assert(conn_state.pending_write == 1);
        assert(conn_state.write_len == strlen(binary_msg1));
        
        // Test 2: Send another binary message while one is pending (should be dropped)
        cout << "\n测试2: 在有 pending binary 消息时发送新的 binary 消息" << endl;
        const char* binary_msg2 = "binary_data_2";
        int result2 = send_ws_message(mock_wsi, &conn_state, binary_msg2, strlen(binary_msg2), 1);
        
        cout << "第二个 binary 消息发送结果: " << result2 << " (期望: -2)" << endl;
        cout << "pending_write 状态: " << conn_state.pending_write << " (期望: 1)" << endl;
        cout << "write_len: " << conn_state.write_len << " (期望: " << strlen(binary_msg1) << " - 应该还是第一个 binary 消息的长度)" << endl;
        
        assert(result2 == -2);
        assert(conn_state.pending_write == 1);
        assert(conn_state.write_len == strlen(binary_msg1)); // Should still be the first message length
        
        // Verify buffer content hasn't been overwritten
        char buffer_content[256];
        memcpy(buffer_content, conn_state.write_buf + LWS_PRE, conn_state.write_len);
        buffer_content[conn_state.write_len] = '\0';
        cout << "缓冲区内容: '" << buffer_content << "' (期望: '" << binary_msg1 << "')" << endl;
        assert(strcmp(buffer_content, binary_msg1) == 0);
        
        cout << "✓ Binary 消息缓冲发送测试通过" << endl;
    }
    
    void test_mixed_message_scenarios() {
        cout << "\n=== 测试混合消息场景 ===" << endl;
        
        // Test: Send text message while binary message is pending
        cout << "\n测试: 在有 pending binary 消息时发送 text 消息" << endl;
        const char* text_msg = "{\"type\":\"abort\"}";
        int result = send_ws_message(mock_wsi, &conn_state, text_msg, strlen(text_msg), 0);
        
        cout << "在有 pending binary 时发送 text 消息结果: " << result << " (期望: 0)" << endl;
        cout << "pending_write 状态: " << conn_state.pending_write << " (期望: 1 - binary 消息仍然 pending)" << endl;
        
        assert(result == 0); // text message should succeed
        assert(conn_state.pending_write == 1); // binary message still pending
        
        cout << "✓ 混合消息场景测试通过" << endl;
    }
    
    void test_json_message_functions() {
        cout << "\n=== 测试 JSON 消息函数 ===" << endl;
        
        // Clear pending state first
        conn_state.pending_write = 0;
        strcpy(conn_state.session_id, "test_session_123");
        
        cout << "\n测试 JSON 消息立即发送" << endl;
        int result1 = send_chat_message(mock_wsi, &conn_state, "Hello from JSON");
        cout << "JSON 消息发送结果: " << result1 << " (期望: 0)" << endl;
        cout << "pending_write 状态: " << conn_state.pending_write << " (期望: 0 - JSON 消息立即发送)" << endl;
        assert(result1 == 0);
        assert(conn_state.pending_write == 0);
        
        // Test multiple JSON messages
        int result2 = send_start_listening_message(mock_wsi, &conn_state);
        int result3 = send_stop_listening_message(mock_wsi, &conn_state);
        
        cout << "start listening 消息发送结果: " << result2 << " (期望: 0)" << endl;
        cout << "stop listening 消息发送结果: " << result3 << " (期望: 0)" << endl;
        
        assert(result2 == 0);
        assert(result3 == 0);
        assert(conn_state.pending_write == 0);
        
        cout << "✓ JSON 消息函数测试通过" << endl;
    }
    
    void run_all_tests() {
        cout << "开始测试改进的 WebSocket 消息保护机制..." << endl;
        cout << "- Text 消息（JSON 控制指令）：立即发送" << endl;
        cout << "- Binary 消息（音频数据）：缓冲发送，防止覆盖" << endl;
        
        test_text_message_immediate_send();
        test_binary_message_buffered_send();
        test_mixed_message_scenarios();
        test_json_message_functions();
        
        cout << "\n=== 所有测试完成! ===" << endl;
        cout << "改进方案验证成功：" << endl;
        cout << "✓ Text 消息立即发送，无需等待" << endl;
        cout << "✓ Binary 消息使用缓冲机制，防止数据损坏" << endl;
        cout << "✓ 混合发送场景正常工作" << endl;
        cout << "✓ JSON 消息函数正常工作" << endl;
        
        cout << "\n统计信息：" << endl;
        cout << "lws_callback_on_writable 调用次数: " << mock_lws_callback_on_writable_called << endl;
        cout << "lws_cancel_service 调用次数: " << mock_lws_cancel_service_called << endl;
        cout << "lws_write 调用次数: " << mock_lws_write_called << endl;
    }
};

int main() {
    cout << "=== WebSocket Message Protection Test ===" << endl;
    
    try {
        WebSocketMessageProtectionTest test;
        test.run_all_tests();
        
        cout << "\n所有测试通过！" << endl;
        return 0;
    } catch (const exception& e) {
        cerr << "测试失败: " << e.what() << endl;
        return 1;
    } catch (...) {
        cerr << "测试失败: 未知错误" << endl;
        return 1;
    }
}
