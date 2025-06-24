# WebSocket 客户端实现分析与开发文档

## 概述

本文档基于 `client/ws_send_msg.c` 和 `client/ws_parse_msg.c` 的实现，结合 `docs/websocket.md` 协议规范，对WebSocket客户端的消息发送和解析功能进行全面分析，并提供开发指导。

## 1. 架构概览

### 1.1 核心组件

- **ws_send_msg.c**: 负责构造和发送各类WebSocket消息
- **ws_parse_msg.c**: 负责解析服务器返回的消息
- **wsmate.c**: 主程序，提供交互式命令行界面
- **ws_audio_utils.c**: 音频处理工具（MP3播放等）

### 1.2 状态管理

客户端采用正式的状态机管理连接生命周期：

```c
typedef enum {
    WS_STATE_DISCONNECTED = 0,  // 初始状态，未连接
    WS_STATE_CONNECTING,        // WebSocket连接进行中
    WS_STATE_CONNECTED,         // WebSocket已连接，等待hello交换
    WS_STATE_HELLO_SENT,        // 客户端hello已发送，等待服务器hello
    WS_STATE_AUTHENTICATED,     // Hello交换完成，准备操作
    WS_STATE_LISTENING,         // 监听模式（音频流传输）
    WS_STATE_SPEAKING,          // 说话/处理模式
    WS_STATE_ERROR,             // 错误状态
    WS_STATE_CLOSING            // 连接关闭中
} websocket_state_t;
```

## 2. 消息发送实现分析

### 2.1 核心发送函数

#### 2.1.1 基础消息构造

```c
static cJSON* create_base_message(connection_state_t* conn_state, const char* type) {
    // 创建包含 session_id 和 type 的基础消息结构
    // 所有消息都必须包含这两个字段
}
```

**✅ 优点**: 
- 确保所有消息都包含必需的 `session_id` 和 `type` 字段
- 统一的错误处理和JSON对象管理

#### 2.1.2 Listen 消息实现

```c
// 开始监听消息
int send_start_listening_message(struct lws *wsi, connection_state_t *conn_state) {
    cJSON *root = create_base_message(conn_state, "listen");
    cJSON_AddStringToObject(root, "state", "start");
    
    // 添加音频参数
    cJSON *audio_params = cJSON_CreateObject();
    cJSON_AddStringToObject(audio_params, "format", conn_state->audio_params.format);
    cJSON_AddNumberToObject(audio_params, "sample_rate", conn_state->audio_params.sample_rate);
    cJSON_AddNumberToObject(audio_params, "channels", conn_state->audio_params.channels);
    cJSON_AddNumberToObject(audio_params, "frame_duration", conn_state->audio_params.frame_duration);
    cJSON_AddItemToObject(root, "audio_params", audio_params);
    
    return send_json_object(wsi, conn_state, root);
}
```

**⚠️ 协议差异**: 
- 实现中未包含 `mode` 字段，而协议文档示例中常包含 `"mode": "manual"`
- 音频参数的包含可能不是协议必需的

#### 2.1.3 检测和聊天消息

```c
// 检测消息（唤醒词检测）
int send_detect_message(struct lws *wsi, connection_state_t *conn_state, const char *text) {
    cJSON *root = create_base_message(conn_state, "listen");
    cJSON_AddStringToObject(root, "state", "detect");
    cJSON_AddStringToObject(root, "text", text);
    return send_json_object(wsi, conn_state, root);
}

// 聊天消息（文本转语音）
int send_chat_message(struct lws *wsi, connection_state_t *conn_state, const char *text) {
    cJSON *root = create_base_message(conn_state, "listen");
    cJSON_AddStringToObject(root, "mode", "manual");  // ← 仅在此处添加mode字段
    cJSON_AddStringToObject(root, "state", "detect");
    cJSON_AddStringToObject(root, "text", text);
    return send_json_object(wsi, conn_state, root);
}
```

**⚠️ 不一致性**: 
- `send_chat_message` 包含 `mode` 字段，但 `send_detect_message` 不包含
- 两个函数功能相似，可能存在代码重复

### 2.2 MCP 协议支持

```c
int send_mcp_response(struct lws* wsi, connection_state_t* conn_state, int rpc_id, cJSON* result) {
    cJSON *root = create_base_message(conn_state, "mcp");
    
    // 构造JSON-RPC 2.0响应
    cJSON *payload = cJSON_CreateObject();
    cJSON_AddStringToObject(payload, "jsonrpc", "2.0");
    cJSON_AddNumberToObject(payload, "id", rpc_id);
    cJSON_AddItemToObject(payload, "result", result);
    
    cJSON_AddItemToObject(root, "payload", payload);
    return send_json_object(wsi, conn_state, root);
}
```

**✅ 优点**: 
- 完全符合JSON-RPC 2.0规范
- 正确的MCP消息封装格式

### 2.3 Hello 消息生成

**⚠️ 当前限制**: Hello消息在 `wsmate.c` 中以固定字符串定义：

```c
static const char *g_hello_msg = 
    "{\"type\":\"hello\","
    "\"version\":1,"
    "\"features\":{\"mcp\":true,\"llm\":true,\"stt\":true,\"tts\":true},"
    "\"transport\":\"websocket\","
    "\"audio_params\":{"
        "\"format\":\"opus\","
        "\"sample_rate\":16000,"
        "\"channels\":1,"
        "\"frame_duration\":40}}";
```

**改进建议**: 应根据 `connection_state_t` 动态生成，支持可配置的特性和音频参数。

## 3. 消息解析实现分析

### 3.1 Hello 消息处理

```c
void handle_hello_message(struct lws *wsi, cJSON *json_response) {
    // 解析协议版本
    if (cJSON_IsNumber(version_item)) {
        conn_state->protocol_version = version_item->valueint;
    }
    
    // 解析服务器特性
    if (cJSON_IsObject(features_item)) {
        conn_state->features_mcp = cJSON_IsTrue(mcp_feature) ? 1 : 0;
        conn_state->features_stt = cJSON_IsTrue(stt_feature) ? 1 : 0;
        conn_state->features_tts = cJSON_IsTrue(tts_feature) ? 1 : 0;
        conn_state->features_llm = cJSON_IsTrue(llm_feature) ? 1 : 0;
    }
    
    // 解析会话ID
    if (cJSON_IsString(session_id_item)) {
        strncpy(conn_state->session_id, session_id_item->valuestring, 
                sizeof(conn_state->session_id) - 1);
    }
    
    // 解析音频参数
    if (cJSON_IsObject(audio_params_item)) {
        // 使用服务器提供的音频参数覆盖默认值
    }
    
    // 验证传输类型并进入认证状态
    if (strcmp(transport_item->valuestring, "websocket") == 0) {
        change_websocket_state(conn_state, WS_STATE_AUTHENTICATED);
        send_start_listening_message(wsi, conn_state);
    }
}
```

**✅ 优点**: 
- 完整解析所有协议字段
- 自动状态转换和监听启动
- 支持服务器音频参数覆盖

### 3.2 MCP 消息处理

```c
void handle_mcp_message(struct lws *wsi, cJSON *json_response) {
    const cJSON *payload = cJSON_GetObjectItemCaseSensitive(json_response, "payload");
    const cJSON *method = cJSON_GetObjectItemCaseSensitive(payload, "method");
    const cJSON *id = cJSON_GetObjectItemCaseSensitive(payload, "id");
    
    if (strcmp(method_str, "initialize") == 0) {
        cJSON* result = cJSON_CreateObject();
        send_mcp_response(wsi, conn_state, id_num, result);
    } else if (strcmp(method_str, "tools/list") == 0) {
        cJSON* result = cJSON_CreateObject();
        cJSON* tools_array = cJSON_CreateArray();
        cJSON_AddItemToObject(result, "tools", tools_array);
        send_mcp_response(wsi, conn_state, id_num, result);
    }
}
```

**✅ 优点**: 
- 正确处理JSON-RPC 2.0方法调用
- 支持标准MCP初始化流程
- 空工具列表响应（适合测试客户端）

### 3.3 TTS 消息处理

```c
void handle_tts_message(struct lws *wsi, cJSON *json_response) {
    const cJSON *state_item = cJSON_GetObjectItemCaseSensitive(json_response, "state");
    
    if (strcmp(state_item->valuestring, "start") == 0) {
        fprintf(stdout, "TTS playback starting, audio will come via binary frames\n");
    } else if (strcmp(state_item->valuestring, "stop") == 0) {
        fprintf(stdout, "TTS playback stopped\n");
    }
}
```

**⚠️ 限制**: 
- 仅提供日志记录，未实现状态转换
- 未处理 `sentence_start` 状态和文本显示

## 4. 音频处理能力

### 4.1 Opus 音频发送

客户端支持从文件读取Opus音频数据并发送：

```c
static void handle_opus(struct lws* wsi, connection_state_t* conn_state, const char* command) {
    // 1. 发送开始监听消息
    send_start_listening_message(wsi, conn_state);
    
    // 2. 读取Opus文件并分帧发送
    while (fread(&frame_length, sizeof(uint32_t), 1, file) == 1) {
        // 发送二进制音频帧
        send_ws_message(wsi, conn_state, opus_buffer, frame_length, 1);
    }
    
    // 3. 发送停止消息
    send_stop_listening_message(wsi, conn_state);
}
```

### 4.2 MP3 音频播放

通过 `ws_audio_utils.c` 实现MP3音频播放：

```c
int ws_audio_play_mp3(const void *data, size_t len);
```

**✅ 特性**: 
- 循环缓冲区解决电流音问题
- 支持实时MP3解码和播放
- 流控机制防止缓冲区溢出

## 5. 协议合规性评估

### 5.1 ✅ 完全符合的功能

| 功能 | 协议要求 | 实现状态 |
|------|----------|----------|
| Hello交换 | 必需 | ✅ 完整实现 |
| Session ID管理 | 必需 | ✅ 自动存储和使用 |
| Listen消息 | 必需 | ✅ 支持start/stop/detect |
| Abort消息 | 必需 | ✅ 支持可选reason |
| MCP协议 | 可选 | ✅ JSON-RPC 2.0兼容 |
| 二进制音频 | 必需 | ✅ Opus发送，MP3接收 |
| 状态管理 | 隐含 | ✅ 正式状态机 |
| 超时处理 | 推荐 | ✅ 10秒hello超时 |

### 5.2 ⚠️ 部分符合或存在差异

| 功能 | 协议要求 | 实现状态 | 差异说明 |
|------|----------|----------|----------|
| Listen mode字段 | 常见 | ⚠️ 不一致 | 仅chat消息包含mode |
| 动态Hello生成 | 推荐 | ⚠️ 固定字符串 | 未根据配置动态生成 |
| TTS状态处理 | 必需 | ⚠️ 仅日志 | 未实现状态转换 |
| 错误消息处理 | 推荐 | ❌ 未实现 | 无错误消息类型处理 |

### 5.3 🔧 改进建议

#### 5.3.1 统一Listen消息格式

```c
// 建议的统一接口
int send_listen_message(struct lws *wsi, connection_state_t *conn_state, 
                       const char *state, const char *mode, const char *text) {
    cJSON *root = create_base_message(conn_state, "listen");
    cJSON_AddStringToObject(root, "state", state);
    
    if (mode) {
        cJSON_AddStringToObject(root, "mode", mode);
    }
    
    if (text) {
        cJSON_AddStringToObject(root, "text", text);
    }
    
    return send_json_object(wsi, conn_state, root);
}
```

#### 5.3.2 动态Hello消息生成

```c
int send_hello_message(struct lws *wsi, connection_state_t *conn_state) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "hello");
    cJSON_AddNumberToObject(root, "version", 1);
    cJSON_AddStringToObject(root, "transport", "websocket");
    
    // 根据编译配置动态添加features
    cJSON *features = cJSON_CreateObject();
    #ifdef ENABLE_MCP
    cJSON_AddBoolToObject(features, "mcp", true);
    #endif
    // ... 其他特性
    
    cJSON_AddItemToObject(root, "features", features);
    
    // 添加音频参数
    cJSON *audio_params = cJSON_CreateObject();
    cJSON_AddStringToObject(audio_params, "format", conn_state->audio_params.format);
    // ... 其他参数
    
    return send_json_object(wsi, conn_state, root);
}
```

#### 5.3.3 增强TTS处理

```c
void handle_tts_message(struct lws *wsi, cJSON *json_response) {
    connection_state_t *conn_state = (connection_state_t *)lws_wsi_user(wsi);
    const cJSON *state_item = cJSON_GetObjectItemCaseSensitive(json_response, "state");
    
    if (strcmp(state_item->valuestring, "start") == 0) {
        change_websocket_state(conn_state, WS_STATE_SPEAKING);
        // 停止录音，准备播放
    } else if (strcmp(state_item->valuestring, "stop") == 0) {
        change_websocket_state(conn_state, WS_STATE_LISTENING);
        // 恢复监听状态
    }
}
```

## 6. 开发最佳实践

### 6.1 错误处理

- ✅ 所有函数都进行参数验证
- ✅ JSON对象创建失败时正确清理
- ✅ 网络发送失败时返回错误码
- ⚠️ 建议添加更详细的错误分类

### 6.2 内存管理

- ✅ 使用cJSON库自动管理JSON对象
- ✅ 及时释放动态分配的字符串
- ✅ 避免内存泄漏

### 6.3 线程安全

- ✅ 使用libwebsockets的回调机制
- ✅ 避免全局状态共享
- ⚠️ 音频处理线程需要额外同步

### 6.4 调试支持

- ✅ 详细的日志输出
- ✅ 消息内容预览（截断长消息）
- ✅ 状态转换日志
- ✅ 支持status命令查看连接状态

## 7. 测试和验证

### 7.1 功能测试

客户端提供完整的交互式测试界面：

```bash
# 连接和基本操作
hello               - 发送hello消息
listen              - 发送开始监听消息
detect "你好小明"   - 发送检测消息
chat "你好"         - 发送聊天消息
abort               - 发送中止消息
status              - 显示连接状态

# 音频测试
opus filename.opus  - 发送Opus音频文件

# 协议测试
mcp payload         - 发送MCP消息
```

### 7.2 协议兼容性测试

- ✅ 与JavaScript版本的消息格式兼容
- ✅ 支持服务器重复hello消息
- ✅ 正确处理MCP初始化流程
- ✅ 音频数据双向传输

## 8. 总结

WebSocket客户端实现在核心功能上与协议规范高度一致，具备完整的状态管理、消息发送/解析、音频处理等能力。主要优势包括：

**✅ 核心优势**:
- 完整的协议实现覆盖
- 健壮的状态管理机制
- 良好的错误处理和资源管理
- 丰富的调试和测试功能
- 音频处理能力完善

**⚠️ 改进空间**:
- Listen消息格式的一致性
- Hello消息的动态生成
- TTS状态处理的完整性
- 错误消息类型的支持

总体而言，当前实现为WebSocket通信提供了坚实的基础，在少量改进后可以达到完全的协议合规性。

---

*文档版本: 1.0*  
*最后更新: 2025-06-24*  
*基于代码版本: mqtt-websocket-proxy*
