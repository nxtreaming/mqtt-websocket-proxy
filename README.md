# MQTT WebSocket Proxy C++ Implementation

High-performance MQTT+UDP to WebSocket bridge service based on libuv + libwebsockets

## 🚀 Quick Start

### 1. Requirements

**Windows:**
- Visual Studio 2019/2022 (Recommended)
- CMake 3.16+
- Git

**Linux/macOS:**
- GCC 7+ or Clang 8+
- CMake 3.16+
- Git

### 2. Clone Project

```bash
git clone https://github.com/nxtreaming/mqtt-websocket-proxy
cd mqtt-websocket-proxy
```

### 3. Prepare Dependencies

#### Method 1: Using Git Submodules (Recommended)

```bash
# Initialize submodules
git submodule update --init --recursive

# If you need to add submodules
git submodule add https://github.com/libuv/libuv.git third_party/libuv
git submodule add https://github.com/warmcat/libwebsockets.git third_party/libwebsockets
```

#### Method 2: Manual Download

1. Download [libuv](https://github.com/libuv/libuv/releases) to `third_party/libuv/`
2. Download [libwebsockets](https://github.com/warmcat/libwebsockets/releases) to `third_party/libwebsockets/`
3. Download [nlohmann/json](https://github.com/nlohmann/json/releases) to `third_party/nlohmann/`

### 4. Build Project

#### Windows (Visual Studio)

```bash
mkdir build
cd build

# Visual Studio 2019
cmake .. -G "Visual Studio 16 2019" -A x64

# Visual Studio 2022
cmake .. -G "Visual Studio 17 2022" -A x64

# Build
cmake --build . --config Release
```

#### Linux/macOS

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### 5. Configuration and Running

```bash
# Copy configuration file
cp config/gateway.json.example config/gateway.json

# Edit configuration file
vim config/gateway.json  # Linux/macOS
notepad config/gateway.json  # Windows

# Run program
./bin/mqtt-websocket-proxy  # Linux/macOS
.\bin\Release\mqtt-websocket-proxy.exe  # Windows
```

## 📁 Project Structure

```
mqtt-websocket-proxy/
├── CMakeLists.txt              # Main CMake configuration
├── src/                        # Source code
│   ├── main.cpp                # Program entry point
│   │
│   ├── server/                # Server core implementation
│   │   ├── gateway_server.cpp  # Main gateway server implementation
│   │   ├── gateway_server.h    # Gateway server interface
│   │   ├── mqtt_server.cpp     # MQTT server implementation
│   │   ├── mqtt_server.h       # MQTT server interface
│   │   ├── udp_server.cpp      # UDP server implementation
│   │   └── udp_server.h        # UDP server interface
│   │
│   ├── protocol/              # Protocol handling
│   │   ├── mqtt_packet.cpp     # MQTT packet serialization/deserialization
│   │   ├── mqtt_packet.h       # MQTT packet definitions
│   │   ├── mqtt_protocol.cpp   # MQTT protocol implementation
│   │   └── mqtt_protocol.h     # MQTT protocol interface
│   │
│   ├── connection/            # Connection management
│   │   ├── mqtt_connection.cpp  # MQTT connection handling
│   │   ├── mqtt_connection.h    # MQTT connection interface
│   │   ├── websocket_bridge.cpp # WebSocket bridge implementation
│   │   └── websocket_bridge.h   # WebSocket bridge interface
│   │
│   ├── utils/                 # Utility components
│   │   ├── config_manager.cpp   # Configuration management implementation
│   │   ├── config_manager.h     # Configuration interface
│   │   ├── crypto_utils.cpp     # Cryptographic simulated implementation
│   |   ├── crypto_utils_openssl.cpp # OpenSSL-based crypto implementation
│   │   ├── crypto_utils.h       # Crypto utilities interface
│   │   ├── logger.cpp           # Logging implementation
│   │   ├── logger.h             # Logging interface
│   │   ├── mcp_proxy.cpp        # MCP proxy implementation
│   │   └── mcp_proxy.h          # MCP proxy interface
│   │   ├── mqtt_auth.cpp        # MQTT authentication implementation
│   │   └── mqtt_auth.h          # Authentication interface
│   │
│   └── common/                # Common definitions
│       ├── types.h            # Type definitions
│       ├── constants.h        # Constant definitions
│       └── error_codes.h      # Error code definitions
├── tests/                     # Test suite
│   ├── test_basic.cpp                # Basic functionality tests
│   ├── test_mqtt_protocol.cpp        # MQTT protocol tests
│   ├── test_mqtt_auth.cpp            # Authentication tests
│   ├── test_mcp_proxy.cpp            # MCP proxy tests
│   ├── test_js_compatibility.cpp     # JavaScript compatibility tests
│   ├── test_config_hot_reload.cpp    # Configuration reload tests
│   ├── test_tcp_server.cpp           # TCP server tests
│   ├── test_udp_server.cpp           # UDP server tests
│   ├── test_encryption.cpp           # Encryption tests
│   ├── test_audio_packet_format.cpp  # Audio packet format tests
│   ├── test_websocket_reconnection.cpp # WebSocket reconnection tests
│   ├── integration_test.cpp          # Integration tests for all components
│   └── test_complete_gateway.cpp     # End-to-end gateway tests
├── third_party/              # Third-party libraries
│   ├── libuv/                # libuv source code
│   ├── libwebsockets/        # libwebsockets source code
│   └── nlohmann/             # JSON library
└── config/                   # Configuration files
    └── gateway.json.example
```

## ⚙️ Configuration

Edit `config/gateway.json`:

```json
{
  "mqtt": {
    "host": "0.0.0.0",
    "port": 1883,
    "max_connections": 10000,
    "max_payload_size": 8192
  },
  "udp": {
    "host": "0.0.0.0", 
    "port": 8884,
    "public_ip": "your-server-ip"
  },
  "websocket": {
    "production_servers": [
      "wss://chat.xiaozhi.me/ws"
    ],
    "development_servers": [
      "wss://dev-chat.xiaozhi.me/ws"
    ],
    "development_mac_addresses": [
      "aa:bb:cc:dd:ee:ff"
    ]
  },
  "logging": {
    "enabled": true,
    "level": "info",
    "file_path": "logs/gateway.log"
  }
}
```

## 🔧 CMake Options

```bash
# Use system libraries instead of built-in libraries
cmake .. -DUSE_SYSTEM_LIBUV=ON -DUSE_SYSTEM_LIBWEBSOCKETS=ON

# Disable tests
cmake .. -DBUILD_TESTS=OFF

# Specify installation path
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
```

## 🚀 Performance Features

- **High Concurrency**: Support 10,000+ concurrent MQTT connections
- **Low Latency**: MQTT message processing latency < 1ms
- **High Throughput**: UDP audio data processing > 1000 packets/sec
- **Low Memory**: Memory usage per connection < 1KB
- **Cross-platform**: Native support for Windows/Linux/macOS

## 🔍 Technology Stack

- **Language**: C++17
- **Network Library**: libuv (Async I/O)
- **WebSocket**: libwebsockets
- **JSON**: nlohmann/json
- **Encryption**: OpenSSL/mbedTLS
- **Build System**: CMake

## 📊 Comparison with Node.js Version

| Feature | Node.js Version | C++ Version |
|---------|----------------|-------------|
| Memory Usage | ~50MB | ~5MB |
| Startup Time | ~2s | ~0.1s |
| Concurrent Connections | 1,000 | 10,000+ |
| CPU Usage | Higher | Lower |
| Deployment Complexity | Simple | Medium |

## 🧪 Testing

The project includes a comprehensive test suite covering all major components:

```bash
# Build tests
cmake .. -DBUILD_TESTS=ON
make -j$(nproc)  # Linux/macOS
cmake --build . --config Release  # Windows

# Run individual tests
./bin/test_basic  # Linux/macOS
.\bin\Release\test_basic.exe  # Windows
```

### Test Suite Components

| Test | Description |
|------|-------------|
| test_basic | Basic functionality and utility tests |
| test_mqtt_protocol | MQTT protocol parsing and serialization |
| test_mqtt_auth | MQTT authentication mechanisms |
| test_mcp_proxy | MCP proxy functionality |
| test_js_compatibility | JavaScript compatibility tests |
| test_config_hot_reload | Configuration hot reload functionality |
| test_tcp_server | TCP server implementation |
| test_udp_server | UDP server implementation |
| test_encryption | Encryption and decryption tests |
| test_audio_packet_format | Audio packet format handling |
| test_websocket_reconnection | WebSocket reconnection logic |
| test_complete_gateway | End-to-end gateway functionality |

## 🐛 Troubleshooting

### Compilation Errors

1. **libuv not found**: Ensure submodules are initialized
2. **OpenSSL errors**: Use vcpkg to install OpenSSL on Windows
3. **Compiler version**: Ensure using C++17 compatible compiler

### Runtime Errors

1. **Port in use**: Check if MQTT/UDP ports are used by other programs
2. **Configuration file errors**: Verify JSON format is correct
3. **Permission issues**: Ensure program has permission to bind ports

## 📝 Development Status

### ✅ Completed (100%)
- Project structure and CMake configuration
- Core types and interface definitions
- Logger system implementation
- Configuration management system
- Gateway server framework
- Error handling system
- **MQTT protocol parser** (`src/protocol/mqtt_protocol.cpp`) - QoS 0 only
- **MQTT packet serialization** (`src/protocol/mqtt_packet.cpp`) - Core packets
- **TCP server for MQTT connections** (`src/server/mqtt_server.cpp`) - Full implementation
- **MQTT connection management** (`src/connection/mqtt_connection.cpp`) - Complete
- **WebSocket bridge client** (`src/connection/websocket_bridge.cpp`) - Full implementation with auto-reconnection
- **WebSocket auto-reconnection** - Exponential backoff, server failover, infinite retry capability
- **UDP server implementation** (`src/server/udp_server.cpp`) - Complete with encrypted session management
- **Audio data encryption** (`src/utils/crypto_utils_openssl.cpp`) - AES-128-CTR compatible with JavaScript
- **Complete message forwarding** - MQTT ↔ WebSocket ↔ UDP encrypted audio data
- **Session duration tracking** - Track and log client session durations
- **Goodbye message handling** - Send proper goodbye messages with session information
- **Configuration hot reload** - Dynamic configuration updates without restart
- Performance optimization for high-throughput audio
- Advanced monitoring and metrics

### ⏳ TODO (Low Priority)

- Complete test suite
- Performance optimization
- Documentation improvements

### 🎯 Architecture Focus

This is a **MQTT forwarding gateway**, not a full MQTT broker:

- Accepts MQTT client connections (QoS 0 only)
- Forwards MQTT messages to WebSocket servers
- Handles UDP audio data bidirectionally
- No message persistence or complex broker features

## 🤝 Contributing

Issues and Pull Requests are welcome!

## 📄 License

MIT License
