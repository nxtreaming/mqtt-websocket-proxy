# Tests CMakeLists.txt for mqtt-websocket-proxy

# Test executables
set(TEST_EXECUTABLES
    test_basic
    test_mqtt_protocol
    test_mqtt_auth
    test_mcp_proxy
    test_js_compatibility
    test_config_hot_reload
    test_tcp_server
    test_udp_server
    test_encryption
    test_audio_packet_format
    test_websocket_reconnection
    test_complete_gateway
    integration_test
)

# Add include paths for the main project
include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CMAKE_SOURCE_DIR}/third_party)
include_directories(${CMAKE_SOURCE_DIR}/third_party/libwebsockets/include)
include_directories(${CMAKE_BINARY_DIR}/third_party/libwebsockets/include)

# Ensure core libraries can be found
link_directories(${CMAKE_BINARY_DIR}/lib)

# Common test dependencies
set(COMMON_TEST_LIBS
    xiaozhi-mqtt-core # Main dependency on core library
)

# Test 0: Basic Test
add_executable(test_basic test_basic.cpp)

target_include_directories(test_basic PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
)

target_link_libraries(test_basic PRIVATE
    ${COMMON_TEST_LIBS}
)

# Test 1: MQTT Protocol Test
add_executable(test_mqtt_protocol test_mqtt_protocol.cpp)

target_include_directories(test_mqtt_protocol PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
)

target_link_libraries(test_mqtt_protocol PRIVATE
    ${COMMON_TEST_LIBS}
)

# Test 1.5: MQTT Authentication Test
add_executable(test_mqtt_auth test_mqtt_auth.cpp)

target_include_directories(test_mqtt_auth PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
)

target_link_libraries(test_mqtt_auth PRIVATE
    ${COMMON_TEST_LIBS}
)

# Test 1.7: MCP Proxy Test
add_executable(test_mcp_proxy test_mcp_proxy.cpp)

target_include_directories(test_mcp_proxy PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
)

target_link_libraries(test_mcp_proxy PRIVATE
    ${COMMON_TEST_LIBS}
)

# Test 1.8: JavaScript Compatibility Test
add_executable(test_js_compatibility test_js_compatibility.cpp)

target_include_directories(test_js_compatibility PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
)

target_link_libraries(test_js_compatibility PRIVATE
    ${COMMON_TEST_LIBS}
)

# Test 1.9: Configuration Hot Reload Test
add_executable(test_config_hot_reload test_config_hot_reload.cpp)

target_include_directories(test_config_hot_reload PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
)

target_link_libraries(test_config_hot_reload PRIVATE
    ${COMMON_TEST_LIBS}
)

# Test 2: TCP Server Test
add_executable(test_tcp_server test_tcp_server.cpp)

target_include_directories(test_tcp_server PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
)

target_link_libraries(test_tcp_server PRIVATE
    ${COMMON_TEST_LIBS}
)

# Test 3: UDP Server Test
add_executable(test_udp_server test_udp_server.cpp)

target_include_directories(test_udp_server PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
)

target_link_libraries(test_udp_server PRIVATE
    ${COMMON_TEST_LIBS}
)

# Test 4: Encryption Test
add_executable(test_encryption test_encryption.cpp)

target_include_directories(test_encryption PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
)

target_link_libraries(test_encryption PRIVATE
    ${COMMON_TEST_LIBS}
)

# Test 4.5: Audio Packet Format Test
add_executable(test_audio_packet_format test_audio_packet_format.cpp)

target_include_directories(test_audio_packet_format PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
)

target_link_libraries(test_audio_packet_format PRIVATE
    ${COMMON_TEST_LIBS}
)

# Test 5: WebSocket Reconnection Test
add_executable(test_websocket_reconnection test_websocket_reconnection.cpp)

target_include_directories(test_websocket_reconnection PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
)

target_link_libraries(test_websocket_reconnection PRIVATE
    ${COMMON_TEST_LIBS}
)

# Test 6: Complete Gateway Test
add_executable(test_complete_gateway test_complete_gateway.cpp)

target_include_directories(test_complete_gateway PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
)

target_link_libraries(test_complete_gateway PRIVATE
    ${COMMON_TEST_LIBS}
)

# Integration Test
add_executable(integration_test integration_test.cpp)

target_include_directories(integration_test PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
)

target_link_libraries(integration_test PRIVATE
    ${COMMON_TEST_LIBS}
)

# Set C++ standard and compile definitions for all tests
foreach(test_target ${TEST_EXECUTABLES})
    set_target_properties(${test_target} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
    )

    # Add PROJECT_VERSION definition for all test targets
    target_compile_definitions(${test_target} PRIVATE
        PROJECT_VERSION="${PROJECT_VERSION}"
        $<$<CONFIG:Debug>:DEBUG_BUILD>
    )
endforeach()
