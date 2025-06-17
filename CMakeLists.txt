cmake_minimum_required(VERSION 3.16)
project(mqtt-websocket-proxy VERSION 1.0.0 LANGUAGES C CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set compile options
if(MSVC)
    add_compile_options(/W4 /utf-8)
    # Disable specific warnings
    add_compile_options(
        /wd4100 # unreferenced formal parameter
        /wd4189 # unreferenced local variable
        /wd4267 # conversion from 'size_t' to 'type', possible loss of data
        /wd4244 # conversion from 'type1' to 'type2', possible loss of data
        /wd4525 # 'class' : all user-defined conversion operators are inherited
        /wd4701 # potentially uninitialized local variable 'name' used
        /wd4334 # 'operator' : result of 32-bit shift implicitly converted to 64 bits
        /wd4152 # nonstandard extension, function/data pointer conversion in expression
        /wd4702 # unreachable code
        /wd4245 # signed/unsigned mismatch

    )
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O3 -DNDEBUG)
    endif()
endif()

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)
# Add include path for original source directory
include_directories(${CMAKE_SOURCE_DIR}/third_party/libwebsockets/include)
# Add include path for build directory
include_directories(${CMAKE_BINARY_DIR}/third_party/libwebsockets/include)
include_directories(${CMAKE_BINARY_DIR}/third_party/libwebsockets/include/libwebsockets)

# Set OpenSSL paths for Windows before finding the package
if(WIN32)
    set(OPENSSL_ROOT_DIR "D:/OpenSSL-Win64" CACHE PATH "OpenSSL root directory")
    set(OPENSSL_INCLUDE_DIR "D:/OpenSSL-Win64/include" CACHE PATH "OpenSSL include directory")
    set(OPENSSL_CRYPTO_LIBRARY "D:/OpenSSL-Win64/lib/VC/x64/MD/libcrypto.lib" CACHE FILEPATH "OpenSSL crypto library")
    set(OPENSSL_SSL_LIBRARY "D:/OpenSSL-Win64/lib/VC/x64/MD/libssl.lib" CACHE FILEPATH "OpenSSL SSL library")
endif()

# Find system dependencies
find_package(OpenSSL REQUIRED)

# Third-party library options
option(USE_SYSTEM_LIBUV "Use system libuv" OFF)
option(USE_SYSTEM_LIBWEBSOCKETS "Use system libwebsockets" OFF)
option(BUILD_TESTS "Build tests" ON)

# Crypto implementation option
option(USE_OPENSSL_CRYPTO "Use OpenSSL for AES-128-CTR implementation (more secure)" ON)
if(NOT USE_OPENSSL_CRYPTO)
    message(STATUS "Using simple XOR cipher implementation (less secure)")
else()
    message(STATUS "Using OpenSSL AES-128-CTR implementation (more secure)")
endif()

# libuv dependency
if(USE_SYSTEM_LIBUV)
    find_package(LibUV REQUIRED)
    # LibUV_FOUND, LibUV_INCLUDE_DIRS, LibUV_LIBRARIES should be set by FindLibUV.cmake
    # Modern CMake might provide an imported target like LibUV::LibUV
    if(TARGET LibUV::LibUV)
        set(LIBUV_LIBRARIES LibUV::LibUV)
        # Include dirs are often handled by the target itself, but can be explicit if needed
        set(LIBUV_INCLUDE_DIRS ${LibUV_INCLUDE_DIRS}) 
    else()
        # Fallback to traditional variables if imported target not available
        # Ensure LIBUV_LIBRARIES and LIBUV_INCLUDE_DIRS are correctly populated by FindLibUV
    endif()
    message(STATUS "Using system libuv: ${LIBUV_LIBRARIES} include: ${LIBUV_INCLUDE_DIRS}")
else()
    # Use built-in libuv
    set(LIBUV_BUILD_TESTS OFF CACHE BOOL "Build libuv tests")
    add_subdirectory(third_party/libuv)
    set(LIBUV_LIBRARIES uv_a)
    set(LIBUV_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/third_party/libuv/include)
endif()

# libwebsockets dependency
if(USE_SYSTEM_LIBWEBSOCKETS)
    find_package(Libwebsockets REQUIRED)
    # Check for common imported target names (actual name might vary based on FindLibwebsockets.cmake)
    if(TARGET Libwebsockets::libwebsockets)
        set(LIBWEBSOCKETS_LIBRARIES Libwebsockets::libwebsockets)
        set(LIBWEBSOCKETS_INCLUDE_DIRS "") # Assume target handles includes
    elseif(TARGET Libwebsockets::websockets)
        set(LIBWEBSOCKETS_LIBRARIES Libwebsockets::websockets)
        set(LIBWEBSOCKETS_INCLUDE_DIRS "") # Assume target handles includes
    else()
        # Fallback to traditional variables if no common imported target found
        # Ensure Libwebsockets_LIBRARIES and Libwebsockets_INCLUDE_DIRS are correctly populated by FindLibwebsockets.cmake
        set(LIBWEBSOCKETS_LIBRARIES ${Libwebsockets_LIBRARIES})
        set(LIBWEBSOCKETS_INCLUDE_DIRS ${Libwebsockets_INCLUDE_DIRS})
    endif()
    message(STATUS "Using system libwebsockets: ${LIBWEBSOCKETS_LIBRARIES} include: ${LIBWEBSOCKETS_INCLUDE_DIRS}")
else()
    # Use built-in libwebsockets
    set(LWS_WITH_SSL ON CACHE BOOL "Enable SSL support")
    set(LWS_WITH_STATIC ON CACHE BOOL "Build static library")
    set(LWS_WITH_SHARED OFF CACHE BOOL "Build shared library")
    set(LWS_WITHOUT_TESTAPPS ON CACHE BOOL "Don't build test apps")
    set(LWS_WITHOUT_TEST_SERVER ON CACHE BOOL "Don't build test server")
    set(LWS_WITHOUT_TEST_PING ON CACHE BOOL "Don't build test ping")
    set(LWS_WITHOUT_TEST_CLIENT ON CACHE BOOL "Don't build test client")

    # Disable warnings as errors for libwebsockets (this is the key setting)
    set(DISABLE_WERROR ON CACHE BOOL "Avoid treating compiler warnings as fatal errors")

    # Additional libwebsockets options to reduce build issues
    set(LWS_WITH_MINIMAL_EXAMPLES OFF CACHE BOOL "Don't build minimal examples")
    set(LWS_WITH_LWSWS OFF CACHE BOOL "Don't build lwsws")
    set(LWS_WITH_PLUGINS OFF CACHE BOOL "Don't build plugins")
    set(LWS_SUPPRESS_DEPRECATED_API_WARNINGS ON CACHE BOOL "Turn off deprecated API warnings")

    # Pass OpenSSL configuration to libwebsockets if OpenSSL was found
    if(OpenSSL_FOUND)
        set(LWS_OPENSSL_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR} CACHE STRING "OpenSSL include directory")
        set(LWS_OPENSSL_LIBRARIES ${OPENSSL_LIBRARIES} CACHE STRING "OpenSSL libraries")
        set(OPENSSL_ROOT_DIR ${OPENSSL_ROOT_DIR} CACHE PATH "OpenSSL root directory")
    endif()

    # Save current compiler flags
    set(SAVED_CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
    set(SAVED_CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})

    # Temporarily disable warnings as errors for libwebsockets
    if(MSVC)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W1")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W1")
    else()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -w")
    endif()

    add_subdirectory(third_party/libwebsockets)

    # Ensure libwebsockets include directory exists
    if(NOT EXISTS ${CMAKE_BINARY_DIR}/third_party/libwebsockets/include/libwebsockets)
        file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/third_party/libwebsockets/include/libwebsockets)
    endif()

    # Restore compiler flags
    set(CMAKE_C_FLAGS ${SAVED_CMAKE_C_FLAGS})
    set(CMAKE_CXX_FLAGS ${SAVED_CMAKE_CXX_FLAGS})

    set(LIBWEBSOCKETS_LIBRARIES websockets) # Use the CMake target name
    set(LIBWEBSOCKETS_INCLUDE_DIRS
        ${CMAKE_SOURCE_DIR}/third_party/libwebsockets/include
        ${CMAKE_BINARY_DIR}/third_party/libwebsockets)

    # libwebsockets link directory will be set in the xiaozhi-mqtt-core target
endif()

# nlohmann/json (header-only)
set(JSON_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/third_party/nlohmann)

# Source files
set(GATEWAY_SOURCES
    src/server/gateway_server.cpp
    src/server/mqtt_server.cpp
    src/server/udp_server.cpp
    src/connection/mqtt_connection.cpp
    src/connection/websocket_bridge.cpp
    src/utils/config_manager.cpp
    src/utils/logger.cpp
    src/utils/mqtt_auth.cpp
    src/utils/mcp_proxy.cpp
    src/protocol/mqtt_protocol.cpp
    src/protocol/mqtt_packet.cpp
)

# Choose crypto implementation based on option
if(USE_OPENSSL_CRYPTO)
    list(APPEND GATEWAY_SOURCES src/utils/crypto_utils_openssl.cpp)
    add_compile_definitions(USE_OPENSSL_CRYPTO)
else()
    list(APPEND GATEWAY_SOURCES src/utils/crypto_utils.cpp)
endif()

# Header files
set(GATEWAY_HEADERS
    src/server/gateway_server.h
    src/server/mqtt_server.h
    src/server/udp_server.h
    src/protocol/mqtt_protocol.h
    src/protocol/mqtt_packet.h
    src/connection/mqtt_connection.h
    src/connection/websocket_bridge.h
    src/utils/config_manager.h
    src/utils/crypto_utils.h
    src/utils/mqtt_auth.h
    src/utils/mcp_proxy.h
    src/utils/logger.h
    src/common/types.h
    src/common/constants.h
    src/common/error_codes.h
)

# Create a static library with all the core functionality
add_library(xiaozhi-mqtt-core STATIC ${GATEWAY_SOURCES} ${GATEWAY_HEADERS})

# Set include directories for the library
# Consolidate include directories. 
# For system libraries found via find_package, if they provide imported targets,
# their include directories are often handled automatically when linking against the target.
# For bundled libraries, we specify them directly.

target_include_directories(xiaozhi-mqtt-core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party # General third_party includes if any
    ${JSON_INCLUDE_DIRS} # nlohmann_json
)

# Add include directories based on how dependencies are resolved
if(USE_SYSTEM_LIBUV AND LibUV_FOUND)
    if(NOT TARGET LibUV::LibUV) # If not using imported target, add include dirs manually
        target_include_directories(xiaozhi-mqtt-core PUBLIC ${LIBUV_INCLUDE_DIRS})
    endif()
else()
    target_include_directories(xiaozhi-mqtt-core PUBLIC ${CMAKE_SOURCE_DIR}/third_party/libuv/include) # Bundled libuv
endif()

if(USE_SYSTEM_LIBWEBSOCKETS AND LIBWEBSOCKETS_FOUND)
    if(NOT TARGET Libwebsockets::libwebsockets) # Example imported target name
         target_include_directories(xiaozhi-mqtt-core PUBLIC ${LIBWEBSOCKETS_INCLUDE_DIRS})
    endif()
else()
    target_include_directories(xiaozhi-mqtt-core PUBLIC 
        ${CMAKE_SOURCE_DIR}/third_party/libwebsockets/include 
        ${CMAKE_BINARY_DIR}/third_party/libwebsockets/include # For generated lws_config.h
    )
endif()

# OpenSSL include directories (FindOpenSSL.cmake sets OpenSSL_INCLUDE_DIR)
target_include_directories(xiaozhi-mqtt-core PUBLIC ${OpenSSL_INCLUDE_DIR})

# Add specific link directories for xiaozhi-mqtt-core
target_link_directories(xiaozhi-mqtt-core PRIVATE
    ${CMAKE_BINARY_DIR}/third_party/libwebsockets/lib/$<CONFIG>
)

# Link dependencies to the core library
# Link libraries
# Prefer modern CMake imported targets where available
if(TARGET OpenSSL::SSL AND TARGET OpenSSL::Crypto)
    target_link_libraries(xiaozhi-mqtt-core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
else()
    target_link_libraries(xiaozhi-mqtt-core PUBLIC ${OpenSSL_LIBRARIES}) # Fallback to older variable
endif()

if(USE_SYSTEM_LIBUV AND LibUV_FOUND)
    if(TARGET LibUV::LibUV)
        target_link_libraries(xiaozhi-mqtt-core PUBLIC LibUV::LibUV)
    else()
        target_link_libraries(xiaozhi-mqtt-core PUBLIC ${LIBUV_LIBRARIES})
    endif()
else()
    target_link_libraries(xiaozhi-mqtt-core PUBLIC uv_a) # Bundled libuv target name
endif()

if(USE_SYSTEM_LIBWEBSOCKETS AND LIBWEBSOCKETS_FOUND)
    # Assuming LIBWEBSOCKETS_LIBRARIES is set to the target name or library path by find_package/pkg_check_modules
    target_link_libraries(xiaozhi-mqtt-core PUBLIC ${LIBWEBSOCKETS_LIBRARIES})
else() # USE_SYSTEM_LIBWEBSOCKETS is OFF
    target_link_libraries(xiaozhi-mqtt-core PUBLIC websockets) # Link against the CMake target 'websockets'
endif()

# Add Windows-specific system libraries
if(WIN32)
    target_link_libraries(xiaozhi-mqtt-core PUBLIC
        ws2_32      # Winsock
        iphlpapi    # IP Helper API (for network adapter info, etc.)
        crypt32     # Cryptographic API (often needed by OpenSSL or for system certs)
        userenv     # User Profile (sometimes needed for path lookups)
    )
endif()

# Set properties for the library
set_target_properties(xiaozhi-mqtt-core PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
    OUTPUT_NAME "xiaozhi-mqtt-core"
)

# Add explicit dependency on websockets (static library)
add_dependencies(xiaozhi-mqtt-core websockets)

# Add compile definitions for the library
target_compile_definitions(xiaozhi-mqtt-core PUBLIC
    XIAOZHI_MQTT_CORE_EXPORTS
    XIAOZHI_CRYPTO_STATIC
    PROJECT_VERSION="${PROJECT_VERSION}"
    $<$<PLATFORM_ID:Windows>:_WIN32_WINNT=0x0601>
    $<$<PLATFORM_ID:Windows>:WIN32_LEAN_AND_MEAN>
)

# Create main executable (just needs a main entry point)
add_executable(mqtt-websocket-proxy src/main.cpp)

# Link the core library to the executable
target_link_libraries(mqtt-websocket-proxy PRIVATE xiaozhi-mqtt-core)

# Add compile definitions for Windows
if(WIN32)
    target_compile_definitions(mqtt-websocket-proxy PRIVATE
        _WIN32_WINNT=0x0601
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        HAVE_OPENSSL
    )
    
    # Only define XIAOZHI_CRYPTO_EXPORTS when building the crypto utils
    # This ensures proper symbol export/import
    target_compile_definitions(mqtt-websocket-proxy PRIVATE $<$<CONFIG:Debug>:XIAOZHI_CRYPTO_EXPORTS>)
    target_compile_definitions(mqtt-websocket-proxy PRIVATE $<$<CONFIG:Release>:XIAOZHI_CRYPTO_EXPORTS>)
    
    # Add Windows SDK library paths
    target_link_directories(mqtt-websocket-proxy PRIVATE
        ${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/um/x64
        ${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/ucrt/x64
    )
endif()

# Add include directories for crypto_utils
target_include_directories(mqtt-websocket-proxy PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Add library search paths
target_link_directories(mqtt-websocket-proxy PRIVATE
    ${CMAKE_BINARY_DIR}/third_party/libwebsockets/lib/$<CONFIG>
)

# Add compile definitions for Windows
if(WIN32)
    target_compile_definitions(mqtt-websocket-proxy PRIVATE
        _WIN32_WINNT=0x0601
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()

# Define Windows system libraries
if(WIN32)
    set(WINDOWS_LIBS 
        ws2_32
        userenv
        psapi
        iphlpapi
        crypt32
    )
else()
    set(WINDOWS_LIBS)
endif()

# Link Windows system libraries to all test targets
function(link_windows_libs target_name)
    if(WIN32 AND TARGET ${target_name})
        target_link_libraries(${target_name} ${WINDOWS_LIBS})
    endif()
endfunction()

# Link Windows libraries to test targets
link_windows_libs(test_encryption)
link_windows_libs(test_tcp_server)
link_windows_libs(test_udp_server)
link_windows_libs(test_websocket_reconnection)

# OpenSSL linking is now handled in the main target_link_libraries call

# Include directories
target_include_directories(mqtt-websocket-proxy PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/third_party
    ${LIBUV_INCLUDE_DIRS}
    ${LIBWEBSOCKETS_INCLUDE_DIRS}
    ${JSON_INCLUDE_DIRS}
)

# Platform-specific link libraries (non-Windows)
if(UNIX AND NOT APPLE)
    target_link_libraries(mqtt-websocket-proxy PRIVATE pthread dl)
endif()

# Add the wsmate client subdirectory
add_subdirectory(client)

if(APPLE)
    target_link_libraries(mqtt-websocket-proxy PRIVATE pthread)
endif()

# Compile definitions
target_compile_definitions(mqtt-websocket-proxy PRIVATE
    PROJECT_VERSION="${PROJECT_VERSION}"
    $<$<CONFIG:Debug>:DEBUG_BUILD>
    XIAOZHI_CRYPTO_EXPORTS
)

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Install rules
install(TARGETS mqtt-websocket-proxy
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES config/gateway.json.example
    DESTINATION etc/mqtt-websocket-proxy
    RENAME gateway.json
)

# Package configuration
set(CPACK_PACKAGE_NAME "mqtt-websocket-proxy")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "MQTT+UDP to WebSocket Proxy")
set(CPACK_PACKAGE_VENDOR "Xiaozhi")

if(WIN32)
    set(CPACK_GENERATOR "ZIP;NSIS")
else()
    set(CPACK_GENERATOR "TGZ;DEB;RPM")
endif()

include(CPack)

# Display configuration information
message(STATUS "")
message(STATUS "Configuration Summary:")
message(STATUS "  Project: ${PROJECT_NAME} ${PROJECT_VERSION}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Use System libuv: ${USE_SYSTEM_LIBUV}")
message(STATUS "  Use System libwebsockets: ${USE_SYSTEM_LIBWEBSOCKETS}")
message(STATUS "  Build Tests: ${BUILD_TESTS}")
message(STATUS "  Install Prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
