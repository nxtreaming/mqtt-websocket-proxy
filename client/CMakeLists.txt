cmake_minimum_required(VERSION 3.10)
project(wsmate C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Add the cJSON subdirectory (builds cjson_static library)
add_subdirectory(cjson)

# Add include directory for libwebsockets if it's not globally available
# Assuming libwebsockets headers are accessible via the main project's include paths
# or that the 'websockets' target handles its own include directories.

add_executable(wsmate wsmate.c)

# Include directory for cJSON.h (from the cjson subdirectory)
target_include_directories(wsmate PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/cjson)

# Link against the libwebsockets library target from the main project
# This assumes 'websockets' is a target defined in the parent CMake project
# that provides the libwebsockets library.
if(TARGET websockets)
    target_link_libraries(wsmate PRIVATE websockets cjson_static)
else()
    message(WARNING "libwebsockets target 'websockets' not found. You may need to link manually or adjust the main CMakeLists.txt.")
    # As a fallback, try finding the package if it's installed system-wide
    # find_package(Libwebsockets REQUIRED)
    # if(Libwebsockets_FOUND)
    #     target_link_libraries(wsmate PRIVATE Libwebsockets::Libwebsockets)
    # endif()
endif()

# On Windows, libwebsockets might require ws2_32 and other libraries
if(WIN32)
    target_link_libraries(wsmate PRIVATE ws2_32 secur32 bcrypt cjson_static)
endif()
