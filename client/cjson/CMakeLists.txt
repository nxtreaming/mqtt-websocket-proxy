cmake_minimum_required(VERSION 3.10)
project(cjson C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(cjson_static STATIC 
    cJSON.c
)

# Public include directory for cJSON.h
target_include_directories(cjson_static PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Set output name for the static library
set_target_properties(cjson_static PROPERTIES OUTPUT_NAME "cjson")
