cmake_minimum_required(VERSION 3.10)
project(LogAnalyser C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Include directories
include_directories(${PROJECT_SOURCE_DIR}/include)

# Source files
set(SOURCES
    src/main.c
    src/help.c
    src/core/config.c
    src/collectors/file_collector.c
    src/parsers/log_parser.c
    src/analyzers/analyzer.c
)

# Create executable
add_executable(loganalyser ${SOURCES})

# Platform-specific settings
if(WIN32)
    # Windows specific flags
    target_compile_definitions(loganalyser PRIVATE _CRT_SECURE_NO_WARNINGS)
elseif(UNIX AND NOT APPLE)
    # Linux specific flags
    target_link_libraries(loganalyser m)
elseif(APPLE)
    # macOS specific flags
    target_link_libraries(loganalyser m)
endif()

# Installation
install(TARGETS loganalyser DESTINATION bin)
