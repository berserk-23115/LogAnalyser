cmake_minimum_required(VERSION 3.10)
project(LogAnalyser C)

# Set C standard to C11
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Enable color diagnostics for supported compilers
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-fdiagnostics-color=always)
elseif(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    add_compile_options(/diagnostics:color)
endif()

# Enable testing
enable_testing()

# Platform detection
if(WIN32)
    set(PLATFORM_WINDOWS 1)
    add_compile_definitions(PLATFORM_WINDOWS)
elseif(APPLE)
    set(PLATFORM_MACOS 1)
    add_compile_definitions(PLATFORM_MACOS)
elseif(UNIX)
    set(PLATFORM_LINUX 1)
    add_compile_definitions(PLATFORM_LINUX)
endif()

# Find libpcap using pkg-config first, then fallback to manual search
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PCAP libpcap)
endif()

# Manual search if pkg-config didn't find it
if(NOT PCAP_FOUND)
    find_path(PCAP_INCLUDE_DIR pcap.h PATHS /usr/include /usr/local/include)
    find_library(PCAP_LIBRARY NAMES pcap wpcap PATHS /usr/lib /usr/local/lib)
    
    if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
        set(PCAP_FOUND TRUE)
        set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
        set(PCAP_LIBRARIES ${PCAP_LIBRARY})
    endif()
endif()

if(NOT PCAP_FOUND)
    message(FATAL_ERROR "Could not find libpcap library or headers. Please install libpcap-dev (Linux), libpcap (macOS), or WinPcap/Npcap (Windows).")
endif()

message(STATUS "Found libpcap: ${PCAP_LIBRARIES}")
message(STATUS "libpcap includes: ${PCAP_INCLUDE_DIRS}")

# Optional: Find OpenSSL for encryption features
find_package(OpenSSL QUIET)
if(OPENSSL_FOUND)
    message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")
    add_compile_definitions(HAVE_OPENSSL)
else()
    message(STATUS "OpenSSL not found - encryption features will be disabled")
endif()

# Include directories
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${PCAP_INCLUDE_DIRS}
)

if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
endif()

# Create directories if they don't exist
file(MAKE_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)
file(MAKE_DIRECTORY ${PROJECT_SOURCE_DIR}/tests)

# Source files
set(SOURCES
    src/main.c
    src/help.c
    src/core/config.c
    src/collectors/file_collector.c
    src/collectors/pcap_collector.c
    src/parsers/log_parser.c
    src/analyzers/rules.c
    src/analyzers/analyzer.c
    src/reporters/reporter.c
    src/security/security.c
)

# Create core library for reuse in tests
add_library(loganalyser_core STATIC ${SOURCES})
target_include_directories(loganalyser_core PUBLIC ${PROJECT_SOURCE_DIR}/include)

# Create executable
add_executable(loganalyser src/main.c)
target_link_libraries(loganalyser PRIVATE loganalyser_core)

# Initialize link libraries
set(LINK_LIBS ${PCAP_LIBRARIES})

# Platform-specific compiler flags and libraries
if(WIN32)
    # Windows specific flags
    target_compile_definitions(loganalyser_core PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(loganalyser_core PRIVATE /W4)
    list(APPEND LINK_LIBS ws2_32 iphlpapi)
    
elseif(UNIX)
    # Linux/macOS specific flags
    target_compile_options(loganalyser_core PRIVATE -Wall -Wextra -pedantic)
    list(APPEND LINK_LIBS m)
    
    if(PLATFORM_LINUX)
        # Linux-specific: add pthread
        list(APPEND LINK_LIBS pthread)
        target_compile_options(loganalyser_core PRIVATE -D_POSIX_C_SOURCE=200809L)
    endif()
endif()

# Add OpenSSL if available
if(OPENSSL_FOUND)
    list(APPEND LINK_LIBS OpenSSL::SSL OpenSSL::Crypto)
endif()

# Link all libraries
target_link_libraries(loganalyser_core PUBLIC ${LINK_LIBS})

# Installation rules - install to bin/ directory
install(TARGETS loganalyser 
    RUNTIME DESTINATION ${PROJECT_SOURCE_DIR}/bin
    COMPONENT runtime
)

# Install configuration files
install(FILES README.md CHANGELOG.md 
    DESTINATION ${PROJECT_SOURCE_DIR}/bin
    COMPONENT documentation
    OPTIONAL
)

# Add tests subdirectory if it exists
if(EXISTS ${PROJECT_SOURCE_DIR}/tests/CMakeLists.txt)
    add_subdirectory(tests)
endif()

# Print configuration summary
message(STATUS "=== Build Configuration Summary ===")
message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "C Standard: C${CMAKE_C_STANDARD}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Install Prefix: ${PROJECT_SOURCE_DIR}/bin")
message(STATUS "OpenSSL Support: ${OPENSSL_FOUND}")
message(STATUS "====================================")
