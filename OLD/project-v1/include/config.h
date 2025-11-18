#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>

// Platform detection
#ifdef _WIN32
    #define PLATFORM_WINDOWS
    #include <windows.h>
#elif defined(__APPLE__) && defined(__MACH__)
    #define PLATFORM_MACOS
    #include <unistd.h>
#elif defined(__linux__)
    #define PLATFORM_LINUX
    #include <unistd.h>
#endif

// ANSI Color codes for cross-platform terminal output
#ifdef PLATFORM_WINDOWS
    // Windows console color attributes
    #define COLOR_RESET     SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7)
    #define COLOR_RED       SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY)
    #define COLOR_GREEN     SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY)
    #define COLOR_YELLOW    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
    #define COLOR_BLUE      SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_INTENSITY)
    #define COLOR_MAGENTA   SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
    #define COLOR_CYAN      SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
    
    // Use these as string macros (empty for Windows before printf)
    #define ANSI_RESET      ""
    #define ANSI_RED        ""
    #define ANSI_GREEN      ""
    #define ANSI_YELLOW     ""
    #define ANSI_BLUE       ""
    #define ANSI_MAGENTA    ""
    #define ANSI_CYAN       ""
    #define ANSI_BOLD       ""
#else
    // ANSI escape codes for Unix-like systems
    #define COLOR_RESET     
    #define COLOR_RED       
    #define COLOR_GREEN     
    #define COLOR_YELLOW    
    #define COLOR_BLUE      
    #define COLOR_MAGENTA   
    #define COLOR_CYAN      
    
    #define ANSI_RESET      "\033[0m"
    #define ANSI_RED        "\033[1;31m"
    #define ANSI_GREEN      "\033[1;32m"
    #define ANSI_YELLOW     "\033[1;33m"
    #define ANSI_BLUE       "\033[1;34m"
    #define ANSI_MAGENTA    "\033[1;35m"
    #define ANSI_CYAN       "\033[1;36m"
    #define ANSI_BOLD       "\033[1m"
#endif

// Cross-platform utility functions
void init_console_colors(void);
void print_colored(const char *color, const char *message);
void print_threat(const char *message);    // Red
void print_warning(const char *message);   // Yellow
void print_success(const char *message);   // Green
void print_info(const char *message);      // Cyan

// Configuration file paths
#define CONFIG_FILE "loganalyser.conf"
#define RULES_DIR "rules/"
#define SIGNATURES_DIR "signatures/"
#define UPDATES_DIR "updates/"
#define MAX_PATH_LENGTH 512
#define MAX_BUFFER_SIZE 8192

// Configuration structure
typedef struct {
    char rules_path[MAX_PATH_LENGTH];
    char signatures_path[MAX_PATH_LENGTH];
    char output_dir[MAX_PATH_LENGTH];
    int max_log_size_mb;
    int retention_days;
    int enable_encryption;
    int packet_buffer_size;
    int analysis_threshold;
} Config;

// Configuration management functions
int init_config(void);
int load_config(Config *config);
int save_config(const Config *config);
void set_default_config(Config *config);

// Global configuration instance
extern Config g_config;

#endif
