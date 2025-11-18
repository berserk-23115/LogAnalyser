#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Global configuration instance
Config g_config = {0};

/**
 * Initialize console for color output
 */
void init_console_colors(void) {
#ifdef PLATFORM_WINDOWS
    // Enable ANSI escape sequences on Windows 10+
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
#endif
}

/**
 * Print colored message (Unix-like systems)
 */
void print_colored(const char *color, const char *message) {
#ifdef PLATFORM_WINDOWS
    // For Windows, we'll use ANSI codes if VT processing is enabled
    printf("%s%s%s", color, message, ANSI_RESET);
#else
    printf("%s%s%s", color, message, ANSI_RESET);
#endif
}

/**
 * Print threat message in red
 */
void print_threat(const char *message) {
#ifdef PLATFORM_WINDOWS
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
    printf("%s", message);
    SetConsoleTextAttribute(hConsole, 7); // Reset to default
#else
    printf("%s%s%s", ANSI_RED, message, ANSI_RESET);
#endif
}

/**
 * Print warning message in yellow
 */
void print_warning(const char *message) {
#ifdef PLATFORM_WINDOWS
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("%s", message);
    SetConsoleTextAttribute(hConsole, 7);
#else
    printf("%s%s%s", ANSI_YELLOW, message, ANSI_RESET);
#endif
}

/**
 * Print success message in green
 */
void print_success(const char *message) {
#ifdef PLATFORM_WINDOWS
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("%s", message);
    SetConsoleTextAttribute(hConsole, 7);
#else
    printf("%s%s%s", ANSI_GREEN, message, ANSI_RESET);
#endif
}

/**
 * Print info message in cyan
 */
void print_info(const char *message) {
#ifdef PLATFORM_WINDOWS
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("%s", message);
    SetConsoleTextAttribute(hConsole, 7);
#else
    printf("%s%s%s", ANSI_CYAN, message, ANSI_RESET);
#endif
}

/**
 * Set default configuration values
 */
void set_default_config(Config *config) {
    if (!config) return;
    
    strncpy(config->rules_path, RULES_DIR, MAX_PATH_LENGTH - 1);
    strncpy(config->signatures_path, SIGNATURES_DIR, MAX_PATH_LENGTH - 1);
    strncpy(config->output_dir, "output/", MAX_PATH_LENGTH - 1);
    
    config->max_log_size_mb = 100;
    config->retention_days = 30;
    config->enable_encryption = 0;
    config->packet_buffer_size = 10000;
    config->analysis_threshold = 5;
}

/**
 * Initialize configuration file with defaults
 */
int init_config(void) {
    Config config = {0};
    set_default_config(&config);
    
    FILE *fp = fopen(CONFIG_FILE, "w");
    if (!fp) {
        print_warning("Warning: Could not create config file. Using defaults.\n");
        g_config = config;
        return 1;
    }
    
    fprintf(fp, "# Log Analyser Configuration File\n");
    fprintf(fp, "# Generated automatically - Edit as needed\n\n");
    fprintf(fp, "rules_path=%s\n", config.rules_path);
    fprintf(fp, "signatures_path=%s\n", config.signatures_path);
    fprintf(fp, "output_dir=%s\n", config.output_dir);
    fprintf(fp, "max_log_size_mb=%d\n", config.max_log_size_mb);
    fprintf(fp, "retention_days=%d\n", config.retention_days);
    fprintf(fp, "enable_encryption=%d\n", config.enable_encryption);
    fprintf(fp, "packet_buffer_size=%d\n", config.packet_buffer_size);
    fprintf(fp, "analysis_threshold=%d\n", config.analysis_threshold);
    
    fclose(fp);
    
    g_config = config;
    print_success("Configuration file created successfully!\n");
    return 0;
}

/**
 * Load configuration from file
 */
int load_config(Config *config) {
    if (!config) return -1;
    
    set_default_config(config);
    
    FILE *fp = fopen(CONFIG_FILE, "r");
    if (!fp) {
        print_warning("Warning: Config file not found. Using defaults.\n");
        g_config = *config;
        return 1;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') continue;
        
        char key[128], value[384];
        if (sscanf(line, "%127[^=]=%383[^\n]", key, value) == 2) {
            if (strcmp(key, "rules_path") == 0)
                strncpy(config->rules_path, value, MAX_PATH_LENGTH - 1);
            else if (strcmp(key, "signatures_path") == 0)
                strncpy(config->signatures_path, value, MAX_PATH_LENGTH - 1);
            else if (strcmp(key, "output_dir") == 0)
                strncpy(config->output_dir, value, MAX_PATH_LENGTH - 1);
            else if (strcmp(key, "max_log_size_mb") == 0)
                config->max_log_size_mb = atoi(value);
            else if (strcmp(key, "retention_days") == 0)
                config->retention_days = atoi(value);
            else if (strcmp(key, "enable_encryption") == 0)
                config->enable_encryption = atoi(value);
            else if (strcmp(key, "packet_buffer_size") == 0)
                config->packet_buffer_size = atoi(value);
            else if (strcmp(key, "analysis_threshold") == 0)
                config->analysis_threshold = atoi(value);
        }
    }
    
    fclose(fp);
    g_config = *config;
    return 0;
}

/**
 * Save configuration to file
 */
int save_config(const Config *config) {
    if (!config) return -1;
    
    FILE *fp = fopen(CONFIG_FILE, "w");
    if (!fp) {
        print_threat("Error: Could not save config file.\n");
        return -1;
    }
    
    fprintf(fp, "# Log Analyser Configuration File\n\n");
    fprintf(fp, "rules_path=%s\n", config->rules_path);
    fprintf(fp, "signatures_path=%s\n", config->signatures_path);
    fprintf(fp, "output_dir=%s\n", config->output_dir);
    fprintf(fp, "max_log_size_mb=%d\n", config->max_log_size_mb);
    fprintf(fp, "retention_days=%d\n", config->retention_days);
    fprintf(fp, "enable_encryption=%d\n", config->enable_encryption);
    fprintf(fp, "packet_buffer_size=%d\n", config->packet_buffer_size);
    fprintf(fp, "analysis_threshold=%d\n", config->analysis_threshold);
    
    fclose(fp);
    return 0;
}
