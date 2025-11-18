#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include "collector.h"
#include "parser.h"

int collect_logs(const char *file_path) {
    printf("\n╔════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║  Collecting logs from: %-52s ║\n", file_path);
    printf("╚════════════════════════════════════════════════════════════════════════════╝\n\n");
    
    FILE *fp = fopen(file_path, "r");
    if (!fp) {
        printf("❌ Error: Could not open file: %s\n", file_path);
        return 1;
    }
    
    char line[MAX_LINE_LENGTH];
    int line_count = 0;
    
    // Print header
    printf("%-8s %-20s %s\n", "Line #", "Timestamp", "Log Entry");
    printf("═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    
    while (fgets(line, sizeof(line), fp)) {
        line_count++;
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        // Get current timestamp
        time_t now = time(NULL);
        struct tm *timeinfo = localtime(&now);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
        
        // Truncate line if too long for display
        char display_line[100];
        if (strlen(line) > 95) {
            snprintf(display_line, sizeof(display_line), "%.92s...", line);
        } else {
            snprintf(display_line, sizeof(display_line), "%s", line);
        }
        
        // Color alternate lines for better readability
        const char *color = (line_count % 2 == 0) ? "\033[0;36m" : "\033[0;37m"; // Cyan/White
        const char *reset = "\033[0m";
        
        printf("%s%-8d %-20s %s%s\n", color, line_count, time_str, display_line, reset);
    }
    
    printf("\n╔════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║  ✅ Total lines collected: %-48d ║\n", line_count);
    printf("╚════════════════════════════════════════════════════════════════════════════╝\n");
    
    fclose(fp);
    return 0;
}

int watch_log_file(const char *file_path) {
    printf("Watching log file: %s (Press Ctrl+C to stop)\n", file_path);
    // TODO: Implement file watching with inotify/kqueue/ReadDirectoryChangesW
    return 0;
}

// Live log monitoring with classification and storage
int monitor_live_logs(const char *file_path) {
    printf("\n╔════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║              LIVE LOG MONITORING MODE                                      ║\n");
    printf("║  Monitoring: %-61s ║\n", file_path);
    printf("║  Saving to: %-62s ║\n", LIVE_LOG_FILE);
    printf("║  Press Ctrl+C to stop                                                      ║\n");
    printf("╚════════════════════════════════════════════════════════════════════════════╝\n\n");
    
    // Open the source log file
    FILE *source_fp = fopen(file_path, "r");
    if (!source_fp) {
        printf("❌ Error: Could not open file: %s\n", file_path);
        return 1;
    }
    
    // Open the live log storage file for appending
    FILE *live_fp = fopen(LIVE_LOG_FILE, "a");
    if (!live_fp) {
        printf("❌ Error: Could not create live log file: %s\n", LIVE_LOG_FILE);
        fclose(source_fp);
        return 1;
    }
    
    // Seek to end of file to start tailing
    fseek(source_fp, 0, SEEK_END);
    
    printf("%-20s %-10s %-25s %-15s %s\n", 
           "Timestamp", "Severity", "Event Type", "Source IP", "Message");
    printf("═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    
    char line[MAX_LINE_LENGTH];
    int line_count = 0;
    
    while (1) {
        // Try to read a line
        if (fgets(line, sizeof(line), source_fp)) {
            line_count++;
            line[strcspn(line, "\n")] = 0;  // Remove newline
            
            // Save to live log file
            fprintf(live_fp, "%s\n", line);
            fflush(live_fp);  // Ensure it's written immediately
            
            // Parse and classify the log
            NormalizedLog log = {0};
            log.timestamp = (long)time(NULL);
            
            // Detect log type
            if (strstr(line, "Failed password") || strstr(line, "authentication failure")) {
                strncpy(log.raw_message, line, sizeof(log.raw_message) - 1);
                strcpy(log.event_type, "auth_failure");
                strcpy(log.severity, "MEDIUM");
                
                // Extract IP if present
                char *ip_start = strstr(line, "from ");
                if (ip_start) {
                    sscanf(ip_start + 5, "%45s", log.source_ip);
                }
            } else if (strstr(line, "Accepted password") || strstr(line, "Accepted publickey")) {
                strncpy(log.raw_message, line, sizeof(log.raw_message) - 1);
                strcpy(log.event_type, "auth_success");
                strcpy(log.severity, "INFO");
                
                char *ip_start = strstr(line, "from ");
                if (ip_start) {
                    sscanf(ip_start + 5, "%45s", log.source_ip);
                }
            } else if (strstr(line, "GET ") || strstr(line, "POST ")) {
                strncpy(log.raw_message, line, sizeof(log.raw_message) - 1);
                strcpy(log.event_type, "http_request");
                
                // Extract IP (first field in Apache logs)
                sscanf(line, "%45s", log.source_ip);
                
                if (strstr(line, " 404 ") || strstr(line, " 403 ") || strstr(line, " 500 ")) {
                    strcpy(log.severity, "WARN");
                } else {
                    strcpy(log.severity, "INFO");
                }
            } else {
                strncpy(log.raw_message, line, sizeof(log.raw_message) - 1);
                strcpy(log.event_type, "system");
                strcpy(log.severity, "INFO");
            }
            
            // Apply rule-based classification for threats
            if (strstr(line, "' OR '1'='1") || strstr(line, "union") || strstr(line, "select") ||
                strstr(line, "insert") || strstr(line, "delete") || strstr(line, "drop table")) {
                strcpy(log.event_type, "SQL_INJECTION");
                strcpy(log.severity, "CRITICAL");
            }
            
            if (strstr(line, "Failed password") && strstr(line, "invalid user")) {
                strcpy(log.event_type, "BRUTE_FORCE");
                strcpy(log.severity, "HIGH");
            }
            
            // Display with color
            const char *color = "";
            const char *reset = "\033[0m";
            
            if (strcmp(log.severity, "CRITICAL") == 0) {
                color = "\033[1;31m"; // Bold Red
            } else if (strcmp(log.severity, "HIGH") == 0) {
                color = "\033[0;31m"; // Red
            } else if (strcmp(log.severity, "WARN") == 0 || strcmp(log.severity, "MEDIUM") == 0) {
                color = "\033[0;33m"; // Yellow
            } else if (strcmp(log.severity, "INFO") == 0) {
                color = "\033[0;32m"; // Green
            } else {
                color = "\033[0;37m"; // White
            }
            
            // Format timestamp
            time_t now = log.timestamp;
            struct tm *timeinfo = localtime(&now);
            char time_str[64];
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
            
            // Truncate message if too long
            char msg_truncated[80];
            if (strlen(log.raw_message) > 75) {
                snprintf(msg_truncated, sizeof(msg_truncated), "%.72s...", log.raw_message);
            } else {
                snprintf(msg_truncated, sizeof(msg_truncated), "%s", log.raw_message);
            }
            
            printf("%s%-20s %-10s %-25s %-15s %s%s\n",
                   color,
                   time_str,
                   log.severity,
                   log.event_type,
                   log.source_ip[0] ? log.source_ip : "-",
                   msg_truncated,
                   reset);
            fflush(stdout);
            
        } else {
            // No new data, sleep briefly and check for new data
            usleep(100000);  // Sleep 100ms
            clearerr(source_fp);  // Clear EOF flag
            
            // Check if file was rotated
            struct stat st;
            if (stat(file_path, &st) == -1) {
                printf("\n⚠️  Warning: Log file disappeared. Waiting for it to reappear...\n");
                sleep(1);
            }
        }
    }
    
    fclose(source_fp);
    fclose(live_fp);
    return 0;
}

// Tail live logs - just displays raw logs without processing
int tail_live_logs(const char *file_path) {
    printf("\n╔════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║              RAW LIVE LOG TAIL MODE                                        ║\n");
    printf("║  Watching: %-64s ║\n", file_path);
    printf("║  Press Ctrl+C to stop                                                      ║\n");
    printf("╚════════════════════════════════════════════════════════════════════════════╝\n\n");
    
    FILE *fp = fopen(file_path, "r");
    if (!fp) {
        printf("❌ Error: Could not open file: %s\n", file_path);
        return 1;
    }
    
    // Seek to end of file to only show new logs
    fseek(fp, 0, SEEK_END);
    
    char line[MAX_LINE_LENGTH];
    printf("📡 Waiting for new log entries...\n\n");
    fflush(stdout);
    
    while (1) {
        if (fgets(line, sizeof(line), fp)) {
            // Just print the raw line without any processing
            printf("%s", line);
            fflush(stdout);
        } else {
            // No new data, sleep briefly
            usleep(100000);  // Sleep 100ms
            clearerr(fp);  // Clear EOF flag
            
            // Check if file was rotated
            struct stat st;
            if (stat(file_path, &st) == -1) {
                printf("\n⚠️  Warning: Log file disappeared. Waiting for it to reappear...\n");
                sleep(1);
            }
        }
    }
    
    fclose(fp);
    return 0;
}
