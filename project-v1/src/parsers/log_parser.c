#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "parser.h"
#include "rules.h"

LogType detect_log_type(const char *line) {
    if (strstr(line, "syslog") || strstr(line, "kernel:")) {
        return LOG_TYPE_SYSLOG;
    } else if (strstr(line, "GET ") || strstr(line, "POST ")) {
        return LOG_TYPE_APACHE;
    } else if (strstr(line, "authentication failure")) {
        return LOG_TYPE_AUTH;
    } else if (line[0] == '{') {
        return LOG_TYPE_JSON;
    }
    return LOG_TYPE_UNKNOWN;
}

int parse_syslog(const char *line, NormalizedLog *log) {
    // Simple syslog parsing (Month Day Time Host Process: Message)
    char month[16], day[16], time_str[16], host[256];
    
    if (sscanf(line, "%s %s %s %s", month, day, time_str, host) == 4) {
        snprintf(log->raw_message, sizeof(log->raw_message), "%s", line);
        strcpy(log->event_type, "syslog");
        strcpy(log->severity, "INFO");
        log->log_type = LOG_TYPE_SYSLOG;
        return 0;
    }
    return 1;
}

int parse_apache_log(const char *line, NormalizedLog *log) {
    // Common Log Format: IP - - [timestamp] "REQUEST" status size
    char ip[46], timestamp[64], request[512];
    int status, size;
    
    if (sscanf(line, "%45s - - [%63[^]]] \"%511[^\"]\" %d %d", 
               ip, timestamp, request, &status, &size) == 5) {
        strncpy(log->source_ip, ip, sizeof(log->source_ip) - 1);
        snprintf(log->raw_message, sizeof(log->raw_message), "%s", line);
        strcpy(log->event_type, "http_request");
        strcpy(log->severity, status >= 400 ? "WARN" : "INFO");
        log->log_type = LOG_TYPE_APACHE;
        return 0;
    }
    return 1;
}

int parse_log_file(const char *file_path) {
    printf("\n╔════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║  Parsing log file: %-56s ║\n", file_path);
    printf("╚════════════════════════════════════════════════════════════════════════════╝\n\n");
    
    FILE *fp = fopen(file_path, "r");
    if (!fp) {
        printf("❌ Error: Could not open file\n");
        return 1;
    }
    
    // Print header
    printf("%-20s %-10s %-25s %-15s %-15s %s\n", 
           "Timestamp", "Severity", "Event Type", "Source IP", "Dest IP", "Message");
    printf("═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    
    char line[4096];
    int parsed_count = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;
        
        NormalizedLog log = {0};
        LogType type = detect_log_type(line);
        
        // Set timestamp to current time
        log.timestamp = (long)time(NULL);
        
        switch (type) {
            case LOG_TYPE_SYSLOG:
                if (parse_syslog(line, &log) == 0) {
                    classify_log(&log);
                    parsed_count++;
                }
                break;
            case LOG_TYPE_APACHE:
                if (parse_apache_log(line, &log) == 0) {
                    classify_log(&log);
                    parsed_count++;
                }
                break;
            default:
                strncpy(log.raw_message, line, sizeof(log.raw_message) - 1);
                log.log_type = LOG_TYPE_UNKNOWN;
                strcpy(log.event_type, "unknown");
                strcpy(log.severity, "INFO");
                classify_log(&log);
                parsed_count++;
                break;
        }
        
        // Display log with color
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
        char msg_truncated[60];
        if (strlen(log.raw_message) > 58) {
            snprintf(msg_truncated, sizeof(msg_truncated), "%.55s...", log.raw_message);
        } else {
            snprintf(msg_truncated, sizeof(msg_truncated), "%s", log.raw_message);
        }
        
        printf("%s%-20s %-10s %-25s %-15s %-15s %s%s\n",
               color,
               time_str,
               log.severity,
               log.event_type,
               log.source_ip[0] ? log.source_ip : "-",
               log.dest_ip[0] ? log.dest_ip : "-",
               msg_truncated,
               reset);
    }
    
    printf("\n╔════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║  ✅ Total logs parsed: %-52d ║\n", parsed_count);
    printf("╚════════════════════════════════════════════════════════════════════════════╝\n");
    
    fclose(fp);
    return 0;
}
