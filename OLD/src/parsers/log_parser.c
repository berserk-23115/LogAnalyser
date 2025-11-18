#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "parser.h"

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
    printf("Parsing log file: %s\n", file_path);
    
    FILE *fp = fopen(file_path, "r");
    if (!fp) {
        printf("Error: Could not open file\n");
        return 1;
    }
    
    char line[4096];
    int parsed_count = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;
        
        NormalizedLog log = {0};
        LogType type = detect_log_type(line);
        
        switch (type) {
            case LOG_TYPE_SYSLOG:
                if (parse_syslog(line, &log) == 0) parsed_count++;
                break;
            case LOG_TYPE_APACHE:
                if (parse_apache_log(line, &log) == 0) parsed_count++;
                break;
            default:
                strncpy(log.raw_message, line, sizeof(log.raw_message) - 1);
                log.log_type = LOG_TYPE_UNKNOWN;
                parsed_count++;
                break;
        }
        
        // Display first few parsed logs
        if (parsed_count <= 5) {
            printf("[%s] %s: %s\n", log.severity, log.event_type, log.raw_message);
        }
    }
    
    printf("\nTotal logs parsed: %d\n", parsed_count);
    
    fclose(fp);
    return 0;
}
