#ifndef PARSER_H
#define PARSER_H

#include <time.h>

typedef enum {
    LOG_TYPE_UNKNOWN,
    LOG_TYPE_SYSLOG,
    LOG_TYPE_APACHE,
    LOG_TYPE_NGINX,
    LOG_TYPE_AUTH,
    LOG_TYPE_JSON,
    LOG_TYPE_CSV,
    LOG_TYPE_WINDOWS_EVENT,
    LOG_TYPE_FIREWALL
} LogType;

typedef struct {
    time_t timestamp;
    char source_ip[46];
    char dest_ip[46];
    char event_type[64];
    char severity[16];
    char user[128];
    char process[128];
    int port;
    char protocol[16];
    char raw_message[4096];
    LogType log_type;
} NormalizedLog;

// Main parsing functions
int parse_log_file(const char *file_path);
int parse_log_line(const char *line, NormalizedLog *log);
LogType detect_log_type(const char *line);

// Format-specific parsers
int parse_syslog(const char *line, NormalizedLog *log);
int parse_apache_log(const char *line, NormalizedLog *log);
int parse_nginx_log(const char *line, NormalizedLog *log);
int parse_json_log(const char *line, NormalizedLog *log);
int parse_csv_log(const char *line, NormalizedLog *log);
int parse_windows_event(const char *line, NormalizedLog *log);
int parse_firewall_log(const char *line, NormalizedLog *log);

// Utility functions
time_t parse_timestamp(const char *timestamp_str);
int extract_ip_address(const char *text, char *ip_buffer, size_t buffer_size);
void normalize_severity(const char *input, char *output);

// Export functions
int export_logs_to_json(NormalizedLog *logs, int count, const char *filename);
int export_logs_to_csv(NormalizedLog *logs, int count, const char *filename);
int print_log_formatted(const NormalizedLog *log);

#endif
