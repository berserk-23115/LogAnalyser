#ifndef PARSER_H
#define PARSER_H

#include <time.h>

typedef enum {
    LOG_TYPE_UNKNOWN,
    LOG_TYPE_SYSLOG,
    LOG_TYPE_APACHE,
    LOG_TYPE_NGINX,
    LOG_TYPE_AUTH,
    LOG_TYPE_JSON
} LogType;

typedef struct {
    time_t timestamp;
    char source_ip[46];
    char dest_ip[46];
    char event_type[64];
    char severity[16];
    char raw_message[4096];
    LogType log_type;
} NormalizedLog;

int parse_log_file(const char *file_path);
LogType detect_log_type(const char *line);
int parse_syslog(const char *line, NormalizedLog *log);
int parse_apache_log(const char *line, NormalizedLog *log);

#endif
