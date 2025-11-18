#ifndef LOG_ANALYZER_H
#define LOG_ANALYZER_H

#include <stddef.h>

#define MAX_MESSAGE_LEN 256
#define MAX_FIELD_LEN 64

typedef struct {
    char timestamp[MAX_FIELD_LEN];
    char level[MAX_FIELD_LEN];
    char source[MAX_FIELD_LEN];
    char message[MAX_MESSAGE_LEN];
} LogEntry;

typedef struct {
    size_t total;
    size_t info;
    size_t warn;
    size_t error;
    size_t critical;
    size_t suspicious;
} LogStats;

typedef struct {
    char level[MAX_FIELD_LEN];
    char source[MAX_FIELD_LEN];
    char message[MAX_MESSAGE_LEN];
    char reason[MAX_FIELD_LEN];
} SuspiciousEvent;

int parse_log_line(const char *line, LogEntry *entry);
size_t load_log_file(const char *path, LogEntry *entries, size_t max_entries);
LogStats summarize_logs(const LogEntry *entries, size_t count);
size_t find_suspicious_events(const LogEntry *entries, size_t count,
                             SuspiciousEvent *events, size_t max_events);
void print_log_summary(const LogStats *stats);
void print_suspicious_events(const SuspiciousEvent *events, size_t count);

#endif // LOG_ANALYZER_H
