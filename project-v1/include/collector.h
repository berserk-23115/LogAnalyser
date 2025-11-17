#ifndef COLLECTOR_H
#define COLLECTOR_H

#define MAX_LINE_LENGTH 4096
#define LIVE_LOG_FILE "logs_live.txt"

int collect_logs(const char *file_path);
int watch_log_file(const char *file_path);
int monitor_live_logs(const char *file_path);
int tail_live_logs(const char *file_path);

#endif
