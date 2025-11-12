#ifndef COLLECTOR_H
#define COLLECTOR_H

#define MAX_LINE_LENGTH 4096

int collect_logs(const char *file_path);
int watch_log_file(const char *file_path);

#endif
