#ifndef ANALYZER_H
#define ANALYZER_H

int analyze_logs(const char *database_path);
int search_logs(const char *database_path, const char *query);
int detect_threats(const char *database_path);

#endif
