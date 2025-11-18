#ifndef CONFIG_H
#define CONFIG_H

#define CONFIG_FILE "loganalyser.conf"
#define DEFAULT_DB_PATH "logs.db"
#define MAX_PATH_LENGTH 512

typedef struct {
    char database_path[MAX_PATH_LENGTH];
    char rules_path[MAX_PATH_LENGTH];
    int max_log_size_mb;
    int retention_days;
    int enable_anomaly_detection;
} Config;

int init_config(void);
int load_config(Config *config);
int save_config(const Config *config);

#endif
