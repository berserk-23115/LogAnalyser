#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "config.h"

int init_config(void) {
    Config config = {
        .database_path = DEFAULT_DB_PATH,
        .rules_path = "rules/",
        .max_log_size_mb = 1024,
        .retention_days = 90,
        .enable_anomaly_detection = 1
    };
    
    printf("Initializing Log Analyser...\n");
    
    FILE *fp = fopen(CONFIG_FILE, "w");
    if (!fp) {
        printf("Error: Could not create configuration file\n");
        return 1;
    }
    
    fprintf(fp, "# Log Analyser Configuration\n");
    fprintf(fp, "database_path=%s\n", config.database_path);
    fprintf(fp, "rules_path=%s\n", config.rules_path);
    fprintf(fp, "max_log_size_mb=%d\n", config.max_log_size_mb);
    fprintf(fp, "retention_days=%d\n", config.retention_days);
    fprintf(fp, "enable_anomaly_detection=%d\n", config.enable_anomaly_detection);
    
    fclose(fp);
    
    printf("Configuration file created: %s\n", CONFIG_FILE);
    printf("Database will be stored at: %s\n", config.database_path);
    printf("Rules directory: %s\n", config.rules_path);
    printf("\nInitialization complete!\n");
    
    return 0;
}

int load_config(Config *config) {
    FILE *fp = fopen(CONFIG_FILE, "r");
    if (!fp) {
        printf("Warning: Configuration file not found. Using defaults.\n");
        strcpy(config->database_path, DEFAULT_DB_PATH);
        strcpy(config->rules_path, "rules/");
        config->max_log_size_mb = 1024;
        config->retention_days = 90;
        config->enable_anomaly_detection = 1;
        return 1;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        
        char key[128], value[128];
        if (sscanf(line, "%127[^=]=%127s", key, value) == 2) {
            if (strcmp(key, "database_path") == 0) {
                strncpy(config->database_path, value, MAX_PATH_LENGTH - 1);
            } else if (strcmp(key, "rules_path") == 0) {
                strncpy(config->rules_path, value, MAX_PATH_LENGTH - 1);
            } else if (strcmp(key, "max_log_size_mb") == 0) {
                config->max_log_size_mb = atoi(value);
            } else if (strcmp(key, "retention_days") == 0) {
                config->retention_days = atoi(value);
            } else if (strcmp(key, "enable_anomaly_detection") == 0) {
                config->enable_anomaly_detection = atoi(value);
            }
        }
    }
    
    fclose(fp);
    return 0;
}

int save_config(const Config *config) {
    FILE *fp = fopen(CONFIG_FILE, "w");
    if (!fp) return 1;
    
    fprintf(fp, "# Log Analyser Configuration\n");
    fprintf(fp, "database_path=%s\n", config->database_path);
    fprintf(fp, "rules_path=%s\n", config->rules_path);
    fprintf(fp, "max_log_size_mb=%d\n", config->max_log_size_mb);
    fprintf(fp, "retention_days=%d\n", config->retention_days);
    fprintf(fp, "enable_anomaly_detection=%d\n", config->enable_anomaly_detection);
    
    fclose(fp);
    return 0;
}
