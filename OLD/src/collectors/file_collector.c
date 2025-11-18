#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "collector.h"

int collect_logs(const char *file_path) {
    printf("Collecting logs from: %s\n", file_path);
    
    FILE *fp = fopen(file_path, "r");
    if (!fp) {
        printf("Error: Could not open file: %s\n", file_path);
        return 1;
    }
    
    char line[MAX_LINE_LENGTH];
    int line_count = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        line_count++;
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        // Simple display (will be stored to DB later)
        if (line_count <= 10) {
            printf("[%d] %s\n", line_count, line);
        }
    }
    
    printf("\nTotal lines collected: %d\n", line_count);
    
    fclose(fp);
    return 0;
}

int watch_log_file(const char *file_path) {
    printf("Watching log file: %s (Press Ctrl+C to stop)\n", file_path);
    // TODO: Implement file watching with inotify/kqueue/ReadDirectoryChangesW
    return 0;
}
