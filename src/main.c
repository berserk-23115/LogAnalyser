#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "help.h"
#include "collector.h"
#include "parser.h"
#include "analyzer.h"
#include "config.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Welcome to Log Analyser!\n");
        printf("Use --help for usage information\n");
        return 0;
    }

    if (strcmp(argv[1], "--help") == 0) {
        print_help();
        return 0;
    }
    
    // if (strcmp(argv[1], "--devices") == 0) {
    //     list_devices();
    //     return 0;
    // }

    if (strcmp(argv[1], "--collect") == 0) {
        if (argc < 3) {
            printf("Usage: loganalyser --collect <file_path>\n");
            return 1;
        }
        return collect_logs(argv[2]);
    }

    if (strcmp(argv[1], "--parse") == 0) {
        if (argc < 3) {
            printf("Usage: loganalyser --parse <file_path>\n");
            return 1;
        }
        return parse_log_file(argv[2]);
    }

    if (strcmp(argv[1], "--analyze") == 0) {
        if (argc < 3) {
            printf("Usage: loganalyser --analyze <database_path>\n");
            return 1;
        }
        return analyze_logs(argv[2]);
    }

    if (strcmp(argv[1], "--search") == 0) {
        if (argc < 4) {
            printf("Usage: loganalyser --search <database_path> <query>\n");
            return 1;
        }
        return search_logs(argv[2], argv[3]);
    }

    if (strcmp(argv[1], "--init") == 0) {
        return init_config();
    }

    printf("Unknown command: %s\n", argv[1]);
    printf("Use --help for usage information\n");
    return 1;
}