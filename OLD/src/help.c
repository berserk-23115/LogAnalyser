#include <stdio.h>
#include "help.h"

void print_help(void) {
    printf("\n=== Log Analyser - Portable Security Log Analysis Tool ===\n\n");
    printf("Usage: loganalyser [COMMAND] [OPTIONS]\n\n");
    
    printf("Commands:\n");
    printf("  --help                          Show this help message\n");
    printf("  --init                          Initialize configuration and database\n");
    printf("  --collect <file_path>           Collect logs from specified file\n");
    printf("  --parse <file_path>             Parse and normalize log file\n");
    printf("  --analyze <database_path>       Analyze collected logs for threats\n");
    printf("  --search <db_path> <query>      Search logs by keyword or pattern\n");
    // printf("  --devices                       List available network devices\n");
    printf("  --report <db_path> [format]     Generate report (txt, csv, json)\n");
    printf("  --update                        Update detection rules and signatures\n\n");
    
    printf("Examples:\n");
    printf("  loganalyser --init\n");
    printf("  loganalyser --collect /var/log/auth.log\n");
    printf("  loganalyser --parse /var/log/apache2/access.log\n");
    printf("  loganalyser --search logs.db \"failed login\"\n");
    printf("  loganalyser --analyze logs.db\n\n");
    
    printf("For more information, visit the documentation.\n\n");
}

void list_devices(void) {
    printf("Network device listing feature - Coming soon!\n");
    printf("This will show available network interfaces for packet capture.\n");
}
