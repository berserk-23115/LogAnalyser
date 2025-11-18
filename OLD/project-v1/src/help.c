#include <stdio.h>
#include "help.h"

void print_help(void) {
    printf("\n╔══════════════════════════════════════════════════════════════════════╗\n");
    printf("║     Log Analyser - Real-Time Security Log Analysis Tool             ║\n");
    printf("║     Live monitoring with automatic threat detection                 ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════╝\n\n");
    printf("Usage: loganalyser [COMMAND] [OPTIONS]\n\n");
    
    printf("Commands:\n");
    printf("  --help                          Show this help message\n");
    printf("  --init                          Initialize configuration\n");
    printf("  --collect <file_path>           Display logs from specified file\n");
    printf("  --parse <file_path>             Parse and classify log file\n");
    printf("  --monitor <file_path>           Monitor live logs with classification\n");
    printf("  --tail <file_path>              Show raw live logs (no processing)\n");
    printf("  --devices                       List available network devices\n");
    printf("  --capture <interface>           Start live network capture\n\n");
    
    printf(" LIVE MONITORING:\n");
    printf("  --monitor: Watches file, classifies threats, saves to logs_live.txt\n");
    printf("  --tail:    Just shows raw logs like 'tail -f', no processing\n\n");
    
    printf("Examples:\n");
    printf("  loganalyser --init\n");
    printf("  loganalyser --collect /var/log/auth.log\n");
    printf("  loganalyser --parse /var/log/apache2/access.log\n");
    printf("  loganalyser --monitor /var/log/auth.log          # Live with classification\n");
    printf("  loganalyser --tail /var/log/auth.log             # Raw live logs\n");
    printf("  loganalyser --capture eth0                       # Network capture\n\n");
    
    printf(" Color Legend:\n");
    printf("  \033[1;31m● CRITICAL\033[0m - SQL injection, severe attacks\n");
    printf("  \033[0;31m● HIGH\033[0m     - Brute force attempts\n");
    printf("  \033[0;33m● MEDIUM\033[0m   - Failed logins, warnings\n");
    printf("  \033[0;32m● INFO\033[0m     - Normal operations\n\n");
    
    printf("For more information, visit the documentation.\n\n");
}


