#include <stdio.h>

void print_help() {
    printf("Usage: LogAnalyser [options]\n");
    printf("Options:\n");
    printf("  --help          Show this help message\n");
    printf("  --devices       List available network devices\n");
    printf("  --load    Load logs from a file\n");
    printf("  --search <term> Search for a term in logs\n");
    printf("  --filter <rule> Filter logs based on a rule\n");
    printf("  --report        Generate a report\n");
    printf("  --export  Export results to a file\n");
}
