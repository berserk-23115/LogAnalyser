#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        printf("Usage: LogAnalyser [options]\n");
        printf("Options:\n");
        printf("  --help    Show this help message\n");
        return 0;
    }
    printf("Welcome to Log Analyser!\n");
    return 0;

}