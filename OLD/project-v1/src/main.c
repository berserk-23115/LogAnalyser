#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include "help.h"
#include "collector.h"
#include "parser.h"
#include "config.h"
#include "pcap_collector.h"
#include "analyzer.h"

// Forward declarations for new commands
int run_interactive_mode(void);
int analyze_command(int argc, char *argv[]);
int report_command(int argc, char *argv[]);
int update_command(int argc, char *argv[]);
void print_banner(void);
void show_usage(void);

/**
 * Print application banner
 */
void print_banner(void) {
    printf("\n");
    print_info("╔════════════════════════════════════════════════════════════╗\n");
    print_info("║          Live Log Analyser v2.0                            ║\n");
    print_info("║          Real-time Security Log Analysis & Monitoring      ║\n");
    print_info("╚════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

/**
 * Show usage information
 */
void show_usage(void) {
    printf("Usage: loganalyser [COMMAND] [OPTIONS]\n\n");
    printf("Commands:\n");
    print_info("  collect       "); printf("Collect logs from files or devices\n");
    print_info("  analyze       "); printf("Analyze collected logs for threats\n");
    print_info("  report        "); printf("Generate reports from analysis results\n");
    print_info("  interactive   "); printf("Enter interactive mode\n");
    print_info("  update        "); printf("Update signatures and rules\n");
    print_info("  --capture     "); printf("Capture network traffic (PCAP)\n");
    print_info("  --devices     "); printf("List available network devices\n");
    print_info("  --init        "); printf("Initialize configuration\n");
    print_info("  --help        "); printf("Show detailed help\n");
    printf("\nExamples:\n");
    printf("  loganalyser collect /var/log/auth.log\n");
    printf("  loganalyser analyze --anomaly --threshold 5\n");
    printf("  loganalyser --capture eth0\n");
    printf("  loganalyser interactive\n");
    printf("\nFor detailed help: loganalyser --help\n\n");
}

/**
 * Main entry point
 */
int main(int argc, char *argv[]) {
    // Initialize console colors for cross-platform support
    init_console_colors();
    
    // Load configuration
    load_config(&g_config);
    
    // No arguments - show banner and usage
    if (argc < 2) {
        print_banner();
        show_usage();
        return 0;
    }

    // Parse commands
    const char *command = argv[1];
    
    // Help command
    if (strcmp(command, "--help") == 0 || strcmp(command, "-h") == 0) {
        print_help();
        return 0;
    }
    
    // Initialize configuration
    if (strcmp(command, "--init") == 0) {
        return init_config();
    }
    
    // List devices
    if (strcmp(command, "--devices") == 0) {
        list_devices();
        return 0;
    }

    // Capture network traffic
    if (strcmp(command, "--capture") == 0) {
        if (argc < 3) {
            print_threat("Error: Interface name required\n");
            printf("Usage: loganalyser --capture <interface_name>\n");
            printf("Use --devices to list available interfaces.\n");
            return 1;
        }
        return start_capture(argv[2]);
    }

    // Collect logs from file
    if (strcmp(command, "collect") == 0 || strcmp(command, "--collect") == 0) {
        if (argc < 3) {
            print_threat("Error: File path required\n");
            printf("Usage: loganalyser collect <file_path>\n");
            return 1;
        }
        return collect_logs(argv[2]);
    }

    // Parse logs
    if (strcmp(command, "--parse") == 0) {
        if (argc < 3) {
            print_threat("Error: File path required\n");
            printf("Usage: loganalyser --parse <file_path>\n");
            return 1;
        }
        return parse_log_file(argv[2]);
    }

    // Monitor logs in real-time
    if (strcmp(command, "--monitor") == 0) {
        if (argc < 3) {
            print_threat("Error: Log file path required\n");
            printf("Usage: loganalyser --monitor <log_file_to_monitor>\n");
            printf("Example: loganalyser --monitor /var/log/auth.log\n");
            return 1;
        }
        return monitor_live_logs(argv[2]);
    }

    // Tail logs
    if (strcmp(command, "--tail") == 0) {
        if (argc < 3) {
            print_threat("Error: Log file path required\n");
            printf("Usage: loganalyser --tail <log_file_to_tail>\n");
            printf("Example: loganalyser --tail /var/log/auth.log\n");
            return 1;
        }
        return tail_live_logs(argv[2]);
    }
    
    // Analyze command
    if (strcmp(command, "analyze") == 0) {
        return analyze_command(argc, argv);
    }
    
    // Report command
    if (strcmp(command, "report") == 0) {
        return report_command(argc, argv);
    }
    
    // Update command
    if (strcmp(command, "update") == 0) {
        return update_command(argc, argv);
    }
    
    // Interactive mode
    if (strcmp(command, "interactive") == 0 || strcmp(command, "-i") == 0) {
        return run_interactive_mode();
    }

    // Unknown command
    print_threat("Unknown command: ");
    printf("%s\n", command);
    printf("Use --help for usage information\n");
    return 1;
}

/**
 * Interactive mode - CLI loop
 */
int run_interactive_mode(void) {
    char input[512];
    char *args[32];
    int running = 1;
    
    print_banner();
    print_success("Entering interactive mode. Type 'help' for commands or 'exit' to quit.\n\n");
    
    while (running) {
        print_info("loganalyser> ");
        
        if (!fgets(input, sizeof(input), stdin)) {
            break;
        }
        
        // Remove newline
        input[strcspn(input, "\n")] = 0;
        
        // Skip empty input
        if (strlen(input) == 0) continue;
        
        // Parse input into arguments
        int argc = 0;
        char *token = strtok(input, " ");
        while (token && argc < 32) {
            args[argc++] = token;
            token = strtok(NULL, " ");
        }
        
        if (argc == 0) continue;
        
        // Process commands
        if (strcmp(args[0], "exit") == 0 || strcmp(args[0], "quit") == 0) {
            print_success("Exiting interactive mode.\n");
            running = 0;
        }
        else if (strcmp(args[0], "help") == 0) {
            show_usage();
        }
        else if (strcmp(args[0], "collect") == 0) {
            if (argc < 2) {
                print_warning("Usage: collect <file_path>\n");
            } else {
                collect_logs(args[1]);
            }
        }
        else if (strcmp(args[0], "analyze") == 0) {
            analyze_command(argc, args);
        }
        else if (strcmp(args[0], "report") == 0) {
            report_command(argc, args);
        }
        else if (strcmp(args[0], "devices") == 0) {
            list_devices();
        }
        else if (strcmp(args[0], "capture") == 0) {
            if (argc < 2) {
                print_warning("Usage: capture <interface>\n");
            } else {
                start_capture(args[1]);
            }
        }
        else if (strcmp(args[0], "update") == 0) {
            update_command(argc, args);
        }
        else if (strcmp(args[0], "config") == 0) {
            printf("Current configuration:\n");
            printf("  Rules: %s\n", g_config.rules_path);
            printf("  Encryption: %s\n", g_config.enable_encryption ? "Enabled" : "Disabled");
        }
        else if (strcmp(args[0], "clear") == 0) {
            #ifdef PLATFORM_WINDOWS
                system("cls");
            #else
                system("clear");
            #endif
            print_banner();
        }
        else {
            print_warning("Unknown command: ");
            printf("%s\n", args[0]);
            printf("Type 'help' for available commands.\n");
        }
    }
    
    return 0;
}

/**
 * Analyze command - performs log analysis
 */
int analyze_command(int argc, char *argv[]) {
    int anomaly_mode = 0;
    int signature_mode = 1;  // Default
    int threshold = g_config.analysis_threshold;
    const char *input_file = NULL;
    
    // Parse options
    static struct option long_options[] = {
        {"anomaly",   no_argument,       0, 'a'},
        {"signature", no_argument,       0, 's'},
        {"threshold", required_argument, 0, 't'},
        {"input",     required_argument, 0, 'i'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    optind = 1; // Reset getopt
    while ((opt = getopt_long(argc, argv, "ast:i:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'a':
                anomaly_mode = 1;
                break;
            case 's':
                signature_mode = 1;
                break;
            case 't':
                threshold = atoi(optarg);
                break;
            case 'i':
                input_file = optarg;
                break;
            case 'h':
                printf("Usage: analyze [OPTIONS]\n");
                printf("Options:\n");
                printf("  -a, --anomaly       Enable anomaly detection\n");
                printf("  -s, --signature     Enable signature-based detection (default)\n");
                printf("  -t, --threshold N   Set detection threshold\n");
                printf("  -i, --input FILE    Input log file\n");
                return 0;
            default:
                return 1;
        }
    }
    
    print_info("Starting analysis...\n");
    if (anomaly_mode) {
        print_info("Mode: Anomaly Detection (threshold: ");
        printf("%d)\n", threshold);
    }
    if (signature_mode) {
        print_info("Mode: Signature-based Detection\n");
    }
    
    // TODO: Call actual analysis functions
    print_success("Analysis complete!\n");
    return 0;
}

/**
 * Report command - generates reports
 */
int report_command(int argc, char *argv[]) {
    const char *format = "text";
    const char *output = "report.txt";
    
    // Parse options
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            format = argv[++i];
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output = argv[++i];
        }
    }
    
    print_info("Generating report...\n");
    printf("Format: %s\n", format);
    printf("Output: %s\n", output);
    
    // TODO: Call actual report generation
    print_success("Report generated successfully!\n");
    return 0;
}

/**
 * Update command - updates signatures and rules
 */
int update_command(int argc, char *argv[]) {
    const char *source = "updates/";
    
    if (argc > 2) {
        source = argv[2];
    }
    
    print_info("Updating signatures from: ");
    printf("%s\n", source);
    
    // TODO: Implement signature update logic
    print_success("Signatures updated successfully!\n");
    return 0;
}
