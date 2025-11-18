#include "demo.h"
#include "log_analyzer.h"
#include "packet_capture.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(const char *program) {
    printf("Usage: %s [--input file] [--list-samples]\n", program);
    printf("       %s capture [--iface en0] [--limit N] [--duration SEC]\n", program);
    printf("           [--log path] [--threshold N] [--window SEC]\n");
    printf("       %s run demo test1\n", program);
    printf("Defaults to sample-logs/auth.log when no file is provided.\n");
}

static void list_samples(void) {
    printf("Available sample logs:\n");
    printf("  sample-logs/auth.log\n");
    printf("  sample-logs/web.log\n");
    printf("  sample-logs/demo_test1.log (written by demo mode)\n");
}


static size_t parse_size_arg(const char *value, size_t fallback) {
    if (!value) return fallback;
    errno = 0;
    char *end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (errno != 0 || !end || *end != '\0') {
        return fallback;
    }
    return (size_t)parsed;
}

static unsigned int parse_uint_arg(const char *value, unsigned int fallback) {
    if (!value) return fallback;
    errno = 0;
    char *end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (errno != 0 || !end || *end != '\0') {
        return fallback;
    }
    return (unsigned int)parsed;
}

static int run_file_analysis(const char *input_path) {
    LogEntry entries[1024];
    SuspiciousEvent events[1024];

    // Load log entries from file into memory
    size_t count = load_log_file(input_path, entries, 1024);
    if (count == 0) {
        fprintf(stderr, "No logs loaded from %s\n", input_path);
        return 1;
    }

    // Generate statistics and detect suspicious patterns
    LogStats stats = summarize_logs(entries, count);
    size_t suspicious = find_suspicious_events(entries, count, events, 1024);
    stats.suspicious = suspicious;

    printf("Analysing %s (%zu entries)\n", input_path, count);
    print_log_summary(&stats);
    print_suspicious_events(events, suspicious);
    printf("\nDone.\n");
    return 0;
}

static int handle_file_mode(int argc, char **argv) {
    // Default to analyzing the auth.log sample if no file specified
    const char *input_path = "sample-logs/auth.log";

    // Parse command-line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--input") == 0 && i + 1 < argc) {
            input_path = argv[++i];
        } else if (strcmp(argv[i], "--list-samples") == 0) {
            list_samples();
            return 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    return run_file_analysis(input_path);
}


static int handle_capture(int argc, char **argv) {
    // Default capture parameters
    const char *iface = NULL;  // Network interface (NULL = auto-select)
    const char *log_path = "sample-logs/live_capture.log";
    size_t limit = 500;  // Maximum packets to capture
    unsigned int duration = 15;  // Maximum capture duration in seconds
    unsigned int threshold = 120;  // DDoS detection threshold (packets per window)
    unsigned int window_seconds = 5;  // DDoS detection window size

    // Parse capture-specific command-line arguments
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            iface = argv[++i];
        } else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            log_path = argv[++i];
        } else if (strcmp(argv[i], "--limit") == 0 && i + 1 < argc) {
            limit = parse_size_arg(argv[++i], limit);
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            duration = parse_uint_arg(argv[++i], duration);
        } else if (strcmp(argv[i], "--threshold") == 0 && i + 1 < argc) {
            threshold = parse_uint_arg(argv[++i], threshold);
        } else if (strcmp(argv[i], "--window") == 0 && i + 1 < argc) {
            window_seconds = parse_uint_arg(argv[++i], window_seconds);
        } else {
            fprintf(stderr, "Unknown capture argument: %s\n", argv[i]);
            return 1;
        }
    }

    // Configure capture options
    CaptureOptions options = {
        .interface_name = iface,
        .packet_limit = limit,
        .duration_seconds = duration,
        .log_path = log_path,
        .ddos_threshold = threshold,
        .ddos_window_seconds = window_seconds,
    };

    // Execute the live packet capture
    CaptureReport report;
    if (capture_live_packets(&options, &report) != 0) {
        return 1;
    }

    printf("Capture log written to %s\n", log_path);
    print_capture_report(&options, &report);
    return 0;
}

static int handle_run_command(int argc, char **argv) {
    if (argc >= 4 && strcmp(argv[2], "demo") == 0 && strcmp(argv[3], "test1") == 0) {
        return run_demo_test1();
    }
    fprintf(stderr, "Unknown run command. Expected: %s run demo test1\n", argv[0]);
    return 1;
}

int main(int argc, char **argv) {
    // Check for subcommands
    if (argc >= 2) {
        // Live packet capture mode
        if (strcmp(argv[1], "capture") == 0) {
            return handle_capture(argc, argv);
        }
        // Special run commands (demos, tests)
        if (strcmp(argv[1], "run") == 0) {
            return handle_run_command(argc, argv);
        }
    }

    // Default mode: analyze a log file
    return handle_file_mode(argc, argv);
}
