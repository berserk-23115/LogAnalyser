#include "ddos_detector.h"

#include <stddef.h>

typedef struct {
    const char *interface_name;
    size_t packet_limit;
    unsigned int duration_seconds;
    const char *log_path;
    unsigned int ddos_threshold;
    unsigned int ddos_window_seconds;
} CaptureOptions;

typedef struct {
    size_t total_packets;
    size_t ipv4_packets;
    size_t logged_packets;
    size_t errors;
    size_t ddos_alerts;
    DDoSAlert alerts[16];
} CaptureReport;

int capture_live_packets(const CaptureOptions *options, CaptureReport *report);
void print_capture_report(const CaptureOptions *options, const CaptureReport *report);
