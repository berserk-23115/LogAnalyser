#ifndef ANALYZER_H
#define ANALYZER_H

#include "parser.h"
#include <stddef.h>

// Analysis modes
typedef enum {
    ANALYSIS_SIGNATURE = 1,
    ANALYSIS_ANOMALY = 2,
    ANALYSIS_TTP = 4,
    ANALYSIS_ALL = 7
} AnalysisMode;

// Threat severity levels
typedef enum {
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL
} ThreatSeverity;

// Threat detection result
typedef struct {
    char threat_name[128];
    char description[512];
    ThreatSeverity severity;
    time_t detected_at;
    char source_ip[46];
    char indicators[256];
    int confidence;  // 0-100
} ThreatDetection;

// Analysis statistics
typedef struct {
    int total_logs_analyzed;
    int threats_detected;
    int anomalies_found;
    int false_positives;
    double analysis_time_sec;
    int packet_rate_avg;
    int packet_rate_max;
} AnalysisStats;

// Signature-based detection
int analyze_with_signatures(NormalizedLog *logs, int count, ThreatDetection *threats, int max_threats);
int load_threat_signatures(const char *signature_file);
int match_signature(const NormalizedLog *log);

// Anomaly-based detection
int analyze_with_anomaly_detection(NormalizedLog *logs, int count, ThreatDetection *threats, int max_threats);
int calculate_baseline_stats(NormalizedLog *logs, int count);
int detect_statistical_anomaly(const NormalizedLog *log);

// TTP (Tactics, Techniques, Procedures) correlation
int analyze_with_ttp_correlation(NormalizedLog *logs, int count, ThreatDetection *threats, int max_threats);
int load_ttp_rules(const char *rules_file);
int correlate_events(NormalizedLog *logs, int count);

// Main analysis functions
int analyze_logs(const char *database_path);
int analyze_logs_from_buffer(NormalizedLog *logs, int count, int mode);
int search_logs(const char *database_path, const char *query);
int detect_threats(const char *database_path);

// Filtering and search
int filter_logs_by_severity(NormalizedLog *logs, int count, const char *severity, NormalizedLog *output);
int filter_logs_by_ip(NormalizedLog *logs, int count, const char *ip, NormalizedLog *output);
int filter_logs_by_timerange(NormalizedLog *logs, int count, time_t start, time_t end, NormalizedLog *output);

// Output functions
int export_threats_to_json(ThreatDetection *threats, int count, const char *filename);
int export_threats_to_csv(ThreatDetection *threats, int count, const char *filename);
void print_threat_summary(ThreatDetection *threats, int count);
void print_analysis_stats(const AnalysisStats *stats);

#endif
