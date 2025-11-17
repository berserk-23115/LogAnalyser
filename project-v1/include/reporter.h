#ifndef REPORTER_H
#define REPORTER_H

#include "analyzer.h"
#include "parser.h"
#include <time.h>

// Report formats
typedef enum {
    REPORT_FORMAT_TEXT,
    REPORT_FORMAT_JSON,
    REPORT_FORMAT_CSV,
    REPORT_FORMAT_HTML
} ReportFormat;

// Report structure
typedef struct {
    char title[256];
    time_t generated_at;
    int total_logs;
    int total_threats;
    ThreatDetection *threats;
    int threat_count;
    AnalysisStats stats;
} SecurityReport;

// Report generation functions
int generate_report(SecurityReport *report, ReportFormat format, const char *output_file);
int generate_text_report(SecurityReport *report, const char *output_file);
int generate_json_report(SecurityReport *report, const char *output_file);
int generate_csv_report(SecurityReport *report, const char *output_file);
int generate_html_report(SecurityReport *report, const char *output_file);

// Summary functions
void print_executive_summary(SecurityReport *report);
void print_threat_trends(ThreatDetection *threats, int count);
void print_statistics(const AnalysisStats *stats);

// Report helpers
SecurityReport* create_report(const char *title);
void free_report(SecurityReport *report);
int add_threats_to_report(SecurityReport *report, ThreatDetection *threats, int count);

#endif
