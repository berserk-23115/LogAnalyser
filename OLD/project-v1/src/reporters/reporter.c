#include "reporter.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * Create a new report
 */
SecurityReport* create_report(const char *title) {
    SecurityReport *report = (SecurityReport*)calloc(1, sizeof(SecurityReport));
    if (!report) return NULL;
    
    strncpy(report->title, title, 255);
    report->generated_at = time(NULL);
    report->threats = NULL;
    report->threat_count = 0;
    
    return report;
}

/**
 * Free report memory
 */
void free_report(SecurityReport *report) {
    if (!report) return;
    if (report->threats) free(report->threats);
    free(report);
}

/**
 * Add threats to report
 */
int add_threats_to_report(SecurityReport *report, ThreatDetection *threats, int count) {
    if (!report || !threats || count <= 0) return -1;
    
    report->threats = (ThreatDetection*)malloc(count * sizeof(ThreatDetection));
    if (!report->threats) return -1;
    
    memcpy(report->threats, threats, count * sizeof(ThreatDetection));
    report->threat_count = count;
    report->total_threats = count;
    
    return 0;
}

/**
 * Generate text-based report
 */
int generate_text_report(SecurityReport *report, const char *output_file) {
    if (!report) return -1;
    
    FILE *fp = fopen(output_file, "w");
    if (!fp) {
        print_threat("Error: Could not create report file\n");
        return -1;
    }
    
    // Header
    fprintf(fp, "═══════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, "  SECURITY ANALYSIS REPORT\n");
    fprintf(fp, "═══════════════════════════════════════════════════════════════════════\n\n");
    
    fprintf(fp, "Report Title: %s\n", report->title);
    
    char time_str[64];
    struct tm *timeinfo = localtime(&report->generated_at);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
    fprintf(fp, "Generated: %s\n", time_str);
    
    fprintf(fp, "Total Logs Analyzed: %d\n", report->total_logs);
    fprintf(fp, "Total Threats Detected: %d\n\n", report->total_threats);
    
    // Executive Summary
    fprintf(fp, "───────────────────────────────────────────────────────────────────────\n");
    fprintf(fp, "  EXECUTIVE SUMMARY\n");
    fprintf(fp, "───────────────────────────────────────────────────────────────────────\n\n");
    
    int critical = 0, high = 0, medium = 0, low = 0;
    for (int i = 0; i < report->threat_count; i++) {
        switch (report->threats[i].severity) {
            case SEVERITY_CRITICAL: critical++; break;
            case SEVERITY_HIGH: high++; break;
            case SEVERITY_MEDIUM: medium++; break;
            case SEVERITY_LOW: low++; break;
            default: break;
        }
    }
    
    fprintf(fp, "Threat Breakdown by Severity:\n");
    fprintf(fp, "  Critical: %d\n", critical);
    fprintf(fp, "  High:     %d\n", high);
    fprintf(fp, "  Medium:   %d\n", medium);
    fprintf(fp, "  Low:      %d\n\n", low);
    
    // Detailed Threats
    fprintf(fp, "───────────────────────────────────────────────────────────────────────\n");
    fprintf(fp, "  DETAILED THREAT ANALYSIS\n");
    fprintf(fp, "───────────────────────────────────────────────────────────────────────\n\n");
    
    for (int i = 0; i < report->threat_count; i++) {
        fprintf(fp, "[%d] %s\n", i + 1, report->threats[i].threat_name);
        fprintf(fp, "    Severity:    ");
        
        switch (report->threats[i].severity) {
            case SEVERITY_CRITICAL: fprintf(fp, "CRITICAL\n"); break;
            case SEVERITY_HIGH: fprintf(fp, "HIGH\n"); break;
            case SEVERITY_MEDIUM: fprintf(fp, "MEDIUM\n"); break;
            case SEVERITY_LOW: fprintf(fp, "LOW\n"); break;
            default: fprintf(fp, "UNKNOWN\n"); break;
        }
        
        fprintf(fp, "    Confidence:  %d%%\n", report->threats[i].confidence);
        fprintf(fp, "    Source IP:   %s\n", report->threats[i].source_ip);
        
        struct tm *t_info = localtime(&report->threats[i].detected_at);
        char t_str[64];
        strftime(t_str, sizeof(t_str), "%Y-%m-%d %H:%M:%S", t_info);
        fprintf(fp, "    Detected:    %s\n", t_str);
        
        fprintf(fp, "    Description: %s\n", report->threats[i].description);
        fprintf(fp, "    Indicators:  %s\n\n", report->threats[i].indicators);
    }
    
    // Recommendations
    fprintf(fp, "───────────────────────────────────────────────────────────────────────\n");
    fprintf(fp, "  RECOMMENDATIONS\n");
    fprintf(fp, "───────────────────────────────────────────────────────────────────────\n\n");
    
    if (critical > 0) {
        fprintf(fp, "⚠️  URGENT: %d critical threats detected. Immediate action required.\n", critical);
        fprintf(fp, "   - Isolate affected systems\n");
        fprintf(fp, "   - Review and block malicious IPs\n");
        fprintf(fp, "   - Conduct forensic analysis\n\n");
    }
    
    if (high > 0) {
        fprintf(fp, "⚠️  %d high-severity threats detected. Prompt investigation needed.\n", high);
        fprintf(fp, "   - Review security policies\n");
        fprintf(fp, "   - Update firewall rules\n");
        fprintf(fp, "   - Monitor affected resources\n\n");
    }
    
    fprintf(fp, "General Recommendations:\n");
    fprintf(fp, "  - Update threat signatures regularly\n");
    fprintf(fp, "  - Enable continuous monitoring\n");
    fprintf(fp, "  - Review and update security policies\n");
    fprintf(fp, "  - Conduct regular security audits\n\n");
    
    // Footer
    fprintf(fp, "═══════════════════════════════════════════════════════════════════════\n");
    fprintf(fp, "  End of Report\n");
    fprintf(fp, "═══════════════════════════════════════════════════════════════════════\n");
    
    fclose(fp);
    
    print_success("Text report generated: ");
    printf("%s\n", output_file);
    return 0;
}

/**
 * Generate JSON report
 */
int generate_json_report(SecurityReport *report, const char *output_file) {
    if (!report) return -1;
    
    FILE *fp = fopen(output_file, "w");
    if (!fp) return -1;
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"title\": \"%s\",\n", report->title);
    fprintf(fp, "  \"generated_at\": %ld,\n", (long)report->generated_at);
    fprintf(fp, "  \"total_logs\": %d,\n", report->total_logs);
    fprintf(fp, "  \"total_threats\": %d,\n", report->total_threats);
    fprintf(fp, "  \"threats\": [\n");
    
    for (int i = 0; i < report->threat_count; i++) {
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"name\": \"%s\",\n", report->threats[i].threat_name);
        fprintf(fp, "      \"description\": \"%s\",\n", report->threats[i].description);
        fprintf(fp, "      \"severity\": %d,\n", report->threats[i].severity);
        fprintf(fp, "      \"source_ip\": \"%s\",\n", report->threats[i].source_ip);
        fprintf(fp, "      \"confidence\": %d,\n", report->threats[i].confidence);
        fprintf(fp, "      \"detected_at\": %ld,\n", (long)report->threats[i].detected_at);
        fprintf(fp, "      \"indicators\": \"%s\"\n", report->threats[i].indicators);
        fprintf(fp, "    }%s\n", (i < report->threat_count - 1) ? "," : "");
    }
    
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");
    
    fclose(fp);
    
    print_success("JSON report generated: ");
    printf("%s\n", output_file);
    return 0;
}

/**
 * Generate CSV report
 */
int generate_csv_report(SecurityReport *report, const char *output_file) {
    if (!report) return -1;
    
    FILE *fp = fopen(output_file, "w");
    if (!fp) return -1;
    
    fprintf(fp, "Threat Name,Description,Severity,Source IP,Confidence,Timestamp,Indicators\n");
    
    for (int i = 0; i < report->threat_count; i++) {
        fprintf(fp, "\"%s\",\"%s\",%d,\"%s\",%d,%ld,\"%s\"\n",
                report->threats[i].threat_name,
                report->threats[i].description,
                report->threats[i].severity,
                report->threats[i].source_ip,
                report->threats[i].confidence,
                (long)report->threats[i].detected_at,
                report->threats[i].indicators);
    }
    
    fclose(fp);
    
    print_success("CSV report generated: ");
    printf("%s\n", output_file);
    return 0;
}

/**
 * Main report generation function
 */
int generate_report(SecurityReport *report, ReportFormat format, const char *output_file) {
    if (!report) return -1;
    
    switch (format) {
        case REPORT_FORMAT_TEXT:
            return generate_text_report(report, output_file);
        case REPORT_FORMAT_JSON:
            return generate_json_report(report, output_file);
        case REPORT_FORMAT_CSV:
            return generate_csv_report(report, output_file);
        case REPORT_FORMAT_HTML:
            print_warning("HTML report format not yet implemented\n");
            return -1;
        default:
            return -1;
    }
}

/**
 * Print executive summary to console
 */
void print_executive_summary(SecurityReport *report) {
    if (!report) return;
    
    print_info("\n═══════════════════════════════════════════\n");
    print_info(" EXECUTIVE SUMMARY\n");
    print_info("═══════════════════════════════════════════\n\n");
    
    printf("Total Logs Analyzed: %d\n", report->total_logs);
    printf("Total Threats: %d\n\n", report->total_threats);
    
    int critical = 0, high = 0, medium = 0, low = 0;
    for (int i = 0; i < report->threat_count; i++) {
        switch (report->threats[i].severity) {
            case SEVERITY_CRITICAL: critical++; break;
            case SEVERITY_HIGH: high++; break;
            case SEVERITY_MEDIUM: medium++; break;
            case SEVERITY_LOW: low++; break;
            default: break;
        }
    }
    
    printf("Threat Breakdown:\n");
    if (critical > 0) {
        print_threat("  Critical: ");
        printf("%d\n", critical);
    }
    if (high > 0) {
        printf("%s  High:     %s%d\n", ANSI_RED, ANSI_RESET, high);
    }
    if (medium > 0) {
        printf("%s  Medium:   %s%d\n", ANSI_YELLOW, ANSI_RESET, medium);
    }
    if (low > 0) {
        printf("%s  Low:      %s%d\n", ANSI_CYAN, ANSI_RESET, low);
    }
    printf("\n");
}

/**
 * Print statistics
 */
void print_statistics(const AnalysisStats *stats) {
    if (!stats) return;
    
    print_info("Analysis Statistics:\n");
    printf("  Total logs analyzed: %d\n", stats->total_logs_analyzed);
    printf("  Threats detected: %d\n", stats->threats_detected);
    printf("  Anomalies found: %d\n", stats->anomalies_found);
    printf("  Analysis time: %.2f seconds\n", stats->analysis_time_sec);
    
    if (stats->packet_rate_avg > 0) {
        printf("  Average packet rate: %d/sec\n", stats->packet_rate_avg);
        printf("  Max packet rate: %d/sec\n", stats->packet_rate_max);
    }
    printf("\n");
}
