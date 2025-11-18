#include "analyzer.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

// Threat signature database
typedef struct {
    char name[128];
    char pattern[256];
    char description[512];
    ThreatSeverity severity;
    int confidence;
} ThreatSignature;

static ThreatSignature g_signatures[256];
static int g_signature_count = 0;

// Statistical baseline for anomaly detection
typedef struct {
    double avg_packet_rate;
    double stddev_packet_rate;
    int baseline_samples;
    time_t last_update;
} BaselineStats;

static BaselineStats g_baseline = {0};

/**
 * Load threat signatures from file
 */
int load_threat_signatures(const char *signature_file) {
    FILE *fp = fopen(signature_file, "r");
    if (!fp) {
        print_warning("Warning: Could not load signatures from file. Using defaults.\n");
        
        // Load default hardcoded signatures
        strcpy(g_signatures[0].name, "SSH Brute Force");
        strcpy(g_signatures[0].pattern, "Failed password");
        strcpy(g_signatures[0].description, "Multiple failed SSH authentication attempts");
        g_signatures[0].severity = SEVERITY_HIGH;
        g_signatures[0].confidence = 85;
        
        strcpy(g_signatures[1].name, "SQL Injection Attempt");
        strcpy(g_signatures[1].pattern, "' OR '1'='1");
        strcpy(g_signatures[1].description, "Potential SQL injection in request");
        g_signatures[1].severity = SEVERITY_CRITICAL;
        g_signatures[1].confidence = 90;
        
        strcpy(g_signatures[2].name, "Port Scan");
        strcpy(g_signatures[2].pattern, "SYN_SCAN");
        strcpy(g_signatures[2].description, "Network port scanning detected");
        g_signatures[2].severity = SEVERITY_MEDIUM;
        g_signatures[2].confidence = 75;
        
        strcpy(g_signatures[3].name, "Unauthorized Access");
        strcpy(g_signatures[3].pattern, "Access denied");
        strcpy(g_signatures[3].description, "Unauthorized access attempt");
        g_signatures[3].severity = SEVERITY_HIGH;
        g_signatures[3].confidence = 80;
        
        strcpy(g_signatures[4].name, "Malware Communication");
        strcpy(g_signatures[4].pattern, "C2_SERVER");
        strcpy(g_signatures[4].description, "Communication with known C2 server");
        g_signatures[4].severity = SEVERITY_CRITICAL;
        g_signatures[4].confidence = 95;
        
        g_signature_count = 5;
        print_info("Loaded ");
        printf("%d default signatures\n", g_signature_count);
        return 0;
    }
    
    char line[1024];
    g_signature_count = 0;
    
    while (fgets(line, sizeof(line), fp) && g_signature_count < 256) {
        if (line[0] == '#' || line[0] == '\n') continue;
        
        char *name = strtok(line, "|");
        char *pattern = strtok(NULL, "|");
        char *desc = strtok(NULL, "|");
        char *sev = strtok(NULL, "|");
        char *conf = strtok(NULL, "|\n");
        
        if (name && pattern && desc && sev && conf) {
            strncpy(g_signatures[g_signature_count].name, name, 127);
            strncpy(g_signatures[g_signature_count].pattern, pattern, 255);
            strncpy(g_signatures[g_signature_count].description, desc, 511);
            g_signatures[g_signature_count].severity = atoi(sev);
            g_signatures[g_signature_count].confidence = atoi(conf);
            g_signature_count++;
        }
    }
    
    fclose(fp);
    print_success("Loaded ");
    printf("%d signatures from file\n", g_signature_count);
    return 0;
}

int match_signature(const NormalizedLog *log) {
    if (!log) return -1;
    
    for (int i = 0; i < g_signature_count; i++) {
        if (strstr(log->raw_message, g_signatures[i].pattern) ||
            strstr(log->event_type, g_signatures[i].pattern)) {
            return i;
        }
    }
    return -1;
}

int analyze_with_signatures(NormalizedLog *logs, int count, ThreatDetection *threats, int max_threats) {
    if (!logs || !threats || count <= 0) return 0;
    
    int threat_count = 0;
    for (int i = 0; i < count && threat_count < max_threats; i++) {
        int sig_index = match_signature(&logs[i]);
        
        if (sig_index >= 0) {
            ThreatSignature *sig = &g_signatures[sig_index];
            strncpy(threats[threat_count].threat_name, sig->name, 127);
            strncpy(threats[threat_count].description, sig->description, 511);
            threats[threat_count].severity = sig->severity;
            threats[threat_count].detected_at = logs[i].timestamp;
            strncpy(threats[threat_count].source_ip, logs[i].source_ip, 45);
            snprintf(threats[threat_count].indicators, 255, "Matched pattern: %s", sig->pattern);
            threats[threat_count].confidence = sig->confidence;
            threat_count++;
        }
    }
    return threat_count;
}

int calculate_baseline_stats(NormalizedLog *logs, int count) {
    if (!logs || count < 2) return -1;
    
    time_t start_time = logs[0].timestamp;
    time_t end_time = logs[count - 1].timestamp;
    if (end_time <= start_time) return -1;
    
    double duration = difftime(end_time, start_time);
    if (duration <= 0) duration = 1.0;
    
    g_baseline.avg_packet_rate = count / duration;
    
    double sum_squared_diff = 0.0;
    for (int i = 0; i < count - 1; i++) {
        double interval = difftime(logs[i + 1].timestamp, logs[i].timestamp);
        if (interval > 0) {
            double rate = 1.0 / interval;
            double diff = rate - g_baseline.avg_packet_rate;
            sum_squared_diff += diff * diff;
        }
    }
    
    g_baseline.stddev_packet_rate = sqrt(sum_squared_diff / count);
    g_baseline.baseline_samples = count;
    g_baseline.last_update = time(NULL);
    
    print_info("Baseline established: Avg rate = ");
    printf("%.2f packets/sec, StdDev = %.2f\n", 
           g_baseline.avg_packet_rate, g_baseline.stddev_packet_rate);
    
    return 0;
}

int detect_statistical_anomaly(const NormalizedLog *log) {
    (void)log;
    if (g_baseline.baseline_samples < 10) return 0;
    return 0;
}

int analyze_with_anomaly_detection(NormalizedLog *logs, int count, ThreatDetection *threats, int max_threats) {
    if (!logs || !threats || count <= 0) return 0;
    
    calculate_baseline_stats(logs, count);
    
    int threat_count = 0;
    int threshold = g_config.analysis_threshold;
    
    for (int i = 0; i < count - threshold && threat_count < max_threats; i++) {
        int same_ip_count = 1;
        for (int j = i + 1; j < i + 10 && j < count; j++) {
            if (strcmp(logs[i].source_ip, logs[j].source_ip) == 0) {
                same_ip_count++;
            }
        }
        
        if (same_ip_count >= threshold) {
            strncpy(threats[threat_count].threat_name, "Anomalous Activity Rate", 127);
            snprintf(threats[threat_count].description, 511,
                    "Detected %d events in rapid succession from same IP", same_ip_count);
            threats[threat_count].severity = SEVERITY_MEDIUM;
            threats[threat_count].detected_at = logs[i].timestamp;
            strncpy(threats[threat_count].source_ip, logs[i].source_ip, 45);
            snprintf(threats[threat_count].indicators, 255, 
                    "Event rate: %d in 10-event window", same_ip_count);
            threats[threat_count].confidence = 70;
            threat_count++;
        }
    }
    
    return threat_count;
}

int analyze_with_ttp_correlation(NormalizedLog *logs, int count, ThreatDetection *threats, int max_threats) {
    if (!logs || !threats || count <= 0) return 0;
    
    int threat_count = 0;
    
    for (int i = 0; i < count - 5 && threat_count < max_threats; i++) {
        int scan_detected = 0;
        int connection_attempts = 0;
        char attack_ip[46] = {0};
        
        for (int j = i; j < i + 20 && j < count; j++) {
            if (strstr(logs[j].event_type, "scan") || 
                strstr(logs[j].event_type, "probe")) {
                scan_detected = 1;
                strncpy(attack_ip, logs[j].source_ip, 45);
            }
            
            if (scan_detected && strcmp(logs[j].source_ip, attack_ip) == 0) {
                if (strstr(logs[j].event_type, "connection") ||
                    strstr(logs[j].event_type, "attempt")) {
                    connection_attempts++;
                }
            }
        }
        
        if (scan_detected && connection_attempts >= 3) {
            strncpy(threats[threat_count].threat_name, "Multi-Stage Attack Pattern", 127);
            snprintf(threats[threat_count].description, 511,
                    "Port scan followed by %d connection attempts", connection_attempts);
            threats[threat_count].severity = SEVERITY_HIGH;
            threats[threat_count].detected_at = logs[i].timestamp;
            strncpy(threats[threat_count].source_ip, attack_ip, 45);
            strcpy(threats[threat_count].indicators, "Reconnaissance -> Exploitation pattern");
            threats[threat_count].confidence = 85;
            threat_count++;
        }
    }
    
    return threat_count;
}

int analyze_logs_from_buffer(NormalizedLog *logs, int count, int mode) {
    if (!logs || count <= 0) return -1;
    
    ThreatDetection threats[512];
    int total_threats = 0;
    
    print_info("Starting analysis on ");
    printf("%d log entries...\n", count);
    
    if (mode & ANALYSIS_SIGNATURE) {
        print_info("Running signature-based detection...\n");
        load_threat_signatures(g_config.signatures_path);
        int sig_threats = analyze_with_signatures(logs, count, 
                                                  threats + total_threats, 
                                                  512 - total_threats);
        print_success("Signature detection: ");
        printf("%d threats found\n", sig_threats);
        total_threats += sig_threats;
    }
    
    if (mode & ANALYSIS_ANOMALY) {
        print_info("Running anomaly detection...\n");
        int anomaly_threats = analyze_with_anomaly_detection(logs, count,
                                                             threats + total_threats,
                                                             512 - total_threats);
        print_success("Anomaly detection: ");
        printf("%d threats found\n", anomaly_threats);
        total_threats += anomaly_threats;
    }
    
    if (mode & ANALYSIS_TTP) {
        print_info("Running TTP correlation...\n");
        int ttp_threats = analyze_with_ttp_correlation(logs, count,
                                                       threats + total_threats,
                                                       512 - total_threats);
        print_success("TTP correlation: ");
        printf("%d threats found\n", ttp_threats);
        total_threats += ttp_threats;
    }
    
    printf("\n");
    print_threat("═══════════════════════════════════════════\n");
    print_threat(" THREAT ANALYSIS SUMMARY\n");
    print_threat("═══════════════════════════════════════════\n");
    printf("Total Threats Detected: %d\n\n", total_threats);
    
    print_threat_summary(threats, total_threats);
    
    if (total_threats > 0) {
        export_threats_to_json(threats, total_threats, "threats.json");
        export_threats_to_csv(threats, total_threats, "threats.csv");
    }
    
    return total_threats;
}

void print_threat_summary(ThreatDetection *threats, int count) {
    for (int i = 0; i < count; i++) {
        const char *sev_color = ANSI_RESET;
        
        switch (threats[i].severity) {
            case SEVERITY_CRITICAL: sev_color = ANSI_RED; break;
            case SEVERITY_HIGH: sev_color = ANSI_RED; break;
            case SEVERITY_MEDIUM: sev_color = ANSI_YELLOW; break;
            case SEVERITY_LOW: sev_color = ANSI_CYAN; break;
            default: sev_color = ANSI_RESET; break;
        }
        
        printf("%s[%d] %s%s\n", sev_color, i + 1, threats[i].threat_name, ANSI_RESET);
        printf("    Source: %s\n", threats[i].source_ip);
        printf("    Severity: %d | Confidence: %d%%\n", 
               threats[i].severity, threats[i].confidence);
        printf("    %s\n", threats[i].description);
        printf("    Indicators: %s\n\n", threats[i].indicators);
    }
}

int export_threats_to_json(ThreatDetection *threats, int count, const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) return -1;
    
    fprintf(fp, "{\n  \"threats\": [\n");
    
    for (int i = 0; i < count; i++) {
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"name\": \"%s\",\n", threats[i].threat_name);
        fprintf(fp, "      \"description\": \"%s\",\n", threats[i].description);
        fprintf(fp, "      \"severity\": %d,\n", threats[i].severity);
        fprintf(fp, "      \"source_ip\": \"%s\",\n", threats[i].source_ip);
        fprintf(fp, "      \"confidence\": %d,\n", threats[i].confidence);
        fprintf(fp, "      \"timestamp\": %ld,\n", (long)threats[i].detected_at);
        fprintf(fp, "      \"indicators\": \"%s\"\n", threats[i].indicators);
        fprintf(fp, "    }%s\n", (i < count - 1) ? "," : "");
    }
    
    fprintf(fp, "  ]\n}\n");
    fclose(fp);
    
    print_success("Threats exported to ");
    printf("%s\n", filename);
    return 0;
}

int export_threats_to_csv(ThreatDetection *threats, int count, const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) return -1;
    
    fprintf(fp, "Name,Description,Severity,Source IP,Confidence,Timestamp,Indicators\n");
    
    for (int i = 0; i < count; i++) {
        fprintf(fp, "\"%s\",\"%s\",%d,\"%s\",%d,%ld,\"%s\"\n",
                threats[i].threat_name, threats[i].description,
                threats[i].severity, threats[i].source_ip,
                threats[i].confidence, (long)threats[i].detected_at,
                threats[i].indicators);
    }
    
    fclose(fp);
    print_success("Threats exported to ");
    printf("%s\n", filename);
    return 0;
}

int analyze_logs(const char *database_path) {
    (void)database_path;
    print_warning("Note: analyze_logs() requires buffer-based analysis. Use analyze_logs_from_buffer()\n");
    return 0;
}

int search_logs(const char *database_path, const char *query) {
    (void)database_path;
    (void)query;
    print_warning("Note: search_logs() requires implementation\n");
    return 0;
}

int detect_threats(const char *database_path) {
    (void)database_path;
    print_warning("Note: detect_threats() requires implementation\n");
    return 0;
}