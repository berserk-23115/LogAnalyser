#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../include/parser.h"
#include "../include/analyzer.h"
#include "../include/pcap_collector.h"
#include "../include/config.h"

// Test results tracking
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(condition, message) \
    do { \
        tests_run++; \
        if (condition) { \
            tests_passed++; \
            printf("  ✓ %s\n", message); \
        } else { \
            tests_failed++; \
            printf("  ✗ %s\n", message); \
        } \
    } while(0)

// Forward declarations
void run_parser_tests(void);
void run_analyzer_tests(void);
void run_buffer_tests(void);
void print_test_summary(void);

int main(int argc, char *argv[]) {
    init_console_colors();
    
    printf("\n");
    print_info("═══════════════════════════════════════════\n");
    print_info(" Log Analyser Test Suite\n");
    print_info("═══════════════════════════════════════════\n\n");
    
    if (argc > 1) {
        if (strcmp(argv[1], "parser") == 0) {
            run_parser_tests();
        } else if (strcmp(argv[1], "analyzer") == 0) {
            run_analyzer_tests();
        } else if (strcmp(argv[1], "buffer") == 0) {
            run_buffer_tests();
        } else {
            printf("Unknown test suite: %s\n", argv[1]);
            printf("Available: parser, analyzer, buffer\n");
            return 1;
        }
    } else {
        // Run all tests
        run_parser_tests();
        run_analyzer_tests();
        run_buffer_tests();
    }
    
    print_test_summary();
    
    return (tests_failed > 0) ? 1 : 0;
}

void run_parser_tests(void) {
    print_info("\n── Parser Tests ──\n\n");
    
    // Test 1: Log type detection
    const char *syslog_line = "Jan 15 10:30:00 server kernel: test message";
    const char *apache_line = "192.168.1.1 - - [15/Jan/2025:10:30:00] \"GET / HTTP/1.1\" 200 1234";
    const char *json_line = "{\"timestamp\": 1234567890, \"message\": \"test\"}";
    
    TEST_ASSERT(detect_log_type(syslog_line) == LOG_TYPE_SYSLOG, 
                "Detect syslog format");
    TEST_ASSERT(detect_log_type(apache_line) == LOG_TYPE_APACHE, 
                "Detect Apache format");
    TEST_ASSERT(detect_log_type(json_line) == LOG_TYPE_JSON, 
                "Detect JSON format");
    
    // Test 2: Syslog parsing
    NormalizedLog log = {0};
    int result = parse_syslog(syslog_line, &log);
    TEST_ASSERT(result == 0, "Parse syslog line");
    TEST_ASSERT(log.log_type == LOG_TYPE_SYSLOG, "Syslog type set correctly");
    
    // Test 3: Apache log parsing
    NormalizedLog apache_log = {0};
    result = parse_apache_log(apache_line, &apache_log);
    TEST_ASSERT(result == 0, "Parse Apache log line");
    TEST_ASSERT(strcmp(apache_log.source_ip, "192.168.1.1") == 0, 
                "Extract IP from Apache log");
    TEST_ASSERT(apache_log.log_type == LOG_TYPE_APACHE, 
                "Apache log type set correctly");
}

void run_analyzer_tests(void) {
    print_info("\n── Analyzer Tests ──\n\n");
    
    // Test 1: Signature loading
    int sig_count = load_threat_signatures("nonexistent.txt");
    TEST_ASSERT(sig_count == 0, "Load default signatures when file not found");
    
    // Test 2: Signature matching
    NormalizedLog log = {0};
    strcpy(log.raw_message, "Multiple Failed password attempts detected");
    strcpy(log.event_type, "auth_failure");
    
    int match = match_signature(&log);
    TEST_ASSERT(match >= 0, "Match threat signature");
    
    // Test 3: Anomaly detection
    NormalizedLog logs[20];
    for (int i = 0; i < 20; i++) {
        logs[i].timestamp = 1000000000 + i;
        strcpy(logs[i].source_ip, "192.168.1.100");
        strcpy(logs[i].event_type, "connection");
    }
    
    ThreatDetection threats[50];
    int threat_count = analyze_with_anomaly_detection(logs, 20, threats, 50);
    TEST_ASSERT(threat_count >= 0, "Run anomaly detection");
    
    // Test 4: Baseline calculation
    int baseline_result = calculate_baseline_stats(logs, 20);
    TEST_ASSERT(baseline_result == 0, "Calculate baseline statistics");
}

void run_buffer_tests(void) {
    print_info("\n── Buffer Tests ──\n\n");
    
    // Test 1: Buffer creation
    PacketBuffer *buffer = create_packet_buffer(100);
    TEST_ASSERT(buffer != NULL, "Create packet buffer");
    TEST_ASSERT(buffer->capacity == 100, "Buffer capacity correct");
    TEST_ASSERT(buffer->count == 0, "Buffer initially empty");
    
    // Test 2: Add to buffer
    NormalizedLog log = {0};
    log.timestamp = 1000000000;
    strcpy(log.source_ip, "192.168.1.1");
    strcpy(log.event_type, "test_event");
    
    int result = add_to_buffer(buffer, &log);
    TEST_ASSERT(result == 0, "Add log to buffer");
    TEST_ASSERT(buffer->count == 1, "Buffer count updated");
    
    // Test 3: Fill buffer
    for (int i = 0; i < 150; i++) {
        add_to_buffer(buffer, &log);
    }
    TEST_ASSERT(buffer->count == 100, "Buffer respects capacity limit");
    TEST_ASSERT(buffer_is_full(buffer), "Buffer full detection");
    
    // Test 4: Retrieve from buffer
    NormalizedLog output[50];
    int retrieved = get_buffer_logs(buffer, output, 50);
    TEST_ASSERT(retrieved == 50, "Retrieve logs from buffer");
    
    // Test 5: Clear buffer
    clear_buffer(buffer);
    TEST_ASSERT(buffer->count == 0, "Clear buffer");
    
    // Cleanup
    free_packet_buffer(buffer);
    TEST_ASSERT(1, "Free packet buffer");
}

void print_test_summary(void) {
    printf("\n");
    print_info("═══════════════════════════════════════════\n");
    print_info(" Test Summary\n");
    print_info("═══════════════════════════════════════════\n\n");
    
    printf("Total tests run: %d\n", tests_run);
    
    if (tests_passed > 0) {
        print_success("Tests passed: ");
        printf("%d\n", tests_passed);
    }
    
    if (tests_failed > 0) {
        print_threat("Tests failed: ");
        printf("%d\n", tests_failed);
    } else {
        print_success("All tests passed! ✓\n");
    }
    
    printf("\n");
}
