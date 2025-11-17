#ifndef RULES_H
#define RULES_H

#include "parser.h"

// Struct for a single detection rule
typedef struct {
    char *name;         // Name of the threat/event (e.g., "SSH Brute Force")
    char *pattern;      // The REGEX pattern to match
    char *severity;     // The severity to assign (e.g., "HIGH")
} DetectionRule;

/**
 * @brief Classifies a log entry based on a set of regex rules.
 * * This function iterates through a predefined list of rules and checks
 * if the log's raw_message matches any rule's pattern.
 * * If a match is found, it updates log->event_type and log->severity
 * with the values from the rule.
 * * @param log A pointer to the NormalizedLog struct to classify.
 */
void classify_log(NormalizedLog *log);

#endif