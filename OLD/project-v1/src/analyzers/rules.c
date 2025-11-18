#include <stdio.h>
#include <string.h>
#include <regex.h>
#include "rules.h"

// Define our list of detection rules
// You can add as many rules as you want here!
DetectionRule rules[] = {
    {
        "SSH Login Failure",
        "Failed password for", // Simple string match
        "MEDIUM"
    },
    {
        "SSH Brute Force",
        "Failed password for .* from ([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+) port [0-9]+ ssh2", // Regex match
        "HIGH"
    },
    {
        "Apache 404 Error",
        "\" 404 [0-9]+", // Matches the 404 status code in an Apache log
        "LOW"
    },
    {
        "SQL Injection Attempt",
        "(union|select|insert|delete|from|where|' or '1'='1)", // Common SQLi keywords
        "CRITICAL"
    }
};
int num_rules = sizeof(rules) / sizeof(rules[0]);

// Function to check a single log against all rules
void classify_log(NormalizedLog *log) {
    regex_t regex;
    int reti;

    for (int i = 0; i < num_rules; i++) {
        // Compile the regex
        reti = regcomp(&regex, rules[i].pattern, REG_EXTENDED | REG_ICASE);
        if (reti) {
            fprintf(stderr, "Could not compile regex: %s\n", rules[i].pattern);
            continue;
        }

        // Execute the regex against the raw message
        reti = regexec(&regex, log->raw_message, 0, NULL, 0);
        
        if (reti == 0) {
            // A match was found!
            // Update the log entry with the rule's info
            strcpy(log->event_type, rules[i].name);
            strcpy(log->severity, rules[i].severity);
            
            // Free the compiled regex and stop checking
            regfree(&regex);
            return; // We found our classification, so we're done
        }
        
        regfree(&regex);
    }
    
    // If no rules matched, the log keeps its original event_type and severity
}