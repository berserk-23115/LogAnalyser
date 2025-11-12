#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include "help.h"

void list_devices() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return;
    }
    printf("Available devices:\n");
    for (pcap_if_t *d = alldevs; d; d = d->next) {
        printf("  %s: %s\n", d->name, d->description ? d->description : "No description");
    }
    pcap_freealldevs(alldevs);
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        print_help();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--devices") == 0) {
        list_devices();
        return 0;
    }
    printf("Welcome to Log Analyser!\n");
    return 0;   
    
    
}