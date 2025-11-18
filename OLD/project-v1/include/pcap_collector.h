#ifndef PCAP_COLLECTOR_H
#define PCAP_COLLECTOR_H

#include "parser.h"

// Packet buffer for offline analysis
typedef struct {
    NormalizedLog *logs;
    int capacity;
    int count;
    int head;
    int tail;
} PacketBuffer;

// Buffer management functions
PacketBuffer* create_packet_buffer(int capacity);
void free_packet_buffer(PacketBuffer *buffer);
int add_to_buffer(PacketBuffer *buffer, const NormalizedLog *log);
int get_buffer_logs(PacketBuffer *buffer, NormalizedLog *output, int max_count);
void clear_buffer(PacketBuffer *buffer);
int buffer_is_full(const PacketBuffer *buffer);

// Capture functions
int start_capture(const char *interface);
int start_capture_to_buffer(const char *interface, int packet_count, PacketBuffer *buffer);
int read_pcap_file(const char *filename, PacketBuffer *buffer);

// Syslog UDP listener
int start_syslog_listener(int port, PacketBuffer *buffer);

// Device management
void list_devices(void);

// Global buffer for offline operation
extern PacketBuffer *g_packet_buffer;

#endif