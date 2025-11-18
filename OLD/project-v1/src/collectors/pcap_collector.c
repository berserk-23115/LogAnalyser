#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>

// --- New Headers for Parsing ---
#include <netinet/if_ether.h> // For struct ether_header, ETHERTYPE_IP
#include <netinet/ip.h>       // For struct ip
#include <netinet/tcp.h>      // For struct tcphdr
#include <netinet/udp.h>      // For struct udphdr
#include <arpa/inet.h>        // For inet_ntop() and ntohs()

// --- Your Project Headers ---
#include "pcap_collector.h"
#include "parser.h"           // So we can use NormalizedLog
#include "rules.h"
#include "config.h"

#define SNAP_LEN 1518 // Standard Ethernet MTU

// Global packet buffer for offline operation
PacketBuffer *g_packet_buffer = NULL;

// Context for packet handler
typedef struct {
    PacketBuffer *buffer;
    int *packet_count;
    int max_packets;
} CaptureContext;

/**
 * Create a new packet buffer
 */
PacketBuffer* create_packet_buffer(int capacity) {
    PacketBuffer *buffer = (PacketBuffer*)malloc(sizeof(PacketBuffer));
    if (!buffer) return NULL;
    
    buffer->logs = (NormalizedLog*)calloc(capacity, sizeof(NormalizedLog));
    if (!buffer->logs) {
        free(buffer);
        return NULL;
    }
    
    buffer->capacity = capacity;
    buffer->count = 0;
    buffer->head = 0;
    buffer->tail = 0;
    
    return buffer;
}

/**
 * Free packet buffer
 */
void free_packet_buffer(PacketBuffer *buffer) {
    if (!buffer) return;
    if (buffer->logs) free(buffer->logs);
    free(buffer);
}

/**
 * Add log to buffer (circular buffer)
 */
int add_to_buffer(PacketBuffer *buffer, const NormalizedLog *log) {
    if (!buffer || !log) return -1;
    
    buffer->logs[buffer->tail] = *log;
    buffer->tail = (buffer->tail + 1) % buffer->capacity;
    
    if (buffer->count < buffer->capacity) {
        buffer->count++;
    } else {
        // Buffer is full, move head forward
        buffer->head = (buffer->head + 1) % buffer->capacity;
    }
    
    return 0;
}

/**
 * Get logs from buffer
 */
int get_buffer_logs(PacketBuffer *buffer, NormalizedLog *output, int max_count) {
    if (!buffer || !output) return 0;
    
    int count = (buffer->count < max_count) ? buffer->count : max_count;
    int index = buffer->head;
    
    for (int i = 0; i < count; i++) {
        output[i] = buffer->logs[index];
        index = (index + 1) % buffer->capacity;
    }
    
    return count;
}

/**
 * Clear buffer
 */
void clear_buffer(PacketBuffer *buffer) {
    if (!buffer) return;
    buffer->count = 0;
    buffer->head = 0;
    buffer->tail = 0;
}

/**
 * Check if buffer is full
 */
int buffer_is_full(const PacketBuffer *buffer) {
    if (!buffer) return 0;
    return buffer->count >= buffer->capacity;
}

/**
 * @brief This is the core packet parsing function.
 * pcap_loop calls this for every packet captured.
 */
void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
    CaptureContext *ctx = (CaptureContext*)user_data;
    
    // Create a log entry, clear it to zeros
    NormalizedLog log = {0};
    log.timestamp = header->ts.tv_sec; // Set timestamp
    log.log_type = LOG_TYPE_UNKNOWN; // We can change this later

    // --- 1. Parse Ethernet Header ---
    const struct ether_header *eth_header = (struct ether_header *)packet;

    // Check if it's an IP packet. We only care about IP.
    // ntohs() = Network to Host Short (converts byte order)
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return; // Not an IP packet, ignore it
    }

    // --- 2. Parse IP Header ---
    // The IP header starts right after the Ethernet header
    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    
    // Calculate the IP header length (it can vary!)
    // ip_hl is in 4-byte words, so multiply by 4
    int ip_header_len = ip_header->ip_hl * 4;

    // Convert the source and destination IP addresses to strings
    inet_ntop(AF_INET, &(ip_header->ip_src), log.source_ip, sizeof(log.source_ip));
    inet_ntop(AF_INET, &(ip_header->ip_dst), log.dest_ip, sizeof(log.dest_ip));

    // --- 3. Parse Transport Layer (TCP/UDP) ---
    
    // Find the start of the transport header
    const u_char *transport_header = packet + sizeof(struct ether_header) + ip_header_len;

    int source_port = 0;
    int dest_port = 0;

    // Check the protocol number from the IP header
    switch (ip_header->ip_p) {
        
        case IPPROTO_TCP: {
            // It's a TCP packet
            const struct tcphdr *tcp_header = (struct tcphdr *)transport_header;
            source_port = ntohs(tcp_header->th_sport);
            dest_port = ntohs(tcp_header->th_dport);

            // --- 4. Create Meaningful Logs ---
            if (dest_port == 22 || source_port == 22) {
                strcpy(log.event_type, "ssh_attempt");
                strcpy(log.severity, "WARN");
            } else if (dest_port == 80 || dest_port == 443 || source_port == 80 || source_port == 443) {
                strcpy(log.event_type, "http_traffic");
                strcpy(log.severity, "INFO");
            } else {
                strcpy(log.event_type, "tcp_connection");
                strcpy(log.severity, "INFO");
            }

            snprintf(log.raw_message, sizeof(log.raw_message),
                     "TCP Packet: %s:%d -> %s:%d",
                     log.source_ip, source_port, log.dest_ip, dest_port);
            break;
        }

        case IPPROTO_UDP: {
            // It's a UDP packet
            const struct udphdr *udp_header = (struct udphdr *)transport_header;
            source_port = ntohs(udp_header->uh_sport);
            dest_port = ntohs(udp_header->uh_dport);

            if (dest_port == 53 || source_port == 53) {
                strcpy(log.event_type, "dns_query");
                strcpy(log.severity, "INFO");
            } else {
                strcpy(log.event_type, "udp_traffic");
                strcpy(log.severity, "INFO");
            }

            snprintf(log.raw_message, sizeof(log.raw_message),
                     "UDP Packet: %s:%d -> %s:%d",
                     log.source_ip, source_port, log.dest_ip, dest_port);
            break;
        }

        case IPPROTO_ICMP: {
            // It's an ICMP packet (like "ping")
            strcpy(log.event_type, "icmp_traffic");
            strcpy(log.severity, "INFO");
            snprintf(log.raw_message, sizeof(log.raw_message),
                     "ICMP Packet: %s -> %s", log.source_ip, log.dest_ip);
            break;
        }

        default:
            // Other protocol
            strcpy(log.event_type, "other_ip_traffic");
            strcpy(log.severity, "LOW");
            snprintf(log.raw_message, sizeof(log.raw_message),
                     "IP Packet (Proto: %d): %s -> %s",
                     ip_header->ip_p, log.source_ip, log.dest_ip);
            break;
    }

    classify_log(&log);
    
    // Add to buffer if available
    if (ctx && ctx->buffer) {
        add_to_buffer(ctx->buffer, &log);
        if (ctx->packet_count) {
            (*ctx->packet_count)++;
            if (ctx->max_packets > 0 && *ctx->packet_count >= ctx->max_packets) {
                // Stop capture after reaching limit
                return;
            }
        }
    }

    // Display the log on terminal with timestamp
    time_t now = log.timestamp;
    struct tm *timeinfo = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
    
    // Print with color based on severity
    if (strcmp(log.severity, "CRITICAL") == 0) {
        print_threat("[");
        printf("%s] [%s] ", time_str, log.severity);
    } else if (strcmp(log.severity, "HIGH") == 0) {
        printf("%s[%s] [%s] ", ANSI_RED, time_str, log.severity);
    } else if (strcmp(log.severity, "WARN") == 0 || strcmp(log.severity, "MEDIUM") == 0) {
        printf("%s[%s] [%s] ", ANSI_YELLOW, time_str, log.severity);
    } else if (strcmp(log.severity, "INFO") == 0) {
        printf("%s[%s] [%s] ", ANSI_GREEN, time_str, log.severity);
    } else {
        printf("[%s] [%s] ", time_str, log.severity);
    }
    
    printf("%s -> %s: %s: %s%s\n", 
           log.source_ip,
           log.dest_ip,
           log.event_type,
           log.raw_message,
           ANSI_RESET);
}

/**
 * @brief Starts the live packet capture session.
 */
int start_capture(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    print_info("Starting capture on device: ");
    printf("%s\n", interface);

    handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        print_threat("Could not open device: ");
        printf("%s - %s\n", interface, errbuf);
        return 2;
    }

    // Initialize context with no buffer (live mode)
    CaptureContext ctx = {0};
    
    print_success("Capture started. Press Ctrl+C to stop.\n\n");
    
    // Start the loop. It will call packet_handler() for every packet.
    // -1 means loop forever.
    pcap_loop(handle, -1, packet_handler, (u_char*)&ctx);

    pcap_close(handle);
    return 0;
}

/**
 * @brief Capture packets to buffer for offline analysis
 */
int start_capture_to_buffer(const char *interface, int packet_count, PacketBuffer *buffer) {
    if (!buffer) return -1;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    print_info("Starting buffered capture on device: ");
    printf("%s (limit: %d packets)\n", interface, packet_count);

    handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        print_threat("Could not open device: ");
        printf("%s - %s\n", interface, errbuf);
        return 2;
    }

    int captured = 0;
    CaptureContext ctx = {
        .buffer = buffer,
        .packet_count = &captured,
        .max_packets = packet_count
    };
    
    print_success("Buffered capture started.\n\n");
    
    // Capture specified number of packets
    pcap_loop(handle, packet_count, packet_handler, (u_char*)&ctx);

    pcap_close(handle);
    
    print_success("Capture complete. ");
    printf("Captured %d packets to buffer.\n", captured);
    
    return 0;
}

/**
 * @brief Read PCAP file and populate buffer
 */
int read_pcap_file(const char *filename, PacketBuffer *buffer) {
    if (!buffer || !filename) return -1;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    print_info("Reading PCAP file: ");
    printf("%s\n", filename);
    
    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        print_threat("Could not open file: ");
        printf("%s - %s\n", filename, errbuf);
        return 2;
    }
    
    int captured = 0;
    CaptureContext ctx = {
        .buffer = buffer,
        .packet_count = &captured,
        .max_packets = -1  // No limit
    };
    
    // Process all packets in file
    pcap_loop(handle, -1, packet_handler, (u_char*)&ctx);
    
    pcap_close(handle);
    
    print_success("PCAP file loaded. ");
    printf("Loaded %d packets to buffer.\n", captured);
    
    return 0;
}

/**
 * @brief Lists all available network devices.
 */
void list_devices(void) {
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    print_info("Available network devices:\n");
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        print_threat("Error finding devices: ");
        printf("%s\n", errbuf);
        return;
    }

    int i = 1;
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        printf("  %d. ", i++);
        print_success(dev->name);
        if (dev->description) {
            printf(" (%s)\n", dev->description);
        } else {
            printf(" (No description available)\n");
        }
    }

    pcap_freealldevs(alldevs);
}

#ifdef PLATFORM_LINUX
#include <sys/socket.h>
#include <netinet/in.h>

/**
 * @brief Start UDP listener for Syslog messages
 */
int start_syslog_listener(int port, PacketBuffer *buffer) {
    if (!buffer) return -1;
    
    int sockfd;
    struct sockaddr_in servaddr, cliaddr;
    char recvbuffer[MAX_BUFFER_SIZE];
    
    print_info("Starting Syslog UDP listener on port ");
    printf("%d\n", port);
    
    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        print_threat("Socket creation failed\n");
        return -1;
    }
    
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));
    
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(port);
    
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        print_threat("Bind failed\n");
        return -1;
    }
    
    print_success("Syslog listener started. Press Ctrl+C to stop.\n\n");
    
    while (1) {
        socklen_t len = sizeof(cliaddr);
        int n = recvfrom(sockfd, recvbuffer, MAX_BUFFER_SIZE, 0,
                        (struct sockaddr *)&cliaddr, &len);
        
        if (n > 0) {
            recvbuffer[n] = '\0';
            
            // Create log entry from syslog message
            NormalizedLog log = {0};
            log.timestamp = time(NULL);
            log.log_type = LOG_TYPE_SYSLOG;
            inet_ntop(AF_INET, &cliaddr.sin_addr, log.source_ip, sizeof(log.source_ip));
            strncpy(log.raw_message, recvbuffer, sizeof(log.raw_message) - 1);
            strcpy(log.severity, "INFO");
            strcpy(log.event_type, "syslog_message");
            
            // Add to buffer
            add_to_buffer(buffer, &log);
            
            // Print received message
            print_info("Received: ");
            printf("%s\n", recvbuffer);
        }
    }
    
    return 0;
}
#else
int start_syslog_listener(int port, PacketBuffer *buffer) {
    (void)port;
    (void)buffer;
    print_warning("Syslog listener not implemented for this platform\n");
    return -1;
}
#endif