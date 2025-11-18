#include "packet_capture.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifndef LOG_ANALYZER_NO_PCAP
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#endif

#define ETHER_HEADER_LEN 14
#define ETHERTYPE_IPV4 0x0800

static double elapsed_seconds(const struct timeval *a, const struct timeval *b) {
    if (!a || !b) return 0.0;
    double sec = (double)(a->tv_sec - b->tv_sec);
    double usec = (double)(a->tv_usec - b->tv_usec) / 1e6;
    return sec + usec;
}

static void format_timestamp(const struct timeval *ts, char *buffer, size_t len) {
    if (!ts || !buffer || len == 0) return;
    time_t seconds = ts->tv_sec;
    struct tm tm_info;
#if defined(_WIN32)
    gmtime_s(&tm_info, &seconds);
#else
    gmtime_r(&seconds, &tm_info);
#endif
    strftime(buffer, len, "%Y-%m-%dT%H:%M:%S", &tm_info);
}

static const char *protocol_name(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_ICMP:
            return "ICMP";
        default:
            return "OTHER";
    }
}

static void persist_packet(FILE *fp,
                           const struct timeval *ts,
                           const char *src,
                           const char *dst,
                           size_t length,
                           uint8_t proto) {
    if (!fp) return;
    char timestamp[32];
    format_timestamp(ts, timestamp, sizeof(timestamp));
    fprintf(fp, "%s %s -> %s proto=%s len=%zu\n",
            timestamp,
            src,
            dst,
            protocol_name(proto),
            length);
}

static void store_alert(CaptureReport *report, const DDoSAlert *alert) {
    if (!report || !alert) return;
    if (report->ddos_alerts >= CAPTURE_MAX_ALERTS) return;
    report->alerts[report->ddos_alerts++] = *alert;
}

#ifndef LOG_ANALYZER_NO_PCAP
static int handle_packet(const u_char *packet,
                         const struct pcap_pkthdr *header,
                         FILE *fp,
                         DDoSDetector *detector,
                         CaptureReport *report) {
    if (!packet || !header || !report) return 0;
    if (header->caplen < ETHER_HEADER_LEN + sizeof(struct ip)) return 0;

    uint16_t ether_type = (uint16_t)((packet[12] << 8) | packet[13]);
    if (ether_type != ETHERTYPE_IPV4) return 0;

    const struct ip *ip_header = (const struct ip *)(packet + ETHER_HEADER_LEN);
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    if (!inet_ntop(AF_INET, &ip_header->ip_src, src_ip, sizeof(src_ip))) return 0;
    if (!inet_ntop(AF_INET, &ip_header->ip_dst, dst_ip, sizeof(dst_ip))) return 0;

    report->ipv4_packets++;
    persist_packet(fp, &header->ts, src_ip, dst_ip, header->len, ip_header->ip_p);
    if (fp) {
        report->logged_packets++;
    }

    if (detector) {
        DDoSAlert alert;
        if (ddos_detector_feed(detector, src_ip, &header->ts, &alert)) {
            store_alert(report, &alert);
        }
    }

    return 1;
}
#endif

int capture_live_packets(const CaptureOptions *options, CaptureReport *report) {
    if (!options || !report) return -1;
    memset(report, 0, sizeof(*report));

#ifdef LOG_ANALYZER_NO_PCAP
    (void)options;
    fprintf(stderr, "pcap support is not available at build time.\n");
    return -1;
#else
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *iface = options->interface_name ? options->interface_name : "en0";
    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Unable to open interface %s: %s\n", iface, errbuf);
        return -1;
    }

    FILE *fp = NULL;
    if (options->log_path) {
        fp = fopen(options->log_path, "w");
        if (!fp) {
            perror("capture log");
            pcap_close(handle);
            return -1;
        }
    }

    DDoSDetector detector;
    ddos_detector_init(&detector,
                       options->ddos_threshold ? options->ddos_threshold : 100,
                       options->ddos_window_seconds ? options->ddos_window_seconds : 5);

    struct timeval start_ts = {0};
    int started = 0;
    size_t packet_limit = options->packet_limit ? options->packet_limit : 500;

    while (report->total_packets < packet_limit) {
        const u_char *packet = NULL;
        struct pcap_pkthdr *header = NULL;
        int status = pcap_next_ex(handle, &header, &packet);
        if (status == 0) {
            continue;
        } else if (status == -1) {
            fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
            report->errors++;
            break;
        } else if (status == -2) {
            break;
        }

        if (!started) {
            start_ts = header->ts;
            started = 1;
        }

        if (options->duration_seconds > 0) {
            double span = elapsed_seconds(&header->ts, &start_ts);
            if (span > options->duration_seconds) {
                break;
            }
        }

        report->total_packets++;
        handle_packet(packet, header, fp, &detector, report);
    }

    if (fp) {
        fclose(fp);
    }
    pcap_close(handle);
    return 0;
#endif
}

void print_capture_report(const CaptureOptions *options, const CaptureReport *report) {
    if (!report) return;

    printf("\nLive Capture Summary\n");
    printf("--------------------\n");
    if (options && options->interface_name) {
        printf("Interface     : %s\n", options->interface_name);
    }
    printf("Packets seen  : %zu\n", report->total_packets);
    printf("IPv4 packets  : %zu\n", report->ipv4_packets);
    if (report->logged_packets) {
        printf("Logged lines  : %zu\n", report->logged_packets);
    }
    printf("Errors        : %zu\n", report->errors);
    printf("DDoS alerts   : %zu\n", report->ddos_alerts);

    for (size_t i = 0; i < report->ddos_alerts; ++i) {
        const DDoSAlert *alert = &report->alerts[i];
        char first_buf[32];
        char last_buf[32];
        format_timestamp(&alert->first_seen, first_buf, sizeof(first_buf));
        format_timestamp(&alert->last_seen, last_buf, sizeof(last_buf));
        printf("  #%zu offender=%s packets=%zu window=%.2fs [%s -> %s]\n",
               i + 1,
               alert->source_ip,
               alert->packet_count,
               alert->window_span,
               first_buf,
               last_buf);
    }
}
