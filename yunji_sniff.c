#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdint.h>

#define ETHERNET_SIZE 14

// Ethernet Header
struct ethheader {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
};

// IP Header
struct ipheader {
    uint8_t ihl_ver;       // Version (4 bits) + IHL (4 bits)
    uint8_t tos;
    uint16_t tlen;
    uint16_t identification;
    uint16_t flags_fo;
    uint8_t ttl;
    uint8_t proto;
    uint16_t crc;
    uint32_t src_ip;
    uint32_t dst_ip;
};

// TCP Header
struct tcpheader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t offset_reserved; // Data offset (upper 4 bits)
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

void print_mac(const uint8_t *mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02X", mac[i]);
        if (i < 5) printf(":");
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->type) != 0x0800) return;

    struct ipheader *ip = (struct ipheader *)(packet + ETHERNET_SIZE);
    int ip_header_len = (ip->ihl_ver & 0x0F) * 4;

    if (ip->proto != 6) return;

    struct tcpheader *tcp = (struct tcpheader *)(packet + ETHERNET_SIZE + ip_header_len);
    int tcp_header_len = ((tcp->offset_reserved & 0xF0) >> 4) * 4;

    int payload_offset = ETHERNET_SIZE + ip_header_len + tcp_header_len;
    int total_len = ntohs(ip->tlen);
    int payload_len = total_len - ip_header_len - tcp_header_len;

    struct in_addr src, dst;
    src.s_addr = ip->src_ip;
    dst.s_addr = ip->dst_ip;

    printf("=======================================\n");
    printf("Ethernet Src MAC: "); print_mac(eth->src_mac); printf("\n");
    printf("Ethernet Dst MAC: "); print_mac(eth->dst_mac); printf("\n");
    printf("IP Src: %s\n", inet_ntoa(src));
    printf("IP Dst: %s\n", inet_ntoa(dst));
    printf("TCP Src Port: %u\n", ntohs(tcp->src_port));
    printf("TCP Dst Port: %u\n", ntohs(tcp->dst_port));

    if (payload_len > 0 && payload_offset < header->caplen) {
        printf("Message: ");
        for (int i = 0; i < payload_len && i < 32; i++) {
            u_char c = packet[payload_offset + i];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("\n");
    } else {
        printf("No Payload.\n");
    }

    printf("=======================================\n\n");
}

int main() {
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0, mask = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    dev = alldevs;
    if (!dev) {
        fprintf(stderr, "No device found.\n");
        return 2;
    }

    printf("Using device: %s\n", dev->name);

    if (pcap_lookupnet(dev->name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Warning: Couldn't get netmask: %s\n", errbuf);
        net = mask = 0;
    }

    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1 || pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't set filter: %s\n", pcap_geterr(handle));
        return 3;
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freealldevs(alldevs);
    pcap_close(handle);
    return 0;
}
