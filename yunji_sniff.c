#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <ctype.h>

#define ETHERNET_SIZE 14

// 이더넷 헤더 구조체
struct ethheader {
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short type;
};

// MAC 주소 출력
void print_mac(const u_char *mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02X", mac[i]);
        if (i < 5) printf(":");
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (header->len < ETHERNET_SIZE + sizeof(struct ip))
        return;

    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->type) != 0x0800)  // IPv4만
        return;

    struct ip *ip = (struct ip *)(packet + ETHERNET_SIZE);
    if (ip->ip_p != IPPROTO_TCP)     // TCP만
        return;

    int ip_header_len = ip->ip_hl * 4;
    struct tcphdr *tcp = (struct tcphdr *)(packet + ETHERNET_SIZE + ip_header_len);
    int tcp_header_len = tcp->th_off * 4;

    int payload_offset = ETHERNET_SIZE + ip_header_len + tcp_header_len;
    int total_ip_len = ntohs(ip->ip_len);
    int payload_len = total_ip_len - ip_header_len - tcp_header_len;

    printf("=======================================\n");
    printf("Ethernet Src MAC: "); print_mac(eth->src_mac); printf("\n");
    printf("Ethernet Dst MAC: "); print_mac(eth->dst_mac); printf("\n");
    printf("IP Src: %s\n", inet_ntoa(ip->ip_src));
    printf("IP Dst: %s\n", inet_ntoa(ip->ip_dst));
    printf("TCP Src Port: %u\n", ntohs(tcp->th_sport));
    printf("TCP Dst Port: %u\n", ntohs(tcp->th_dport));

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
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0, mask = 0;

    // 기본 디바이스 탐색
    pcap_if_t *alldevs, *dev;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }
    dev = alldevs;
    if (dev == NULL) {
        fprintf(stderr, "No device found.\n");
        return 2;
    }
    printf("Using device: %s\n", dev->name);

    if (pcap_lookupnet(dev->name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Warning: Couldn't get netmask for device %s: %s\n", dev->name, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev->name, errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        return 3;
    }

    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}

