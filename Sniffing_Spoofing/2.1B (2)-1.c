#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);  // Assuming Ethernet frame, adjust if needed

    // Check if it's a TCP packet
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4);

        // Extract source and destination IP addresses
        char source_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

        // Print the source and destination IP addresses
        printf("Source IP: %s\n", source_ip);
        printf("Destination IP: %s\n", dest_ip);

        // Print TCP destination port
        printf("TCP Destination Port: %u\n", ntohs(tcp_header->th_dport));

    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp and dst portrange 10-100";  // Filter for TCP and destination port range
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name br-1983922ac8d6.
    // Adjust interface name as needed.
    handle = pcap_open_live("br-1983922ac8d6", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);

    if (pcap_setfilter(handle, &fp) != 0) {
        perror("Error setting filter:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // Close the handle

    return 0;
}

