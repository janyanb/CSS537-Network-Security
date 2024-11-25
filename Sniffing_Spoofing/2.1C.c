#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);  // 

    // Check if it's a TCP packet
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4);
        
        if (ntohs(tcp_header->th_dport) == 23) {
            // Data offset gives the size of the TCP header in 32-bit words
            int data_offset = tcp_header->th_off * 4;

            // Calculate the start of the payload
            const u_char *payload = packet + 14 + ip_header->ip_hl * 4 + data_offset;

            // Get the length of the payload
            int payload_length = ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4) - data_offset;

            // Print the payload (data part of the TCP packet)
            printf("Telnet Payload:\n");
            for (int i = 0; i < payload_length; i++) {
                printf("%c", payload[i]);
            }
            printf("\n");
        }

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

