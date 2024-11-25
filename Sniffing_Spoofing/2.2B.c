#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/udp.h>

#define PACKET_SIZE 64

// Function to calculate the checksum for ICMP header
unsigned short calculate_checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    for (; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// Function to send a raw IP packet
void send_raw_ip_packet(struct ip *ip_header) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set IP_HDRINCL option to include IP header
    int enable = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        perror("setsockopt");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Send the packet
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(struct sockaddr_in));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = ip_header->ip_dst;

    if (sendto(sock, ip_header, ntohs(ip_header->ip_len), 0, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("sendto");
    }

    close(sock);
}

int main() {
    char packet[PACKET_SIZE];
    memset(packet, 0, PACKET_SIZE);

    // IP header
    struct ip *ip_header = (struct ip *)packet;
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_len = htons(PACKET_SIZE);
    ip_header->ip_id = htons(1234);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 255;
    ip_header->ip_p = IPPROTO_ICMP;
    inet_pton(AF_INET, "1.2.3.4", &(ip_header->ip_src)); 
    inet_pton(AF_INET, "10.0.2.3", &(ip_header->ip_dst)); 

    // ICMP header
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + sizeof(struct ip));
    icmp_header->type = ICMP_ECHO;
    icmp_header->code = 0;
    icmp_header->checksum = 0;
    icmp_header->un.echo.id = 0;
    icmp_header->un.echo.sequence = 0;
    icmp_header->checksum = calculate_checksum((unsigned short *)icmp_header, sizeof(struct icmphdr));

    // Send the spoofed ICMP Echo Request
    send_raw_ip_packet(ip_header);

    return 0;
}




