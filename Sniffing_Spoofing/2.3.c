#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include<stdlib.h>

// Function to calculate the checksum
unsigned short calculate_checksum(unsigned short *buf, int length)
{
unsigned short *w = buf;
int nleft = length;
int sum = 0;
unsigned short temp=0;
/*
* The algorithm uses a 32 bit accumulator (sum), adds
* sequential 16 bit words to it, and at the end, folds back all
* the carry bits from the top 16 bits into the lower 16 bits.
*/
while (nleft > 1) {
sum += *w++;
nleft -= 2;
}
/* treat the odd byte at the end, if any */
if (nleft == 1) {
*(u_char *)(&temp) = *(u_char *)w ;
sum += temp;
}
/* add back carry outs from top 16 bits to low 16 bits */
sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
sum += (sum >> 16); // add carry
return (unsigned short)(~sum);
}
unsigned short get_unique_ipid() {
    static unsigned short counter = 0;
    return htons(counter++);
}

// Callback function for packet capture
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_LEN);

    // If ICMP echo request, spoof reply
    if(ip->protocol == IPPROTO_ICMP){
        struct icmphdr *icmp = (struct icmphdr *)(packet + sizeof(struct iphdr) + ETHER_HDR_LEN);

        // If echo request
        if(icmp->type == ICMP_ECHO){
            // Spoof reply
            int sd;
            struct sockaddr_in sin;
            char buffer[1024];
            struct iphdr *ip_reply = (struct iphdr *) buffer;
            struct icmphdr *icmp_reply = (struct icmphdr *) (buffer + sizeof(struct iphdr));

           // Fill in the IP header
ip_reply->ihl = 5;
ip_reply->version = 4;
ip_reply->tos = 0;
ip_reply->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));  // Ensure proper byte order
ip_reply->id = htons(get_unique_ipid());  // Set the IPID field
ip_reply->frag_off = 0;
ip_reply->ttl = 64;
ip_reply->protocol = IPPROTO_ICMP;
ip_reply->saddr = ip->daddr;  // Swap source and destination addresses
ip_reply->daddr = ip->saddr;

// Fill in the ICMP header
icmp_reply->type = ICMP_ECHOREPLY;
icmp_reply->code = 0;
icmp_reply->un.echo.id = icmp->un.echo.id;
icmp_reply->un.echo.sequence = icmp->un.echo.sequence;
icmp_reply->checksum = 0;
icmp_reply->checksum = calculate_checksum((unsigned short *)icmp_reply, sizeof(struct icmphdr));  // Include data length
sleep(1);
// Create a raw socket for IP protocol
if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror("raw socket");
    exit(1);
}

// Tell the kernel that we're providing the IP header
const int on = 1;
if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
    perror("setsockopt");
    exit(1);
}

// Destination address
sin.sin_family = AF_INET;
sin.sin_addr.s_addr = ip->saddr;

// Send the packet
if (sendto(sd, buffer, sizeof(struct iphdr) + sizeof(struct icmphdr), 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
    perror("sendto");
    exit(1);
}
close(sd);
        }
    }
}

int main(){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;

    // Open device for sniffing
    handle = pcap_open_live("br-1983922ac8d6", BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return(2);
    }

    // Start packet capture
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the session
    pcap_close(handle);

    return 0;
}