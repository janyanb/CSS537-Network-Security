# Packet Sniffing and Spoofing

## Overview
This repository contains C programs developed to explore and implement packet sniffing and spoofing techniques. The implementations use libraries like pcap for packet sniffing and raw sockets for packet spoofing. In addition, the repository also includes a simple stateless firewall implementation using C programming, leveraging Netfilter modules and Loadable Kernel Modules (LKMs) in a Linux environment. The firewall is designed to filter incoming and outgoing packets based on specific criteria such as source and destination IP addresses, ports, and protocols. 

Features
1. Packet Sniffing
Objective: Capture and analyze network packets in real-time.
Implementation Details:
Developed a packet-sniffing program using the pcap library.
Captured various types of packets (e.g., ICMP, TCP) on a live network interface.
Extracted and displayed source and destination IP addresses for each packet.
Implemented filters for selective packet capturing:
ICMP Packets: Captured only ICMP packets exchanged between two specific hosts.
TCP Packets: Filtered packets with destination ports in the range of 10-100.
Demonstrated the effect of enabling and disabling promiscuous mode, showing its impact on packet visibility.
2. Packet Spoofing
Objective: Craft and send custom packets with forged headers.
Implementation Details:
Created raw sockets to construct and send custom packets.
Spoofed ICMP Echo Request packets using another machine’s IP address as the source.
Verified spoofing success using Wireshark to capture and analyze spoofed packets.
3. Combined Sniff-and-Spoof
Objective: Intercept live traffic and respond with spoofed packets.
Implementation Details:
Designed a program that monitors ICMP traffic on the LAN.
Upon detecting an ICMP Echo Request, generated and sent an ICMP Echo Reply.
Simulated a scenario where a ping command receives replies even from an inactive machine, illustrating the manipulation of network responses.
