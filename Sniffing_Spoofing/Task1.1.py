#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
 print_pkt.No +=1
 print(f"packet : {print_pkt.No}")
 pkt.show()

print_pkt.No=0

# ICMP Packets
# pkt = sniff(iface='br-1983922ac8d6', filter='icmp', prn=print_pkt)

# TCP Packet from 10.9.0.6(telnet)
#pkt = sniff(iface='br-1983922ac8d6', filter='tcp && src host 10.9.0.6 && dst port 23', prn=print_pkt)

# Subnet Traffic
pkt = sniff(iface='br-1983922ac8d6', filter='net 128.230.0.0/16', prn=print_pkt)
