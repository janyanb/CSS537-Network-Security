#!/usr/bin/env python3

from scapy.all import *
import sys

a = IP()
a.dst = '10.0.2.6'

#Takes the TTL value from cmd
a.ttl = int(sys.argv[1])
b = ICMP()
#send(a/b)

#stores received packet
a = sr1(a/b)

if a:
 print("Source:", a.src)
else:
 print("No Response")
