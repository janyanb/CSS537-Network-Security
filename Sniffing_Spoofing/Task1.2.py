#!/usr/bin/env python3

from scapy.all import *
a = IP() 
a.dst = '10.0.2.3' 
b = ICMP() 
p = a/b 

a.show()
send(p,iface='br-1983922ac8d6') 
