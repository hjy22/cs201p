#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
    pkt.show()

#Capture only the ICMP packet    
#pkt = sniff(iface='br-a8c7f8c44fc9', filter='icmp', prn=print_pkt)

#Capture any TCP packet that comes from a particular IP and with a destination port number 23
pkt = sniff(iface='br-a8c7f8c44fc9', filter='tcp && src host 10.0.9.0/24 && dst port 23', prn=print_pkt)

#Capture packets comes from or to go to a particular subnet
#pkt = sniff(iface='br-a8c7f8c44fc9', filter='src host 128.230.0.0/16', prn=print_pkt)
