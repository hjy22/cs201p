#!/usr/bin/env python3
from scapy.all import *


def spoof_pkt(pkt):
    # checks if the packet is an ICMP echo request (ICMP type 8).
    if ICMP in pkt and pkt[ICMP].type == 8:
        # swap the SIP and DIP
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load
        newpkt = ip / icmp / data
        send(newpkt, verbose=0)

        print("Receive: SIP: ", pkt[IP].src, " DIP: ", pkt[IP].dst)
        print("Send: SIP: ", newpkt[IP].src, " DIP: ", newpkt[IP].dst)
        print("==========================")


# filter = "icmp and host 1.2.3.4"
# filter = "icmp and host 10.9.0.99"
filter = "icmp and host 8.8.8.8"
pkt = sniff(iface="br-bb58983530d7", filter=filter, prn=spoof_pkt)
