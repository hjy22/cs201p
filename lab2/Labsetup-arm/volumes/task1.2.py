#!/usr/bin/env python3
from scapy.layers.inet import *
from scapy.all import *


a = IP()
a.dst = "10.0.2.3"
b = ICMP()
p = a / b
send(p)
ls(a)
