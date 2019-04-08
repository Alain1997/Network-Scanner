#!/usr/bin/python
from scapy.all import *

ip=IP(src="192.168.0.107", dst="192.168.0.101")
TCP_SYN=TCP(sport=1500, dport=57621, flags="A", seq=100)
TCP_SYNACK=sr1(ip/TCP_SYN)

my_ack = TCP_SYNACK.seq + 1
TCP_ACK=TCP(sport=1500, dport=80, flags="A", seq=101, ack=my_ack)
send(ip/TCP_ACK)

my_payload="space for rent!"
TCP_PUSH=TCP(sport=1500, dport=80, flags="PA", seq=102, ack=my_ack)
send(ip/TCP_PUSH/my_payload)
