from scapy.all import IP, TCP, UDP, wrpcap, Ether, ARP
import random

packets = []

# Port scan
for port in range(20, 30):
    packets.append(IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=random.randint(1000,60000), dport=port))

# DDoS
for i in range(150):
    packets.append(IP(src="10.0.0.50", dst="8.8.8.8")/UDP(sport=random.randint(1000,60000), dport=53))

# Malicious IP
for i in range(10):
    packets.append(IP(src="185.130.5.253", dst="192.168.1.5")/TCP(sport=random.randint(1000,60000), dport=445))

# ARP spoofing
for i in range(8):
    packets.append(Ether(src="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.5"))

# DNS queries
for i in range(15):
    packets.append(IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=random.randint(1000,60000), dport=53))

# Brute force
for i in range(25):
    packets.append(IP(src="192.168.1.200", dst="192.168.1.1")/TCP(sport=random.randint(1000,60000), dport=22))

wrpcap("threat_test.pcap", packets)
print(f"✅ Created threat_test.pcap with {len(packets)} packets")