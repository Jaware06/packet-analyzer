#!/usr/bin/env python3
"""
Threat PCAP Generator - Creates a .pcap file with 50+ threat packets
Run this to generate a PCAP file full of malware traffic
"""

import struct
import time
import random
import socket
import os
from datetime import datetime

class ThreatPCAPGenerator:
    def __init__(self, filename=None):
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"full_threat_traffic_{timestamp}.pcap"
        self.filename = filename
        self.packets = []
        
    def create_ethernet(self, src_mac, dst_mac, payload):
        """Ethernet frame"""
        src_bytes = bytes.fromhex(src_mac.replace(':', ''))
        dst_bytes = bytes.fromhex(dst_mac.replace(':', ''))
        ethertype = struct.pack('>H', 0x0800)
        return dst_bytes + src_bytes + ethertype + payload
    
    def create_ip(self, src_ip, dst_ip, payload, protocol=6):
        """IPv4 packet"""
        src_bytes = socket.inet_aton(src_ip)
        dst_bytes = socket.inet_aton(dst_ip)
        
        version_ihl = 0x45
        tos = 0
        total_length = 20 + len(payload)
        identification = random.randint(0, 65535)
        flags = 0x4000
        ttl = 64
        protocol_byte = protocol
        checksum = 0
        
        header = struct.pack('!BBHHHBBH4s4s',
            version_ihl, tos, total_length, identification,
            flags, ttl, protocol_byte, checksum,
            src_bytes, dst_bytes
        )
        
        # Calculate checksum
        if len(header) % 2 != 0:
            header += b'\x00'
        s = sum(struct.unpack('!%dH' % (len(header) // 2), header))
        s = (s >> 16) + (s & 0xFFFF)
        s += (s >> 16)
        checksum = ~s & 0xFFFF
        
        header = struct.pack('!BBHHHBBH4s4s',
            version_ihl, tos, total_length, identification,
            flags, ttl, protocol_byte, checksum,
            src_bytes, dst_bytes
        )
        
        return header + payload
    
    def create_tcp(self, src_ip, dst_ip, src_port, dst_port, payload):
        """TCP segment"""
        src_bytes = socket.inet_aton(src_ip)
        dst_bytes = socket.inet_aton(dst_ip)
        
        seq = random.randint(0, 4294967295)
        ack = 0
        offset_flags = 0x5018
        window = 65535
        checksum = 0
        urgent = 0
        
        tcp_header = struct.pack('!HHIIHHHH',
            src_port, dst_port, seq, ack,
            offset_flags, window, checksum, urgent
        )
        
        # Calculate checksum
        pseudo = struct.pack('!4s4sBBH',
            src_bytes, dst_bytes, 0, 6, len(tcp_header) + len(payload)
        )
        checksum_data = pseudo + tcp_header + payload
        if len(checksum_data) % 2 != 0:
            checksum_data += b'\x00'
        
        s = sum(struct.unpack('!%dH' % (len(checksum_data) // 2), checksum_data))
        s = (s >> 16) + (s & 0xFFFF)
        s += (s >> 16)
        checksum = ~s & 0xFFFF
        
        tcp_header = struct.pack('!HHIIHHHH',
            src_port, dst_port, seq, ack,
            offset_flags, window, checksum, urgent
        )
        
        return tcp_header + payload
    
    def create_udp(self, src_ip, dst_ip, src_port, dst_port, payload):
        """UDP datagram"""
        src_bytes = socket.inet_aton(src_ip)
        dst_bytes = socket.inet_aton(dst_ip)
        
        length = 8 + len(payload)
        checksum = 0
        
        udp_header = struct.pack('!HHHH',
            src_port, dst_port, length, checksum
        )
        
        # Calculate checksum
        pseudo = struct.pack('!4s4sBBH',
            src_bytes, dst_bytes, 0, 17, length
        )
        checksum_data = pseudo + udp_header + payload
        if len(checksum_data) % 2 != 0:
            checksum_data += b'\x00'
        
        s = sum(struct.unpack('!%dH' % (len(checksum_data) // 2), checksum_data))
        s = (s >> 16) + (s & 0xFFFF)
        s += (s >> 16)
        checksum = ~s & 0xFFFF
        
        udp_header = struct.pack('!HHHH',
            src_port, dst_port, length, checksum
        )
        
        return udp_header + payload
    
    def build_packet(self, src_ip, dst_ip, src_port, dst_port,
                     protocol='TCP', payload=None,
                     src_mac='aa:bb:cc:dd:ee:ff',
                     dst_mac='00:11:22:33:44:55'):
        """Build complete packet"""
        if payload is None:
            payload = b'Threat traffic detected'
        
        if protocol == 'TCP':
            transport = self.create_tcp(src_ip, dst_ip, src_port, dst_port, payload)
            ip_protocol = 6
        else:
            transport = self.create_udp(src_ip, dst_ip, src_port, dst_port, payload)
            ip_protocol = 17
        
        ip_packet = self.create_ip(src_ip, dst_ip, transport, protocol=ip_protocol)
        ethernet = self.create_ethernet(src_mac, dst_mac, ip_packet)
        
        return ethernet
    
    def generate_full_threat_traffic(self):
        """Generate 50+ threat packets"""
        
        print("\n" + "="*60)
        print("🔴 GENERATING FULL THREAT PCAP")
        print("="*60)
        
        base_time = int(time.time())
        packet_count = 0
        
        # ============================================================
        # 1. C2 BEACONING - Multiple C2 Servers (UDP)
        # ============================================================
        print("\n[1] C2 Beaconing (UDP)")
        c2_servers = [
            ('23.212.0.17', 4444),
            ('45.33.22.11', 4444),
            ('198.51.100.45', 4444),
            ('203.0.113.77', 4444),
            ('104.18.39.21', 4444),
        ]
        
        for i, (ip, port) in enumerate(c2_servers):
            for j in range(3):  # Multiple beacons per server
                payload = f'C2_BEACON_{i}_{j}_COMMAND_CONTROL_HEARTBEAT'.encode()
                packet = self.build_packet(
                    src_ip='192.168.1.100',
                    dst_ip=ip,
                    src_port=random.randint(1024, 65535),
                    dst_port=port,
                    protocol='UDP',
                    payload=payload
                )
                self.packets.append((packet, base_time + packet_count))
                packet_count += 1
                print(f"    • Beacon to {ip}:{port}")
        
        # ============================================================
        # 2. MALWARE DOWNLOAD (TCP)
        # ============================================================
        print("\n[2] Malware Downloads (TCP)")
        malware_urls = [
            ('20.42.65.89', 443, b'GET /malware/ransomware.exe HTTP/1.1'),
            ('20.42.65.89', 443, b'GET /malware/trojan.dll HTTP/1.1'),
            ('20.42.65.89', 443, b'GET /malware/keylogger.exe HTTP/1.1'),
            ('23.212.0.17', 80, b'GET /payload/backdoor.exe HTTP/1.1'),
            ('104.18.39.21', 8080, b'GET /update/malware.bin HTTP/1.1'),
        ]
        
        for i, (ip, port, payload) in enumerate(malware_urls):
            packet = self.build_packet(
                src_ip='192.168.1.100',
                dst_ip=ip,
                src_port=random.randint(1024, 65535),
                dst_port=port,
                protocol='TCP',
                payload=payload
            )
            self.packets.append((packet, base_time + packet_count))
            packet_count += 1
            print(f"    • Malware download from {ip}:{port}")
        
        # ============================================================
        # 3. DATA EXFILTRATION (DNS Tunneling)
        # ============================================================
        print("\n[3] DNS Tunneling (UDP)")
        dns_servers = [
            ('23.212.0.11', 53),
            ('45.33.22.11', 53),
            ('203.0.113.77', 53),
        ]
        
        for i, (ip, port) in enumerate(dns_servers):
            for j in range(4):
                payload = f'EXFIL_DATA_CHUNK_{i}_{j}_SENSITIVE_INFORMATION'.encode()
                packet = self.build_packet(
                    src_ip='192.168.1.100',
                    dst_ip=ip,
                    src_port=random.randint(1024, 65535),
                    dst_port=port,
                    protocol='UDP',
                    payload=payload
                )
                self.packets.append((packet, base_time + packet_count))
                packet_count += 1
                print(f"    • DNS exfiltration to {ip}:{port}")
        
        # ============================================================
        # 4. C2 COMMUNICATION (TCP)
        # ============================================================
        print("\n[4] C2 Communication (TCP)")
        c2_commands = [
            ('104.18.39.21', 8080, b'C2_COMMAND_EXECUTE_MALWARE'),
            ('104.18.39.21', 8080, b'C2_COMMAND_STEAL_CREDENTIALS'),
            ('104.18.39.21', 8080, b'C2_COMMAND_DOWNLOAD_NEXT_STAGE'),
            ('23.212.0.17', 4444, b'C2_COMMAND_ENCRYPT_FILES'),
            ('45.33.22.11', 1337, b'C2_COMMAND_SCAN_NETWORK'),
        ]
        
        for i, (ip, port, payload) in enumerate(c2_commands):
            packet = self.build_packet(
                src_ip='192.168.1.100',
                dst_ip=ip,
                src_port=random.randint(1024, 65535),
                dst_port=port,
                protocol='TCP',
                payload=payload
            )
            self.packets.append((packet, base_time + packet_count))
            packet_count += 1
            print(f"    • C2 command to {ip}:{port}")
        
        # ============================================================
        # 5. C2 RESPONSES (UDP)
        # ============================================================
        print("\n[5] C2 Response (UDP)")
        c2_responses = [
            ('23.212.0.17', 4444, b'C2_RESPONSE_ACK_COMPLETE'),
            ('45.33.22.11', 4444, b'C2_RESPONSE_OK_PROCEED'),
            ('104.18.39.21', 8080, b'C2_RESPONSE_SUCCESS'),
            ('203.0.113.77', 4444, b'C2_RESPONSE_DATA_RECEIVED'),
        ]
        
        for i, (ip, port, payload) in enumerate(c2_responses):
            packet = self.build_packet(
                src_ip=ip,
                dst_ip='192.168.1.100',
                src_port=port,
                dst_port=random.randint(1024, 65535),
                protocol='UDP',
                payload=payload
            )
            self.packets.append((packet, base_time + packet_count))
            packet_count += 1
            print(f"    • C2 response from {ip}:{port}")
        
        # ============================================================
        # 6. PORT SCANNING (TCP)
        # ============================================================
        print("\n[6] Port Scanning (TCP)")
        scan_targets = [
            ('192.168.1.1', 22),
            ('192.168.1.1', 23),
            ('192.168.1.1', 80),
            ('192.168.1.1', 443),
            ('192.168.1.1', 8080),
            ('192.168.1.1', 3306),
            ('192.168.1.1', 3389),
        ]
        
        for i, (ip, port) in enumerate(scan_targets):
            packet = self.build_packet(
                src_ip='192.168.1.150',
                dst_ip=ip,
                src_port=random.randint(50000, 60000),
                dst_port=port,
                protocol='TCP',
                payload=b'SCAN_PROBE'
            )
            self.packets.append((packet, base_time + packet_count))
            packet_count += 1
            print(f"    • Port scan to {ip}:{port}")
        
        # ============================================================
        # 7. BEACONING TO MULTIPLE IPs (TCP)
        # ============================================================
        print("\n[7] Beaconing to Multiple Suspicious IPs (TCP)")
        suspicious_ips = [
            ('45.33.22.11', 1337),
            ('198.51.100.45', 6667),
            ('203.0.113.77', 31337),
            ('45.33.22.11', 4444),
            ('198.51.100.45', 1337),
        ]
        
        for i, (ip, port) in enumerate(suspicious_ips):
            for j in range(2):
                payload = f'BEACON_HEARTBEAT_{i}_{j}_ALIVE'.encode()
                packet = self.build_packet(
                    src_ip='192.168.1.100',
                    dst_ip=ip,
                    src_port=random.randint(1024, 65535),
                    dst_port=port,
                    protocol='TCP',
                    payload=payload
                )
                self.packets.append((packet, base_time + packet_count))
                packet_count += 1
                print(f"    • Beacon to {ip}:{port}")
        
        # ============================================================
        # 8. RANSOMWARE TRAFFIC (TCP)
        # ============================================================
        print("\n[8] Ransomware Network Activity (TCP)")
        ransomware_ips = [
            ('20.42.65.89', 443, b'POST /ransomware/encrypt HTTP/1.1'),
            ('20.42.65.89', 443, b'POST /ransomware/key HTTP/1.1'),
            ('23.212.0.17', 4444, b'RANSOMWARE_STATUS_ENCRYPTING'),
            ('45.33.22.11', 1337, b'RANSOMWARE_BITCOIN_ADDRESS'),
        ]
        
        for i, (ip, port, payload) in enumerate(ransomware_ips):
            packet = self.build_packet(
                src_ip='192.168.1.100',
                dst_ip=ip,
                src_port=random.randint(1024, 65535),
                dst_port=port,
                protocol='TCP',
                payload=payload
            )
            self.packets.append((packet, base_time + packet_count))
            packet_count += 1
            print(f"    • Ransomware traffic to {ip}:{port}")
        
        # ============================================================
        # 9. FALSE POSITIVES (Will be filtered)
        # ============================================================
        print("\n[9] False Positive Traffic (Will be filtered)")
        
        # UPnP Discovery (filtered)
        for i in range(5):
            packet = self.build_packet(
                src_ip='192.168.1.1',
                dst_ip='239.255.255.250',
                src_port=1900,
                dst_port=1900,
                protocol='UDP',
                payload=b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n'
            )
            self.packets.append((packet, base_time + packet_count))
            packet_count += 1
            print(f"    • UPnP Discovery #{i+1} (filtered)")
        
        # DNS Queries (filtered)
        for i in range(5):
            packet = self.build_packet(
                src_ip='192.168.1.100',
                dst_ip='8.8.8.8',
                src_port=random.randint(1024, 65535),
                dst_port=53,
                protocol='UDP',
                payload=f'DNS_QUERY_EXAMPLE_{i}.com'.encode()
            )
            self.packets.append((packet, base_time + packet_count))
            packet_count += 1
            print(f"    • DNS Query #{i+1} (filtered)")
        
        # DHCP (filtered)
        packet = self.build_packet(
            src_ip='0.0.0.0',
            dst_ip='255.255.255.255',
            src_port=68,
            dst_port=67,
            protocol='UDP',
            payload=b'DHCP_DISCOVER'
        )
        self.packets.append((packet, base_time + packet_count))
        packet_count += 1
        print(f"    • DHCP Discovery (filtered)")
        
        # ============================================================
        # 10. NORMAL TRAFFIC (Not filtered)
        # ============================================================
        print("\n[10] Normal Traffic (Not filtered)")
        
        # Google web traffic
        packet = self.build_packet(
            src_ip='192.168.1.100',
            dst_ip='142.250.185.46',
            src_port=random.randint(1024, 65535),
            dst_port=443,
            protocol='TCP',
            payload=b'GET / HTTP/1.1\r\nHost: google.com\r\n\r\n'
        )
        self.packets.append((packet, base_time + packet_count))
        packet_count += 1
        print(f"    • Google web traffic")
        
        # Facebook
        packet = self.build_packet(
            src_ip='192.168.1.100',
            dst_ip='157.240.1.35',
            src_port=random.randint(1024, 65535),
            dst_port=443,
            protocol='TCP',
            payload=b'GET / HTTP/1.1\r\nHost: facebook.com\r\n\r\n'
        )
        self.packets.append((packet, base_time + packet_count))
        packet_count += 1
        print(f"    • Facebook traffic")
        
        # YouTube
        packet = self.build_packet(
            src_ip='192.168.1.100',
            dst_ip='142.250.185.110',
            src_port=random.randint(1024, 65535),
            dst_port=443,
            protocol='TCP',
            payload=b'GET / HTTP/1.1\r\nHost: youtube.com\r\n\r\n'
        )
        self.packets.append((packet, base_time + packet_count))
        packet_count += 1
        print(f"    • YouTube traffic")
        
        return packet_count
    
    def save(self):
        """Save to PCAP format"""
        with open(self.filename, 'wb') as f:
            # PCAP global header
            f.write(struct.pack('<IHHIIII',
                0xa1b2c3d4,  # magic
                2, 4,        # version
                0, 0,        # timezone, sigfigs
                65535,       # snaplen
                1            # ethernet
            ))
            
            # Sort by timestamp
            sorted_packets = sorted(self.packets, key=lambda x: x[1])
            
            # Write each packet
            for packet_data, timestamp in sorted_packets:
                f.write(struct.pack('<IIII',
                    timestamp,
                    0,
                    len(packet_data),
                    len(packet_data)
                ))
                f.write(packet_data)
        
        size = os.path.getsize(self.filename)
        return size
    
    def generate(self):
        """Generate the full threat PCAP"""
        
        print("\n" + "="*60)
        print("🔴 GENERATING FULL THREAT PCAP")
        print("="*60)
        
        total_packets = self.generate_full_threat_traffic()
        
        print("\n" + "="*60)
        print("💾 Saving to file...")
        print("="*60)
        
        size = self.save()
        
        print(f"\n✅ PCAP GENERATED: {self.filename}")
        print(f"📦 File size: {size:,} bytes ({size/1024:.2f} KB)")
        print(f"📊 Total packets: {total_packets}")
        
        print("\n" + "="*60)
        print("📋 THREAT SUMMARY")
        print("="*60)
        print("  🔴 C2 Beaconing: 15 packets")
        print("  🔴 Malware Downloads: 5 packets")
        print("  🔴 Data Exfiltration: 12 packets")
        print("  🔴 C2 Communication: 5 packets")
        print("  🔴 C2 Responses: 4 packets")
        print("  🔴 Port Scanning: 7 packets")
        print("  🔴 Beaconing: 10 packets")
        print("  🔴 Ransomware: 4 packets")
        print("  🛡️ False Positives: 11 packets (will be filtered)")
        print("  🟢 Normal Traffic: 3 packets")
        print("="*60)
        print(f"  📊 TOTAL: {total_packets} packets")
        print("="*60)
        
        print("\n📌 Next Steps:")
        print(f"  1. Open dashboard.html in browser")
        print("  2. Click the upload area")
        print(f"  3. Select: {self.filename}")
        print("  4. Watch alerts trigger! 🚨")
        print("="*60 + "\n")
        
        return self.filename

if __name__ == "__main__":
    generator = ThreatPCAPGenerator()
    generator.generate()