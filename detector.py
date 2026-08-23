import re
import math
from collections import Counter, defaultdict

class ThreatDetector:
    def __init__(self):
        # We perform analysis dynamically, using statistics rather than static threat lists.
        pass

    def analyze(self, packets):
        """
        Analyzes a list of packet dictionaries and returns detected threats.
        Each packet is a dictionary like:
        {
            'src': '192.168.1.100',
            'dst': '192.168.1.1',
            'protocol': 'TCP',
            'info': 'Port: 1234->22'
        }
        """
        threats = []
        if not packets:
            return threats

        total_packets = len(packets)

        # Counters for statistical analytics
        src_ip_counts = Counter()
        dst_ip_counts = Counter()
        protocol_counts = Counter()
        
        # Track connections per source IP to destination ports
        src_to_ports = defaultdict(set)
        # Track connection logs to specific administrative/sensitive ports
        src_to_admin_ports = defaultdict(int)
        # Track ARP associations (IP -> set of MAC addresses)
        arp_mappings = defaultdict(set)
        # Track DNS query details (domain -> list of packet indexes / lengths)
        dns_queries = Counter()
        dns_long_domains = Counter()

        admin_ports = {22, 23, 3389, 445, 1433, 3306}

        # First pass: collect statistics
        for pkt in packets:
            src = pkt.get('src')
            dst = pkt.get('dst')
            proto = pkt.get('protocol', 'Other')
            info = pkt.get('info', '')

            protocol_counts[proto] += 1

            if src:
                src_ip_counts[src] += 1
            if dst:
                dst_ip_counts[dst] += 1

            # Port analysis
            port_match = re.search(r'Port:\s*(\d+)->(\d+)', info)
            if port_match:
                sport = int(port_match.group(1))
                dport = int(port_match.group(2))
                if src:
                    src_to_ports[src].add(dport)
                    if dport in admin_ports:
                        src_to_admin_ports[src] += 1

            # ARP details
            if proto == 'ARP':
                arp_match = re.search(r'ARP:\s*(?:who-has|is-at)\s+(\S+)\s*->\s*(\S+)', info)
                if arp_match:
                    psrc = arp_match.group(1)
                    pdst = arp_match.group(2)
                    # Often the Ether layer holds MAC addresses. If we don't have MACs in Scapy callback,
                    # we look in the info field for MAC associations.
                    mac_match = re.search(r'MAC:\s*(\S+)', info)
                    mac = mac_match.group(1) if mac_match else None
                    if mac and psrc:
                        arp_mappings[psrc].add(mac)

            # DNS analysis
            if proto == 'UDP' and ('DNS' in info or 'Domain:' in info):
                domain_match = re.search(r'Domain:\s*(\S+)', info)
                if domain_match:
                    domain = domain_match.group(1)
                    dns_queries[domain] += 1
                    if len(domain) > 30:
                        dns_long_domains[domain] += 1

        # Standard Deviation calculation for traffic volumes to detect anomalies
        ip_counts_list = list(src_ip_counts.values())
        avg_volume = 0
        std_dev = 0
        if ip_counts_list:
            avg_volume = sum(ip_counts_list) / len(ip_counts_list)
            variance = sum((x - avg_volume) ** 2 for x in ip_counts_list) / len(ip_counts_list)
            std_dev = math.sqrt(variance)

        # Let's assess threat scores per IP
        # We'll calculate a unified Threat Score (0 - 100) per source IP.
        # High Score indicates high probability of malice.
        ip_scores = {}
        ip_reasons = defaultdict(list)

        # 1. Volumetric/DDoS scoring
        # Threshold: if it deviates significantly from the mean, and is above 40 packets
        for ip, count in src_ip_counts.items():
            # Private subnet gateway / broadcast / loopback addresses are ignored for volumetric alerts
            if ip in {'127.0.0.1', '0.0.0.0', '255.255.255.255', 'ff02::1'}:
                continue
            
            # Volumetric score contribution
            vol_score = 0
            if count > 150:
                vol_score = 35
                ip_reasons[ip].append(f"Extremely high packet volume ({count} packets)")
            elif std_dev > 5 and count > (avg_volume + 3 * std_dev) and count > 40:
                vol_score = 25
                ip_reasons[ip].append(f"Statistically anomalous traffic volume ({count} packets vs avg {avg_volume:.1f})")
            
            ip_scores[ip] = ip_scores.get(ip, 0) + vol_score

        # 2. Port Scanning scoring
        for ip, ports in src_to_ports.items():
            if ip in {'127.0.0.1', '0.0.0.0'}:
                continue
            if len(ports) > 10:
                scan_score = min(40, len(ports) * 2)
                ip_scores[ip] = ip_scores.get(ip, 0) + scan_score
                ip_reasons[ip].append(f"Targeted {len(ports)} different destination ports (potential port scan)")

        # 3. Brute Force Attempt scoring
        for ip, attempts in src_to_admin_ports.items():
            if ip in {'127.0.0.1'}:
                continue
            if attempts > 15:
                bf_score = min(40, attempts * 1.5)
                ip_scores[ip] = ip_scores.get(ip, 0) + bf_score
                ip_reasons[ip].append(f"Sent {attempts} requests to sensitive admin ports (SSH/RDP/SMB/SQL)")

        # 4. ARP Spoofing alerts (Separate threat entry as it is identity-based)
        for ip, macs in arp_mappings.items():
            if len(macs) > 1:
                threats.append({
                    'type': 'ARP Spoofing Detected',
                    'source': ip,
                    'severity': 'Critical',
                    'details': f"IP address associated with multiple hardware addresses: {', '.join(macs)}",
                    'score': 95
                })

        # 5. DNS tunnel/amplification detection
        for domain, q_count in dns_queries.items():
            if q_count > 25:
                threats.append({
                    'type': 'DNS Flooding/Tunneling',
                    'source': domain,
                    'severity': 'High',
                    'details': f"Abnormal DNS query frequency to domain: {q_count} requests",
                    'score': 70
                })
        for domain, q_count in dns_long_domains.items():
            if q_count > 10:
                threats.append({
                    'type': 'DNS Data Exfiltration Suspect',
                    'source': domain,
                    'severity': 'High',
                    'details': f"Excessive long hostname DNS queries (subdomain exfiltration)",
                    'score': 65
                })

        # Combine score-based threats for IPs
        for ip, score in ip_scores.items():
            if score >= 20:
                severity = 'Low'
                if score >= 70:
                    severity = 'Critical'
                elif score >= 45:
                    severity = 'High'
                elif score >= 25:
                    severity = 'Medium'

                threats.append({
                    'type': f'{severity} Risk Network Activity',
                    'source': ip,
                    'severity': severity,
                    'details': '; '.join(ip_reasons[ip]),
                    'score': round(score)
                })

        # Protocol ratio anomalies
        if total_packets > 40:
            tcp_ratio = (protocol_counts.get('TCP', 0) / total_packets) * 100
            udp_ratio = (protocol_counts.get('UDP', 0) / total_packets) * 100
            if tcp_ratio > 98:
                threats.append({
                    'type': 'TCP Traffic Dominance',
                    'source': 'Network Gateway',
                    'severity': 'Medium',
                    'details': f"TCP traffic occupies {tcp_ratio:.1f}% of total network footprint.",
                    'score': 35
                })
            elif udp_ratio > 85:
                threats.append({
                    'type': 'UDP Broadcast Torrent',
                    'source': 'Network Gateway',
                    'severity': 'High',
                    'details': f"UDP volume occupies {udp_ratio:.1f}% of total network footprint (potential flood).",
                    'score': 55
                })

        # Sort threats by severity rank
        severity_rank = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        threats.sort(key=lambda t: severity_rank.get(t['severity'], 0), reverse=True)

        return threats
