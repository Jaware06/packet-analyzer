import threading
import time
import random
import logging
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP

logger = logging.getLogger(__name__)

class LiveSniffer:
    def __init__(self, max_buffer=500):
        self.max_buffer = max_buffer
        self.packets = []
        self.lock = threading.Lock()
        self.active = False
        self.thread = None
        self.is_mock = False

    def packet_callback(self, packet):
        if not self.active:
            return

        info = {'protocol': 'Other', 'info': '', 'length': len(packet)}

        if IP in packet:
            info['src'] = packet[IP].src
            info['dst'] = packet[IP].dst

            if TCP in packet:
                info['protocol'] = 'TCP'
                info['info'] = f"Port: {packet[TCP].sport}->{packet[TCP].dport}"
            elif UDP in packet:
                info['protocol'] = 'UDP'
                info['info'] = f"Port: {packet[UDP].sport}->{packet[UDP].dport}"
            elif ICMP in packet:
                info['protocol'] = 'ICMP'
                info['info'] = "ICMP Echo Request" if packet[ICMP].type == 8 else "ICMP Echo Reply"
        elif ARP in packet:
            info['protocol'] = 'ARP'
            # Look up operation (1=who-has request, 2=is-at reply)
            op = "who-has" if packet[ARP].op == 1 else "is-at"
            info['src'] = packet[ARP].psrc
            info['dst'] = packet[ARP].pdst
            info['info'] = f"ARP: {op} {packet[ARP].psrc} -> {packet[ARP].pdst} MAC: {packet[ARP].hwsrc}"

        # Thread-safe write
        with self.lock:
            self.packets.append(info)
            if len(self.packets) > self.max_buffer:
                self.packets.pop(0)

    def run_sniff(self):
        try:
            # Attempt to capture real network packets
            sniff(prn=self.packet_callback, stop_filter=lambda p: not self.active, store=False, timeout=1)
            # Scapy sniff stops if timeout is hit, so loop while active
            while self.active:
                sniff(prn=self.packet_callback, stop_filter=lambda p: not self.active, store=False, timeout=2)
        except Exception as e:
            logger.warning(f"Real packet sniffing failed: {e}. Falling back to mock capture.")
            self.is_mock = True
            self.run_mock_sniff()

    def run_mock_sniff(self):
        mock_ips = [
            "192.168.1.10", "192.168.1.15", "192.168.1.1", 
            "8.8.8.8", "1.1.1.1", "10.0.0.45", "10.0.0.1"
        ]
        
        # Scenarios we can inject for dynamic threat detection to analyze
        threat_scenario_count = 0
        scenario_active = None
        scenario_attacker = None
        scenario_target = None
        
        while self.active:
            time.sleep(random.uniform(0.1, 0.4))
            
            # Periodically start threat scenarios to test the dynamic threat detector
            if not scenario_active and random.random() < 0.05:
                # Trigger a threat scenario
                scenario_active = random.choice(['ddos', 'portscan', 'bruteforce', 'arp_spoof'])
                scenario_attacker = f"192.168.1.{random.randint(200, 250)}"
                scenario_target = "192.168.1.1" if scenario_active != 'ddos' else "8.8.8.8"
                threat_scenario_count = 0
                logger.info(f"Mocking threat scenario: {scenario_active} from {scenario_attacker}")

            # Generate packet based on current scenario or normal traffic
            info = {
                'src': None,
                'dst': None,
                'protocol': 'Other',
                'info': '',
                'length': random.randint(40, 1500)
            }

            if scenario_active == 'ddos':
                # DDoS is sending huge volume of packets
                info['src'] = scenario_attacker
                info['dst'] = scenario_target
                info['protocol'] = 'UDP'
                info['info'] = f"Port: {random.randint(1024, 65535)}->53 | DNS Query"
                threat_scenario_count += 1
                if threat_scenario_count >= 80:  # End scenario
                    scenario_active = None
            
            elif scenario_active == 'portscan':
                # Portscan scans incrementing ports
                info['src'] = scenario_attacker
                info['dst'] = scenario_target
                info['protocol'] = 'TCP'
                scanned_port = 20 + threat_scenario_count
                info['info'] = f"Port: {random.randint(1024, 65535)}->{scanned_port} | TCP Syn"
                threat_scenario_count += 1
                if threat_scenario_count >= 20:
                    scenario_active = None

            elif scenario_active == 'bruteforce':
                # Brute force targets port 22 or 3389 repeatedly
                info['src'] = scenario_attacker
                info['dst'] = scenario_target
                info['protocol'] = 'TCP'
                info['info'] = f"Port: {random.randint(1024, 65535)}->22 | TCP Syn (Auth attempt)"
                threat_scenario_count += 1
                if threat_scenario_count >= 25:
                    scenario_active = None
            
            elif scenario_active == 'arp_spoof':
                # ARP spoofing broadcasts claiming mapping
                info['protocol'] = 'ARP'
                fake_ip = "192.168.1.1" # Gateway
                fake_mac = "a0:b1:c2:d3:e4:f5"
                info['src'] = fake_ip
                info['dst'] = "192.168.1.15"
                info['info'] = f"ARP: is-at {fake_ip} -> 192.168.1.15 MAC: {fake_mac}"
                threat_scenario_count += 1
                if threat_scenario_count >= 10:
                    scenario_active = None
            
            else:
                # Normal network traffic
                src = random.choice(mock_ips)
                dst = random.choice([ip for ip in mock_ips if ip != src])
                info['src'] = src
                info['dst'] = dst
                
                proto = random.choices(['TCP', 'UDP', 'ICMP', 'ARP'], weights=[50, 30, 10, 10])[0]
                info['protocol'] = proto
                
                if proto == 'TCP':
                    sport = random.randint(1024, 65535)
                    dport = random.choice([80, 443, 22, 8080])
                    info['info'] = f"Port: {sport}->{dport}"
                elif proto == 'UDP':
                    sport = random.randint(1024, 65535)
                    dport = random.choice([53, 123, 443])
                    if dport == 53:
                        domain = random.choice(['google.com', 'github.com', 'microsoft.com', 'openai.com', 'amazon.com'])
                        info['info'] = f"Port: {sport}->{dport} | Domain: {domain} | DNS Query"
                    else:
                        info['info'] = f"Port: {sport}->{dport}"
                elif proto == 'ICMP':
                    info['info'] = random.choice(["ICMP Echo Request", "ICMP Echo Reply"])
                elif proto == 'ARP':
                    psrc = random.choice(["192.168.1.1", "192.168.1.10", "192.168.1.15"])
                    pdst = random.choice(["192.168.1.10", "192.168.1.15", "192.168.1.20"])
                    info['src'] = psrc
                    info['dst'] = pdst
                    info['info'] = f"ARP: who-has {psrc} -> {pdst} MAC: 00:11:22:33:44:55"

            with self.lock:
                self.packets.append(info)
                if len(self.packets) > self.max_buffer:
                    self.packets.pop(0)

    def start(self):
        with self.lock:
            if self.active:
                return False
            self.active = True
            self.is_mock = False
            self.packets = []
            
        self.thread = threading.Thread(target=self.run_sniff, daemon=True)
        self.thread.start()
        return True

    def stop(self):
        with self.lock:
            if not self.active:
                return False
            self.active = False
        return True

    def get_packets(self):
        with self.lock:
            return list(self.packets)

    def clear(self):
        with self.lock:
            self.packets = []

    def is_active(self):
        with self.lock:
            return self.active
