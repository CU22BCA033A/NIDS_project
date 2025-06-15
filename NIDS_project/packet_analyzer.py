from scapy.layers.inet import IP, TCP
from collections import defaultdict
import time
from config import SYN_FLOOD_THRESHOLD, SYN_FLOOD_WINDOW, PORT_SCAN_THRESHOLD
from alert_logger import log_alert

class PacketAnalyzer:
    def __init__(self):
        # Track SYN packets: {src_ip: [(timestamp, packet)]}
        self.syn_packets = defaultdict(list)
        # Track ports scanned: {src_ip: set(port)}
        self.port_scans = defaultdict(set)
        # Track vulnerable port access: {src_ip: {port: count}}
        self.vulnerable_ports = defaultdict(lambda: defaultdict(int))
        # Track spam behavior: {src_ip: {port: [(timestamp, packet)]}}
        self.spam_attempts = defaultdict(lambda: defaultdict(list))
        # Common vulnerable ports
        self.VULNERABLE_PORTS = {445, 3389, 1433, 23, 21}  # SMB, RDP, MSSQL, Telnet, FTP
        # Spam threshold: 5 packets to same port in 5 seconds
        self.SPAM_THRESHOLD = 5
        self.SPAM_WINDOW = 5

    def analyze_packet(self, packet):
        """
        Analyze a single packet for potential threats.
        
        Args:
            packet: Scapy packet object
        """
        print(f"Captured packet: {packet.summary()}")  # Debug
        if packet.haslayer(TCP) and packet.haslayer(IP):  # Ensure IP and TCP layers exist
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            protocol = "TCP"
            current_time = time.time()

            print(f"Processing packet from {src_ip} to {dst_ip}:{dst_port}, flags: {flags}")  # Debug

            # Detect SYN flood
            if flags & 0x02:  # SYN flag
                self.syn_packets[src_ip].append((current_time, packet))
                print(f"SYN packet from {src_ip}, count: {len(self.syn_packets[src_ip])}")  # Debug
                # Clean old packets
                self.syn_packets[src_ip] = [
                    pkt for pkt in self.syn_packets[src_ip]
                    if current_time - pkt[0] <= SYN_FLOOD_WINDOW
                ]
                syn_count = len(self.syn_packets[src_ip])
                print(f"Checking SYN flood for {src_ip}: {syn_count} SYN packets in {SYN_FLOOD_WINDOW}s")  # Debug
                if syn_count > SYN_FLOOD_THRESHOLD:
                    message = f"SYN Flood detected from {src_ip}: {syn_count} SYN packets in {SYN_FLOOD_WINDOW}s"
                    details = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "syn_count": syn_count
                    }
                    print(f"Triggering SYN flood alert: {message}")  # Debug
                    log_alert(message, "CRITICAL", details)

            # Detect port scanning
            self.port_scans[src_ip].add(dst_port)
            port_count = len(self.port_scans[src_ip])
            print(f"Ports scanned by {src_ip}: {port_count} (Ports: {self.port_scans[src_ip]})")  # Debug
            if port_count > PORT_SCAN_THRESHOLD:
                message = f"Port Scan detected from {src_ip}: {port_count} unique ports targeted"
                details = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "ports": ", ".join(str(p) for p in self.port_scans[src_ip]),
                    "protocol": protocol,
                    "port_count": port_count
                }
                print(f"Triggering port scan alert: {message}")  # Debug
                log_alert(message, "WARNING", details)
                self.port_scans[src_ip].clear()

            # Detect vulnerable port access
            if dst_port in self.VULNERABLE_PORTS:
                self.vulnerable_ports[src_ip][dst_port] += 1
                vuln_count = self.vulnerable_ports[src_ip][dst_port]
                print(f"Vulnerable port {dst_port} accessed by {src_ip}, count: {vuln_count}")  # Debug
                if vuln_count == 1:  # Alert on first access
                    message = f"Vulnerable port access detected from {src_ip} to port {dst_port}"
                    details = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "vuln_count": vuln_count
                    }
                    print(f"Triggering vulnerable port alert: {message}")  # Debug
                    log_alert(message, "WARNING", details)

            # Detect spam-like behavior
            self.spam_attempts[src_ip][dst_port].append((current_time, packet))
            # Clean old packets
            self.spam_attempts[src_ip][dst_port] = [
                pkt for pkt in self.spam_attempts[src_ip][dst_port]
                if current_time - pkt[0] <= self.SPAM_WINDOW
            ]
            spam_count = len(self.spam_attempts[src_ip][dst_port])
            print(f"Checking spam for {src_ip} on port {dst_port}: {spam_count} packets in {self.SPAM_WINDOW}s")  # Debug
            if spam_count > self.SPAM_THRESHOLD:
                message = f"Spam-like behavior detected from {src_ip} to port {dst_port}: {spam_count} packets in {self.SPAM_WINDOW}s"
                details = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "spam_count": spam_count
                }
                print(f"Triggering spam alert: {message}")  # Debug
                log_alert(message, "WARNING", details)
                self.spam_attempts[src_ip][dst_port].clear()

def packet_callback(analyzer):
    """
    Callback function for scapy's sniff.
    
    Args:
        analyzer: PacketAnalyzer instance
    """
    def callback(packet):
        analyzer.analyze_packet(packet)
    return callback