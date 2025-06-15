from scapy.all import sniff
from packet_analyzer import PacketAnalyzer, packet_callback
from alert_logger import setup_logger, log_alert
from config import INTERFACE
import time

def main():
    # Set up logging
    setup_logger()
    log_alert("Testing logging functionality", "INFO")  # Test logging
    
    # Initialize analyzer
    analyzer = PacketAnalyzer()
    
    # Start sniffing
    print("Starting NIDS... Press Ctrl+C to stop.")
    try:
        sniff(iface=INTERFACE, prn=packet_callback(analyzer), store=0)
    except KeyboardInterrupt:
        print("\nStopping NIDS...")
    except Exception as e:
        print(f"Error during sniffing: {e}")

if __name__ == "__main__":
    main()