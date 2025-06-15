# Configuration settings for the NIDS
# Threshold for detecting SYN flood (number of SYN packets in a time window)
SYN_FLOOD_THRESHOLD = 5
SYN_FLOOD_WINDOW = 10  # Time window in seconds

# Threshold for detecting port scanning (unique ports targeted by a single IP)
PORT_SCAN_THRESHOLD = 3

# Network interface to monitor (e.g., 'eth0' on Linux, 'Wi-Fi' on Windows)
# Set to "Wi-Fi"  to let Scapy choose the wifi interface
INTERFACE = "Wi-Fi"  # Verify

# Log file for alerts
LOG_FILE = "alerts.log"