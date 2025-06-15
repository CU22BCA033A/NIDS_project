import logging
from colorama import init, Fore, Style
import uuid
from datetime import datetime

init()  # Initialize colorama for colored console output

def setup_logger():
    """
    Set up the logging configuration with a custom format, clearing the log file.
    """
    # Clear alerts.log by opening in write mode
    with open("alerts.log", "w") as f:
        f.write("")
    
    logging.basicConfig(
        filename="alerts.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - AlertID: %(alert_id)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

def log_alert(message, level, details=None):
    """
    Log an alert to both file and console with appropriate color and details.
    
    Args:
        message (str): The alert message
        level (str): The severity level (INFO, WARNING, CRITICAL)
        details (dict): Optional dictionary with additional details (e.g., src_ip, dst_port, protocol)
    """
    color = {
        "INFO": Fore.GREEN,
        "WARNING": Fore.YELLOW,
        "CRITICAL": Fore.RED
    }.get(level, Fore.WHITE)
    
    # Generate a unique alert ID
    alert_id = str(uuid.uuid4())
    
    # Build detailed message
    detail_str = ""
    if details:
        detail_str = ", ".join(f"{k}: {v}" for k, v in details.items())
        full_message = f"{message} ({detail_str})"
    else:
        full_message = message
    
    # Print to console with color
    print(f"{color}[{level}]{Style.RESET_ALL} AlertID: {alert_id} - {full_message}")
    
    # Log to file with extra fields
    logger = logging.getLogger()
    extra = {"alert_id": alert_id}
    if level == "INFO":
        logger.info(full_message, extra=extra)
    elif level == "WARNING":
        logger.warning(full_message, extra=extra)
    elif level == "CRITICAL":
        logger.critical(full_message, extra=extra)