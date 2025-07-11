import re
from collections import defaultdict
from datetime import datetime, timedelta
import sys  # Import the sys module

def parse_log_line(log_line):
    """Extracts timestamp, log level, and message from a log line."""
    print(f"Parsing line: '{log_line.strip()}'")  # Debug print - strip whitespace
    match = re.match(r'\[(.*?)\]\s*(\w+):\s*(.*)', log_line)
    if match:
        timestamp_str = match.group(1)
        #level = match.group(2)
        message = match.group(3)
        try:
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            timestamp = None  # Handle cases where timestamp format is incorrect
            print(f"  Error parsing timestamp: {timestamp_str}") # Debug print
        print(f"  Parsed: timestamp={timestamp}, message='{message}'")  # Debug print
        return timestamp, message
    else:
        print("  No match found for the log line format.")  # Debug print
        return None, None

def detect_failed_logins(log_entries, failed_login_attempts, threshold=3, timeframe=timedelta(minutes=5)):
    """Detects multiple failed login attempts from the same IP within a given timeframe."""
    for timestamp, message in log_entries:
        if timestamp:  # Only process entries with valid timestamps
            match = re.search(r'Authentication failed for user .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
            if match:
                ip_address = match.group(1)
                if ip_address:
                    print(f"  Failed login attempt detected from IP: {ip_address} at {timestamp}")  # Debug print
                    failed_login_attempts.setdefault(ip_address, []).append(timestamp)
                    failed_login_attempts[ip_address] = [
                        t for t in failed_login_attempts[ip_address] if timestamp - t < timeframe
                    ]  # Keep only recent attempts
                if len(failed_login_attempts[ip_address]) >= threshold:
                    alert_message = f"[{timestamp}] ALERT: Multiple failed login attempts detected from IP: {ip_address}"
                    print(alert_message)
                    sys.stdout.flush()  # Ensure output is printed immediately
                    failed_login_attempts[ip_address] = []  # Reset to avoid repeated alerts

ATTACK_KEYWORDS = ["SQL injection", "XSS", "port scan", "buffer overflow", "directory traversal"]
def detect_attack_keywords(log_entries):
    """Detects attack keywords in log messages."""
    for timestamp, message in log_entries:
        if timestamp:  # Only process entries with valid timestamps
            for keyword in ATTACK_KEYWORDS:
                if keyword.lower() in message.lower():
                    alert_message = f"[{timestamp}] ALERT: Potential threat keyword detected: {keyword} - {message}"
                    print(f"  Keyword '{keyword}' found in message: '{message}' at {timestamp}") # Debug print
                    print(alert_message)
                    sys.stdout.flush()  # Ensure output is printed immediately
def main(log_file_path):
    """Reads the log file, parses entries, and detects failed logins and attack keywords."""
    try:
        with open(log_file_path, 'r') as f:
            print(f"Successfully opened log file: {log_file_path}") # Debug print
            log_entries = []
            for line in f:
                line = line.strip()  # Ensure no extra whitespace issues
                timestamp, message = parse_log_line(line)
                if timestamp and message:
                    log_entries.append((timestamp, message))
            print(f"Total log entries processed: {len(log_entries)}") # Debug print
            failed_login_attempts = defaultdict(list)
            detect_failed_logins(log_entries, failed_login_attempts)
            detect_attack_keywords(log_entries)  # Detect keywords
    except FileNotFoundError:
        print(f"Error: Log file '{log_file_path}' not found.")
        sys.stdout.flush()
    except Exception as e:  # Catch any other potential errors
        print(f"An unexpected error occurred: {e}")
        sys.stdout.flush()
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python log_parser.py <log_file_path>")
    else:
        log_file_path = sys.argv[1]
        main(log_file_path)
