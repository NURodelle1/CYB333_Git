import socket
import time
from datetime import datetime

# Define the first 1000 ports for option 1
FIRST_1000_PORTS = list(range(1, 1001))

# Prompt for the target host
target_input = input("Enter target host (127.0.0.1 for localhost or 'scanme.nmap.org'): ")
if target_input.lower() == "localhost":
    target_input = "127.0.0.1"
target = target_input  # use 'target' variable for consistency

# Allow only certain targets (for safety and compliance)
allowed_targets = ["127.0.0.1", "scanme.nmap.org"]
if target not in allowed_targets:
    print("Error: Target not allowed. Please use 127.0.0.1 (localhost) or scanme.nmap.org.")
    exit(1)

# Resolve the target host to an IP address (important for 'scanme.nmap.org')
try:
    target_ip = socket.gethostbyname(target)
except socket.gaierror as e:
    print(f"Error: Unable to resolve host '{target}' -> {e}")
    exit(1)

# Menu options
print("\nScan Menu:")
print("1. Scan first 1000 ports (1-1000)", flush=True)
print("2. Scan multiple ports (range or comma-separated list)", flush=True)
print("3. Scan a single port", flush=True)

choice = input("Enter your choice (1, 2, or 3): ").strip()

ports_to_scan = []  # list of ports to scan based on choice

if choice == '1':
    # Option 1: First 1000 ports (commonly used ports)
    ports_to_scan = FIRST_1000_PORTS
    print("Selected ports 1-1000 (first 1000 ports)")
elif choice == '2':
    # Option 2: Multiple ports (range or list)
    ports_range_input = input("Enter port range or list (e.g., 20-25 or 22,80,443): ").strip()
    try:
        if '-' in ports_range_input:
            # e.g., "20-25" (range input)
            start_str, end_str = ports_range_input.split('-')
            start_port = int(start_str.strip())
            end_port = int(end_str.strip())
            if start_port > end_port:
                # If the start is greater than the end, swap them
                start_port, end_port = end_port, start_port
            ports_to_scan = list(range(start_port, end_port + 1))
        elif ',' in ports_range_input:
            # e.g., "22,80,443" (list of ports)
            parts = ports_range_input.split(',')
            for part in parts:
                part = part.strip()
                if part == "":  # skip empty entries from something like "80,443,"
                    continue
                ports_to_scan.append(int(part))
        else:
            # Single port provided in a scenario they chose option 2
            ports_to_scan = [int(ports_range_input.strip())]
    except ValueError:
        print("Error: Invalid format for ports. Use a number, a range (e.g., 10-20), or a comma-separated list (e.g., 80,443).")
        exit(1)
    ports_to_scan = sorted(set(ports_to_scan))  # remove duplicates and sort
    print("Selected ports:", ports_to_scan)
elif choice == '3':
    # Option 3: Single port
    port_str = input("Enter a single port to scan: ").strip()
    try:
        single_port = int(port_str)
    except ValueError:
        print("Error: Invalid port number. Please enter a valid integer.")
        exit(1)
    ports_to_scan = [single_port]
    print("Selected port:", single_port)
else:
    print("Error: Invalid menu choice. Please restart and choose 1, 2, or 3.")
    exit(1)

# Validate port numbers range
for p in ports_to_scan:
    if p < 1 or p > 65535:
        print(f"Error: Port number {p} is out of valid range (1-65535).")
        exit(1)

# Begin scanning
print(f"\nStarting scan on host {target} (IP: {target_ip})...")
start_time = datetime.now()
print("Scan started at:", start_time.strftime("%Y-%m-%d %H:%M:%S"))

open_ports = []
closed_ports = []

for port in ports_to_scan:
    print(f"Scanning port {port}...", flush=True)  # debug output to trace progress
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)  # short timeout for faster scanning
    result = sock.connect_ex((target_ip, port))
    if result == 0:
        print(f"Port {port} is OPEN")
        open_ports.append(port)
    else:
        print(f"Port {port} is closed")
        closed_ports.append(port)
    sock.close()
    time.sleep(0.2)  # delay between scans to avoid overloading the network

end_time = datetime.now()
duration = end_time - start_time

# Summary of results
print("\nScan completed at:", end_time.strftime("%Y-%m-%d %H:%M:%S"))
print("Duration:", duration)
print(f"Total ports scanned: {len(ports_to_scan)}")
print(f"Open ports: {open_ports if open_ports else 'None'}")
print(f"Closed ports: {len(closed_ports)} out of {len(ports_to_scan)} ports were closed.")
