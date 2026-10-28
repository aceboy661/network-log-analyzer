# Improved Suspicious Connection Detector
# Detects repeated connections and unusual ports

from datetime import datetime
from collections import Counter

def detect_suspicious_connections(log_file):
    connections = []
    unusual_ports = ["4444", "5555", "6666", "31337", "12345"]

    try:
        with open(log_file, "r") as file:
            for line in file:
                connections.append(line.strip())

        print("=" * 55)
        print("SUSPICIOUS CONNECTION DETECTION REPORT")
        print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 55)

        # Count connections per IP
        ip_counter = Counter()
        for line in connections:
            if "->" in line:
                try:
                    src = line.split("->")[0].strip().split()[-1]
                    ip = src.split(":")[0]
                    ip_counter[ip] += 1
                except:
                    pass

        print("\n[+] Repeated Connections from same IP:")
        repeated_found = False
        for ip, count in ip_counter.items():
            if count >= 3:
                print(f"  - {ip} → {count} connections")
                repeated_found = True
        if not repeated_found:
            print("  - None detected")

        print("\n[+] Connections to unusual ports:")
        unusual_found = False
        for line in connections:
            for port in unusual_ports:
                if f":{port}" in line or f"port {port}" in line:
                    print(f"  - {line}")
                    unusual_found = True
        if not unusual_found:
            print("  - None detected")

        print("\n" + "-" * 55)
        if repeated_found or unusual_found:
            print("ALERT: Suspicious network activity detected!")
            print("Recommendation: Investigate source IPs and unusual ports.")
        else:
            print("Status: No strong suspicious activity found.")
        print("=" * 55)

    except FileNotFoundError:
        print("Error: Log file not found.")

detect_suspicious_connections("logs/sample_network.log")
