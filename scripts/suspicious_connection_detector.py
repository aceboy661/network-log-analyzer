# Suspicious Connection Detector
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

        # Count how many times each IP appears
        ip_counter = Counter()
        for line in connections:
            if " from " in line:
                parts = line.split(" from ")
                if len(parts) > 1:
                    ip = parts[1].split(" ")[0]
                    ip_counter[ip] += 1

        print("\nRepeated Connections from same IP:")
        alerts = 0
        for ip, count in ip_counter.items():
            if count >= 4:
                print(f"- {ip} → {count} connections")
                alerts += 1

        print("\nConnections to unusual ports:")
        for line in connections:
            for port in unusual_ports:
                if f"port {port}" in line or f":{port}" in line:
                    print(f"- {line}")
                    alerts += 1

        print("\n" + "-" * 55)
        if alerts > 0:
            print("ALERT: Suspicious network activity detected!")
        else:
            print("Status: No strong suspicious activity found.")
        print("=" * 55)

    except FileNotFoundError:
        print("Error: Log file not found.")

detect_suspicious_connections("logs/sample_network.log")
