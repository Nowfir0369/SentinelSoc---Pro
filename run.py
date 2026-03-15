import re
import json
from collections import defaultdict

log_file = "logs/auth.log"

pattern = r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"

ip_counter = defaultdict(int)
alerts = []

try:
    with open(log_file, "r") as file:
        for line in file:
            match = re.search(pattern, line)
            if match:
                ip = match.group(1)
                ip_counter[ip] += 1
except FileNotFoundError:
    pass

for ip, count in ip_counter.items():
    if count >= 10:
        severity = "CRITICAL"
    elif count >= 5:
        severity = "HIGH"
    elif count >= 3:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    if count >= 3:
        alert = {
            "source_ip": ip,
            "alert_type": "Brute Force Login Attempt",
            "failed_attempts": count,
            "severity": severity,
            "status": "Open"
        }
        alerts.append(alert)

report = {
    "total_alerts": len(alerts),
    "top_attacker": max(ip_counter, key=ip_counter.get) if ip_counter else "None",
    "alerts": alerts
}

with open("alerts/alerts.json", "w") as out:
    json.dump(report, out, indent=4)

print("SentinelSOC scan completed.")
