# SentinelSOC Pro

SentinelSOC Pro is a SIEM-style SOC monitoring platform built using Python and Flask.  
It provides multi-log monitoring, attack detection, event correlation, threat intelligence enrichment, and incident response workflows.

---

# Features

• Real-time SOC Dashboard  
• Multi-log monitoring (auth.log, apache.log, firewall.log)  
• SSH brute-force detection  
• Web attack detection  
• Firewall deny monitoring  
• Cross-source attack correlation  
• MITRE ATT&CK technique mapping  
• Threat Intelligence view  
• IOC Watchlist management  
• Blocklist export  
• Incident management workflow  
• Analyst notes and timeline  
• CSV / JSON report export  
• Telegram test alerts  
• Docker deployment support  

---

# Supported Log Sources

SentinelSOC currently supports:

- auth.log (Linux authentication logs)
- apache.log (web server logs)
- firewall.log (UFW / firewall events)

---

# Project Structure

```
SentinelSOC-Pro
│
├── app.py
├── SentinelSOC_Pro.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── start.sh
├── reset_runtime.sh
│
├── templates/
├── static/
├── logs/
├── alerts/
├── sample_logs/
│
└── README.md
```

---

# Installation

Clone the repository

```bash
git clone https://github.com/Nowfir0369/SentinelSoc---Pro.git
cd SentinelSoc---Pro
```

Create virtual environment

```bash
python3 -m venv venv
```

Activate environment

```bash
source venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run SentinelSOC

```bash
./start.sh
```

Open browser

```
http://127.0.0.1:5000
```

---

# Load Sample Logs

You can load example attack logs for testing.

```
cp sample_logs/auth.log logs/auth.log
cp sample_logs/apache.log logs/apache.log
cp sample_logs/firewall.log logs/firewall.log
```

Restart tool:

```
./start.sh
```

---

# Reset Runtime Data

```
./reset_runtime.sh
```

This clears alerts, incidents, and logs.

---

# Docker Deployment

```
docker compose up --build
```

---

# SOC Workflow

SentinelSOC follows a simplified SOC workflow:

1. Log ingestion
2. Event parsing
3. Alert detection
4. Attack correlation
5. Threat enrichment
6. Analyst investigation
7. Incident management

---

# Author

Built by Nowfir
