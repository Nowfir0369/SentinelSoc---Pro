# SentinelSOC Pro

SentinelSOC Pro is a SIEM-style SOC platform built with Python and Flask for multi-log monitoring, detection, event correlation, threat enrichment, IOC watchlisting, and analyst-driven incident response workflows.

## Core Capabilities

- Real-time SOC dashboard
- Multi-log source ingestion
- Unified event stream
- SSH brute-force detection
- Invalid user enumeration detection
- Suspicious login sequence detection
- Web probe detection from Apache logs
- Firewall deny event monitoring
- Cross-source attack correlation
- MITRE ATT&CK technique mapping
- Threat intelligence enrichment
- IOC watchlist and blocklist export
- Incident assignment and ownership
- Investigation summary and closure notes
- CSV / JSON export
- Telegram and email test alerts
- Docker-ready deployment

## Supported Log Sources

- `auth.log`
- `apache.log`
- `firewall.log`

## Main Modules

- Dashboard
- Events
- Campaigns
- Watchlist
- Alerts
- Incidents
- Threat Intel
- Reports
- Settings

## Project Structure

```text
SentinelSOC-Pro/
├── app.py
├── SentinelSOC_Pro.py
├── run.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── README.md
├── .gitignore
├── .env.example
├── start.sh
├── reset_runtime.sh
├── logs/
├── alerts/
├── sample_logs/
├── static/
└── templates/
