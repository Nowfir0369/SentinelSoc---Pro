from flask import Flask, render_template, request, redirect, send_file, jsonify
import json
import os
import re
import csv
import io
import ipaddress
import threading
import webbrowser
from datetime import datetime
import requests
import smtplib
from email.mime.text import MIMEText

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except Exception:
    WATCHDOG_AVAILABLE = False

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_FILE = os.path.join(BASE_DIR, "logs", "auth.log")
APACHE_LOG_FILE = os.path.join(BASE_DIR, "logs", "apache.log")
FIREWALL_LOG_FILE = os.path.join(BASE_DIR, "logs", "firewall.log")

ALERT_FILE = os.path.join(BASE_DIR, "alerts", "alerts.json")
EVENT_FILE = os.path.join(BASE_DIR, "alerts", "events.json")
CORRELATION_FILE = os.path.join(BASE_DIR, "alerts", "correlations.json")
WATCHLIST_FILE = os.path.join(BASE_DIR, "alerts", "watchlist.json")
INCIDENT_FILE = os.path.join(BASE_DIR, "alerts", "incidents.json")
SETTINGS_FILE = os.path.join(BASE_DIR, "alerts", "settings.json")
GEO_CACHE_FILE = os.path.join(BASE_DIR, "alerts", "geo_cache.json")
ALERT_STATE_FILE = os.path.join(BASE_DIR, "alerts", "alert_state.json")

observer = None


def ensure_files():
    os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "alerts"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "static"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "static", "sounds"), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "templates"), exist_ok=True)

    defaults = {
        ALERT_FILE: {"total_alerts": 0, "top_attacker": "None", "alerts": [], "last_scan": "N/A"},
        EVENT_FILE: {"total_events": 0, "events": [], "last_scan": "N/A"},
        CORRELATION_FILE: {"total_campaigns": 0, "campaigns": [], "last_scan": "N/A"},
        WATCHLIST_FILE: {"items": []},
        INCIDENT_FILE: [],
        GEO_CACHE_FILE: {},
        ALERT_STATE_FILE: {},
        SETTINGS_FILE: {
            "auto_refresh_enabled": True,
            "refresh_seconds": 5,
            "theme": "dark",
            "auto_open_browser": True,
            "telegram_enabled": False,
            "telegram_bot_token": "",
            "telegram_chat_id": "",
            "email_enabled": False,
            "smtp_host": "",
            "smtp_port": 587,
            "smtp_username": "",
            "smtp_password": "",
            "email_to": "",
            "siren_enabled": True,
            "siren_seconds": 5,
            "custom_siren_file": "default_alarm.mp3",
            "abuseipdb_enabled": False,
            "abuseipdb_api_key": "",
            "virustotal_enabled": False,
            "virustotal_api_key": "",
            "otx_enabled": False,
            "otx_api_key": ""
        }
    }

    for log_path in [LOG_FILE, APACHE_LOG_FILE, FIREWALL_LOG_FILE]:
        if not os.path.exists(log_path):
            with open(log_path, "w", encoding="utf-8") as f:
                f.write("")

    for path, default in defaults.items():
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(default, f, indent=4)


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def load_alerts():
    return load_json(ALERT_FILE, {"total_alerts": 0, "top_attacker": "None", "alerts": [], "last_scan": "N/A"})


def load_events():
    return load_json(EVENT_FILE, {"total_events": 0, "events": [], "last_scan": "N/A"})


def load_correlations():
    return load_json(CORRELATION_FILE, {"total_campaigns": 0, "campaigns": [], "last_scan": "N/A"})


def load_watchlist():
    return load_json(WATCHLIST_FILE, {"items": []})


def load_incidents():
    return load_json(INCIDENT_FILE, [])


def load_settings():
    return load_json(
        SETTINGS_FILE,
        {
            "auto_refresh_enabled": True,
            "refresh_seconds": 5,
            "theme": "dark",
            "auto_open_browser": True,
            "telegram_enabled": False,
            "telegram_bot_token": "",
            "telegram_chat_id": "",
            "email_enabled": False,
            "smtp_host": "",
            "smtp_port": 587,
            "smtp_username": "",
            "smtp_password": "",
            "email_to": "",
            "siren_enabled": True,
            "siren_seconds": 5,
            "custom_siren_file": "default_alarm.mp3",
            "abuseipdb_enabled": False,
            "abuseipdb_api_key": "",
            "virustotal_enabled": False,
            "virustotal_api_key": "",
            "otx_enabled": False,
            "otx_api_key": ""
        }
    )


def load_geo_cache():
    return load_json(GEO_CACHE_FILE, {})


def load_alert_state():
    return load_json(ALERT_STATE_FILE, {})


def validate_settings(data):
    try:
        refresh_seconds = int(data.get("refresh_seconds", 5))
    except Exception:
        refresh_seconds = 5
    refresh_seconds = max(2, min(refresh_seconds, 300))

    try:
        smtp_port = int(data.get("smtp_port", 587))
    except Exception:
        smtp_port = 587

    try:
        siren_seconds = int(data.get("siren_seconds", 5))
    except Exception:
        siren_seconds = 5
    siren_seconds = max(1, min(siren_seconds, 30))

    theme = str(data.get("theme", "dark")).strip().lower()
    if theme not in ["dark", "light"]:
        theme = "dark"

    return {
        "auto_refresh_enabled": bool(data.get("auto_refresh_enabled", True)),
        "refresh_seconds": refresh_seconds,
        "theme": theme,
        "auto_open_browser": bool(data.get("auto_open_browser", True)),
        "telegram_enabled": bool(data.get("telegram_enabled", False)),
        "telegram_bot_token": str(data.get("telegram_bot_token", "")).strip(),
        "telegram_chat_id": str(data.get("telegram_chat_id", "")).strip(),
        "email_enabled": bool(data.get("email_enabled", False)),
        "smtp_host": str(data.get("smtp_host", "")).strip(),
        "smtp_port": smtp_port,
        "smtp_username": str(data.get("smtp_username", "")).strip(),
        "smtp_password": str(data.get("smtp_password", "")).strip(),
        "email_to": str(data.get("email_to", "")).strip(),
        "siren_enabled": bool(data.get("siren_enabled", True)),
        "siren_seconds": siren_seconds,
        "custom_siren_file": str(data.get("custom_siren_file", "default_alarm.mp3")).strip() or "default_alarm.mp3",
        "abuseipdb_enabled": bool(data.get("abuseipdb_enabled", False)),
        "abuseipdb_api_key": str(data.get("abuseipdb_api_key", "")).strip(),
        "virustotal_enabled": bool(data.get("virustotal_enabled", False)),
        "virustotal_api_key": str(data.get("virustotal_api_key", "")).strip(),
        "otx_enabled": bool(data.get("otx_enabled", False)),
        "otx_api_key": str(data.get("otx_api_key", "")).strip()
    }


def send_telegram_message(message):
    settings = load_settings()
    if not settings.get("telegram_enabled"):
        return False, "Telegram disabled"

    token = settings.get("telegram_bot_token", "").strip()
    chat_id = settings.get("telegram_chat_id", "").strip()

    if not token or not chat_id:
        return False, "Missing Telegram bot token or chat ID"

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": message}

    try:
        res = requests.post(url, json=payload, timeout=10)
        if res.status_code == 200:
            return True, "Telegram message sent"
        return False, f"Telegram API error: {res.status_code}"
    except Exception as e:
        return False, f"Telegram send failed: {e}"


def send_email_message(subject, body):
    settings = load_settings()
    if not settings.get("email_enabled"):
        return False, "Email disabled"

    smtp_host = settings.get("smtp_host", "").strip()
    smtp_port = settings.get("smtp_port", 587)
    smtp_username = settings.get("smtp_username", "").strip()
    smtp_password = settings.get("smtp_password", "").strip()
    email_to = settings.get("email_to", "").strip()

    if not smtp_host or not smtp_username or not smtp_password or not email_to:
        return False, "Missing SMTP/email settings"

    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = smtp_username
        msg["To"] = email_to

        server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(smtp_username, [email_to], msg.as_string())
        server.quit()
        return True, "Email sent"
    except Exception as e:
        return False, f"Email send failed: {e}"


def get_ip_geo(ip):
    cache = load_geo_cache()
    if ip in cache:
        return cache[ip]

    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            data = {
                "country": "Internal Network",
                "city": "Local",
                "lat": None,
                "lon": None,
                "isp": "Private IP",
                "ip_type": "Private/Internal"
            }
            cache[ip] = data
            save_json(GEO_CACHE_FILE, cache)
            return data
    except Exception:
        pass

    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = res.json()

        if data.get("status") == "success":
            result = {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp", "Unknown"),
                "ip_type": "Public/External"
            }
        else:
            result = {
                "country": "Unknown",
                "city": "Unknown",
                "lat": None,
                "lon": None,
                "isp": "Unknown",
                "ip_type": "Unknown"
            }
    except Exception:
        result = {
            "country": "Unknown",
            "city": "Unknown",
            "lat": None,
            "lon": None,
            "isp": "Unknown",
            "ip_type": "Unknown"
        }

    cache[ip] = result
    save_json(GEO_CACHE_FILE, cache)
    return result


def get_ip_reputation(ip):
    settings = load_settings()

    if not settings.get("abuseipdb_enabled"):
        return {"reputation": "Monitor", "reputation_score": 0, "reputation_source": "Local Engine"}

    api_key = settings.get("abuseipdb_api_key", "").strip()
    if not api_key:
        return {"reputation": "Monitor", "reputation_score": 0, "reputation_source": "Local Engine"}

    try:
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        res = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=10)

        if res.status_code != 200:
            return {"reputation": "Monitor", "reputation_score": 0, "reputation_source": "Local Engine"}

        data = res.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))

        if score >= 75:
            rep = "High Risk"
        elif score >= 40:
            rep = "Suspicious"
        else:
            rep = "Monitor"

        return {"reputation": rep, "reputation_score": score, "reputation_source": "AbuseIPDB"}
    except Exception:
        return {"reputation": "Monitor", "reputation_score": 0, "reputation_source": "Local Engine"}


def classify_severity(count):
    if count >= 10:
        return "CRITICAL"
    if count >= 5:
        return "HIGH"
    if count >= 3:
        return "MEDIUM"
    return "LOW"


def severity_rank(severity):
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(severity, 1)


def classify_alert_type(line):
    lowered = line.lower()

    if "failed password" in lowered:
        return "Brute Force Login Attempt"
    if "invalid user" in lowered:
        return "Invalid User Enumeration"
    if "authentication failure" in lowered:
        return "Authentication Failure"
    if "accepted password" in lowered:
        return "Successful SSH Login"
    if "sudo:" in lowered:
        return "Privileged Command Execution"
    if "wp-login" in lowered or "/admin" in lowered or "select%20" in lowered or "union%20" in lowered:
        return "Suspicious Web Probe"
    if "drop" in lowered or "denied" in lowered:
        return "Firewall Drop Event"

    return "Security Event"


def mitre_mapping(alert_type):
    mapping = {
        "Brute Force Login Attempt": {"technique_id": "T1110", "technique_name": "Brute Force"},
        "Invalid User Enumeration": {"technique_id": "T1589", "technique_name": "Gather Victim Identity Information"},
        "Authentication Failure": {"technique_id": "T1110", "technique_name": "Brute Force"},
        "Successful SSH Login": {"technique_id": "T1078", "technique_name": "Valid Accounts"},
        "Privileged Command Execution": {"technique_id": "T1548", "technique_name": "Abuse Elevation Control Mechanism"},
        "Suspicious Login Sequence": {"technique_id": "T1078", "technique_name": "Valid Accounts"},
        "Suspicious Web Probe": {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"},
        "Firewall Drop Event": {"technique_id": "T1046", "technique_name": "Network Service Discovery"},
        "Multi-Source Attack Correlation": {"technique_id": "T1595", "technique_name": "Active Scanning"}
    }
    return mapping.get(alert_type, {"technique_id": "N/A", "technique_name": "Unmapped"})


def anomaly_engine(ip, count, geo, alert_types, sources):
    score = 0
    reasons = []

    if count >= 10:
        score += 45
        reasons.append("High event burst from source IP")
    elif count >= 5:
        score += 25
        reasons.append("Repeated events from source IP")
    elif count >= 3:
        score += 10
        reasons.append("Repeated suspicious pattern observed")

    if geo.get("ip_type") == "Public/External":
        score += 15
        reasons.append("External source IP")

    country = geo.get("country", "Unknown")
    if country not in ["Internal Network", "Unknown", "India"]:
        score += 20
        reasons.append("Unexpected geolocation")

    if len(sources) >= 2:
        score += 20
        reasons.append("Activity correlated across multiple log sources")

    if "Successful SSH Login" in alert_types and count >= 3:
        score += 20
        reasons.append("Success observed after repeated failures")

    if "Suspicious Web Probe" in alert_types:
        score += 15
        reasons.append("Suspicious web probing activity observed")

    if "Firewall Drop Event" in alert_types:
        score += 10
        reasons.append("Firewall denies linked to same source IP")

    if score >= 70:
        level = "ANOMALOUS"
    elif score >= 40:
        level = "SUSPICIOUS"
    else:
        level = "NORMAL"

    return score, level, reasons


def normalize_event(timestamp, source_ip, event_type, source, severity, raw, service="", extra=None):
    event_id = f"{source}-{source_ip}-{abs(hash(raw))}"
    return {
        "id": event_id,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "event_type": event_type,
        "source": source,
        "service": service,
        "severity": severity,
        "raw": raw,
        "extra": extra or {}
    }


def parse_auth_events():
    events = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                raw = line.strip()

                failed = re.search(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)", raw, re.IGNORECASE)
                invalid = re.search(r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)", raw, re.IGNORECASE)
                authfail = re.search(r"authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)", raw, re.IGNORECASE)
                accepted = re.search(r"Accepted password.*from (\d+\.\d+\.\d+\.\d+)", raw, re.IGNORECASE)

                ip = None
                event_type = None
                severity = "LOW"

                if failed:
                    ip = failed.group(1)
                    event_type = "Brute Force Login Attempt"
                    severity = "MEDIUM"
                elif invalid:
                    ip = invalid.group(1)
                    event_type = "Invalid User Enumeration"
                    severity = "MEDIUM"
                elif authfail:
                    ip = authfail.group(1)
                    event_type = "Authentication Failure"
                    severity = "MEDIUM"
                elif accepted:
                    ip = accepted.group(1)
                    event_type = "Successful SSH Login"
                    severity = "HIGH"

                if ip and event_type:
                    events.append(normalize_event(
                        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        source_ip=ip,
                        event_type=event_type,
                        source="auth.log",
                        service="ssh",
                        severity=severity,
                        raw=raw
                    ))
    except Exception:
        pass
    return events


def parse_apache_events():
    events = []
    suspicious_keywords = ["/admin", "wp-login", "xmlrpc", "select%20", "union%20", "../", "/phpmyadmin"]

    try:
        with open(APACHE_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                raw = line.strip()
                ip_match = re.match(r"^(\d+\.\d+\.\d+\.\d+)", raw)
                req_match = re.search(r"\"(GET|POST|HEAD|PUT|DELETE)\s+(.+?)\s+HTTP", raw)
                status_match = re.search(r"\"\s+(\d{3})\s+", raw)

                if not ip_match:
                    continue

                ip = ip_match.group(1)
                path = req_match.group(2) if req_match else "/"
                status = int(status_match.group(1)) if status_match else 200

                lowered = path.lower()
                suspicious = any(k in lowered for k in suspicious_keywords) or status in [401, 403, 404]

                if suspicious:
                    events.append(normalize_event(
                        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        source_ip=ip,
                        event_type="Suspicious Web Probe",
                        source="apache.log",
                        service="apache",
                        severity="MEDIUM" if status in [401, 403, 404] else "HIGH",
                        raw=raw,
                        extra={"path": path, "status": status}
                    ))
    except Exception:
        pass
    return events


def parse_firewall_events():
    events = []
    try:
        with open(FIREWALL_LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                raw = line.strip()
                src_match = re.search(r"SRC=(\d+\.\d+\.\d+\.\d+)", raw)
                denied_match = re.search(r"Denied.*?from\s+(\d+\.\d+\.\d+\.\d+)", raw, re.IGNORECASE)

                ip = None
                if src_match:
                    ip = src_match.group(1)
                elif denied_match:
                    ip = denied_match.group(1)

                if ip:
                    events.append(normalize_event(
                        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        source_ip=ip,
                        event_type="Firewall Drop Event",
                        source="firewall.log",
                        service="firewall",
                        severity="LOW",
                        raw=raw
                    ))
    except Exception:
        pass
    return events


def build_alert_summary_from_events(events):
    summary = []
    type_counter = {}

    for item in events:
        event_type = item.get("event_type", "Security Event")
        type_counter[event_type] = type_counter.get(event_type, 0) + 1

    for event_type, count in type_counter.items():
        summary.append(f"{count} event(s): {event_type}")

    if not summary:
        summary.append("No enriched summary available")

    return summary


def build_correlations(events):
    ip_groups = {}
    campaigns = []

    for event in events:
        ip = event.get("source_ip")
        ip_groups.setdefault(ip, []).append(event)

    for ip, items in ip_groups.items():
        if len(items) < 4:
            continue

        sources = sorted(list({e.get("source", "unknown") for e in items}))
        event_types = sorted(list({e.get("event_type", "Security Event") for e in items}))
        severities = [e.get("severity", "LOW") for e in items]
        highest_severity = max(severities, key=severity_rank)

        correlation_score = 0
        reasons = []

        if len(sources) >= 2:
            correlation_score += 35
            reasons.append("Same source IP observed across multiple log sources")

        if len(event_types) >= 2:
            correlation_score += 25
            reasons.append("Multiple suspicious event types linked to same source IP")

        if "Brute Force Login Attempt" in event_types and "Successful SSH Login" in event_types:
            correlation_score += 20
            reasons.append("Failed-to-successful login progression detected")

        if "Suspicious Web Probe" in event_types and "Firewall Drop Event" in event_types:
            correlation_score += 20
            reasons.append("Web probing linked with firewall denies")

        if len(items) >= 8:
            correlation_score += 10
            reasons.append("High event volume in correlated campaign")

        if correlation_score >= 70:
            campaign_level = "CRITICAL"
        elif correlation_score >= 45:
            campaign_level = "HIGH"
        else:
            campaign_level = "MEDIUM"

        campaigns.append({
            "id": f"campaign-{ip}",
            "source_ip": ip,
            "event_count": len(items),
            "sources": sources,
            "event_types": event_types,
            "highest_severity": highest_severity,
            "correlation_score": correlation_score,
            "campaign_level": campaign_level,
            "reasons": reasons,
            "timeline": [f"{e.get('source')} → {e.get('event_type')}" for e in items[:10]]
        })

    campaigns.sort(key=lambda x: (severity_rank(x["campaign_level"]), x["correlation_score"], x["event_count"]), reverse=True)
    return campaigns


def get_matching_raw_logs(ip):
    matches = []
    for path in [LOG_FILE, APACHE_LOG_FILE, FIREWALL_LOG_FILE]:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if ip in line:
                        matches.append(line.strip())
        except Exception:
            pass
    return matches[-120:]


def is_watchlisted(ip):
    watch_items = load_watchlist().get("items", [])
    return any(item.get("ip") == ip for item in watch_items)


def scan_logs():
    auth_events = parse_auth_events()
    apache_events = parse_apache_events()
    firewall_events = parse_firewall_events()

    events = auth_events + apache_events + firewall_events
    events.sort(key=lambda x: (x.get("timestamp", ""), x.get("source", "")), reverse=True)

    save_json(EVENT_FILE, {
        "total_events": len(events),
        "events": events,
        "last_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

    campaigns = build_correlations(events)
    save_json(CORRELATION_FILE, {
        "total_campaigns": len(campaigns),
        "campaigns": campaigns,
        "last_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

    ip_groups = {}
    alert_state = load_alert_state()
    alerts = []

    for event in events:
        ip = event.get("source_ip")
        ip_groups.setdefault(ip, []).append(event)

    for ip, grouped_events in ip_groups.items():
        if len(grouped_events) < 3:
            continue

        geo = get_ip_geo(ip)
        count = len(grouped_events)
        sources = sorted(list({e.get("source", "unknown") for e in grouped_events}))
        event_types = sorted(list({e.get("event_type", "Security Event") for e in grouped_events}))

        primary_alert_type = "Brute Force Login Attempt"
        if len(sources) >= 2:
            primary_alert_type = "Multi-Source Attack Correlation"
        elif "Suspicious Web Probe" in event_types:
            primary_alert_type = "Suspicious Web Probe"
        elif "Successful SSH Login" in event_types and count >= 3:
            primary_alert_type = "Suspicious Login Sequence"
        elif "Invalid User Enumeration" in event_types:
            primary_alert_type = "Invalid User Enumeration"
        elif "Authentication Failure" in event_types:
            primary_alert_type = "Authentication Failure"
        elif "Firewall Drop Event" in event_types:
            primary_alert_type = "Firewall Drop Event"

        max_event_severity = max([severity_rank(e.get("severity", "LOW")) for e in grouped_events], default=1)
        count_based = classify_severity(count)

        severity = count_based
        if max_event_severity > severity_rank(severity):
            severity = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}.get(max_event_severity, count_based)

        anomaly_score, anomaly_level, anomaly_reasons = anomaly_engine(ip, count, geo, event_types, sources)
        state = alert_state.get(ip, {})
        disposition = state.get("disposition", "UNREVIEWED")
        notes = state.get("notes", [])
        mitre = mitre_mapping(primary_alert_type)
        summary = build_alert_summary_from_events(grouped_events)

        matched_campaign = next((c for c in campaigns if c["source_ip"] == ip), None)

        alerts.append({
            "id": ip,
            "source_ip": ip,
            "alert_type": primary_alert_type,
            "all_event_types": event_types,
            "failed_attempts": count,
            "severity": severity,
            "status": "Open",
            "country": geo.get("country"),
            "city": geo.get("city"),
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "isp": geo.get("isp"),
            "ip_type": geo.get("ip_type"),
            "anomaly_score": anomaly_score,
            "anomaly_level": anomaly_level,
            "anomaly_reasons": anomaly_reasons,
            "disposition": disposition,
            "notes": notes,
            "mitre_technique_id": mitre.get("technique_id"),
            "mitre_technique_name": mitre.get("technique_name"),
            "summary": summary,
            "sources": sources,
            "correlation_score": matched_campaign["correlation_score"] if matched_campaign else 0,
            "campaign_level": matched_campaign["campaign_level"] if matched_campaign else "N/A",
            "watchlisted": is_watchlisted(ip)
        })

    alerts.sort(key=lambda x: (x.get("watchlisted", False), severity_rank(x["severity"]), x.get("correlation_score", 0), x["anomaly_score"], x["failed_attempts"]), reverse=True)
    top_attacker = alerts[0].get("source_ip", "None") if alerts else "None"

    save_json(ALERT_FILE, {
        "total_alerts": len(alerts),
        "top_attacker": top_attacker,
        "alerts": alerts,
        "last_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


def build_threat_intel():
    data = load_alerts()
    intel = []

    for alert in data.get("alerts", []):
        severity = alert["severity"]

        if severity == "CRITICAL":
            threat_score = 90
        elif severity == "HIGH":
            threat_score = 75
        elif severity == "MEDIUM":
            threat_score = 55
        else:
            threat_score = 25

        if alert.get("anomaly_level") == "ANOMALOUS":
            threat_score = min(100, threat_score + 10)

        if alert.get("correlation_score", 0) >= 45:
            threat_score = min(100, threat_score + 10)

        if alert.get("watchlisted"):
            threat_score = min(100, threat_score + 15)

        reputation_data = get_ip_reputation(alert["source_ip"])

        intel.append({
            "ip": alert["source_ip"],
            "ip_type": alert.get("ip_type", "Unknown"),
            "country": alert.get("country", "Unknown"),
            "city": alert.get("city", "Unknown"),
            "isp": alert.get("isp", "Unknown"),
            "attempts": alert["failed_attempts"],
            "severity": alert["severity"],
            "threat_score": threat_score,
            "reputation": reputation_data.get("reputation", "Monitor"),
            "reputation_score": reputation_data.get("reputation_score", 0),
            "reputation_source": reputation_data.get("reputation_source", "Local Engine"),
            "recommended_action": "Investigate source, review related events, consider block/contain action",
            "anomaly_score": alert.get("anomaly_score", 0),
            "anomaly_level": alert.get("anomaly_level", "NORMAL"),
            "anomaly_reasons": alert.get("anomaly_reasons", []),
            "mitre_technique_id": alert.get("mitre_technique_id", "N/A"),
            "mitre_technique_name": alert.get("mitre_technique_name", "Unmapped"),
            "watchlisted": alert.get("watchlisted", False)
        })

    intel.sort(key=lambda x: (x["threat_score"], x["reputation_score"]), reverse=True)
    return intel


def build_map_points():
    data = load_alerts()
    points = []

    for alert in data.get("alerts", []):
        lat = alert.get("lat")
        lon = alert.get("lon")
        if lat is None or lon is None:
            continue

        points.append({
            "ip": alert["source_ip"],
            "country": alert.get("country", "Unknown"),
            "city": alert.get("city", "Unknown"),
            "severity": alert["severity"],
            "attempts": alert["failed_attempts"],
            "lat": lat,
            "lon": lon
        })

    return points


def build_timeline():
    data = load_alerts()
    alerts = data.get("alerts", [])

    low = len([a for a in alerts if a["severity"] == "LOW"])
    medium = len([a for a in alerts if a["severity"] == "MEDIUM"])
    high = len([a for a in alerts if a["severity"] == "HIGH"])
    critical = len([a for a in alerts if a["severity"] == "CRITICAL"])

    return {"labels": ["Low", "Medium", "High", "Critical"], "counts": [low, medium, high, critical]}


def build_top_attackers(limit=5):
    alerts = load_alerts().get("alerts", [])
    return [
        {
            "ip": a.get("source_ip", "Unknown"),
            "attempts": a.get("failed_attempts", 0),
            "severity": a.get("severity", "LOW"),
            "country": a.get("country", "Unknown")
        }
        for a in sorted(alerts, key=lambda x: x.get("failed_attempts", 0), reverse=True)[:limit]
    ]


def build_top_countries(limit=5):
    alerts = load_alerts().get("alerts", [])
    counter = {}
    for a in alerts:
        country = a.get("country", "Unknown")
        counter[country] = counter.get(country, 0) + 1
    items = sorted(counter.items(), key=lambda x: x[1], reverse=True)[:limit]
    return [{"country": country, "count": count} for country, count in items]


def build_recent_alerts(limit=8):
    alerts = load_alerts().get("alerts", [])
    recent = sorted(alerts, key=lambda x: (x.get("watchlisted", False), severity_rank(x.get("severity", "LOW")), x.get("correlation_score", 0), x.get("failed_attempts", 0)), reverse=True)[:limit]
    return [
        {
            "ip": a.get("source_ip", "Unknown"),
            "type": a.get("alert_type", "Security Event"),
            "severity": a.get("severity", "LOW"),
            "country": a.get("country", "Unknown"),
            "attempts": a.get("failed_attempts", 0)
        }
        for a in recent
    ]


def build_recent_events(limit=12):
    return load_events().get("events", [])[:limit]


def build_recent_campaigns(limit=6):
    return load_correlations().get("campaigns", [])[:limit]


class LogChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith(("auth.log", "apache.log", "firewall.log")):
            scan_logs()


def start_monitor():
    global observer
    if not WATCHDOG_AVAILABLE or observer is not None:
        return

    event_handler = LogChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, path=os.path.join(BASE_DIR, "logs"), recursive=False)
    observer.start()


@app.route("/")
def dashboard():
    scan_logs()
    data = load_alerts()
    settings = load_settings()
    alerts = data.get("alerts", [])
    incidents = load_incidents()

    critical_count = len([a for a in alerts if a["severity"] == "CRITICAL"])
    high_count = len([a for a in alerts if a["severity"] == "HIGH"])
    medium_count = len([a for a in alerts if a["severity"] == "MEDIUM"])
    low_count = len([a for a in alerts if a["severity"] == "LOW"])

    return render_template(
        "dashboard.html",
        total_alerts=data.get("total_alerts", 0),
        top_attacker=data.get("top_attacker", "None"),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        incident_count=len(incidents),
        last_scan=data.get("last_scan", "N/A"),
        settings=settings,
        recent_alerts=build_recent_alerts(),
        recent_events=build_recent_events(),
        recent_campaigns=build_recent_campaigns(),
        top_attackers=build_top_attackers(),
        top_countries=build_top_countries()
    )


@app.route("/api/dashboard")
def api_dashboard():
    scan_logs()
    data = load_alerts()
    alerts = data.get("alerts", [])
    incidents = load_incidents()
    settings = load_settings()

    critical_count = len([a for a in alerts if a["severity"] == "CRITICAL"])
    high_count = len([a for a in alerts if a["severity"] == "HIGH"])
    medium_count = len([a for a in alerts if a["severity"] == "MEDIUM"])
    low_count = len([a for a in alerts if a["severity"] == "LOW"])

    return jsonify({
        "total_alerts": data.get("total_alerts", 0),
        "top_attacker": data.get("top_attacker", "None"),
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "incident_count": len(incidents),
        "last_scan": data.get("last_scan", "N/A"),
        "auto_refresh_enabled": settings.get("auto_refresh_enabled", True),
        "refresh_seconds": settings.get("refresh_seconds", 5),
        "theme": settings.get("theme", "dark"),
        "siren_enabled": settings.get("siren_enabled", True),
        "siren_seconds": settings.get("siren_seconds", 5),
        "custom_siren_file": settings.get("custom_siren_file", "default_alarm.mp3")
    })


@app.route("/api/recent_alerts")
def api_recent_alerts():
    scan_logs()
    return jsonify(build_recent_alerts())


@app.route("/api/recent_events")
def api_recent_events():
    scan_logs()
    return jsonify(build_recent_events())


@app.route("/api/recent_campaigns")
def api_recent_campaigns():
    scan_logs()
    return jsonify(build_recent_campaigns())


@app.route("/api/top_attackers")
def api_top_attackers():
    scan_logs()
    return jsonify(build_top_attackers())


@app.route("/api/top_countries")
def api_top_countries():
    scan_logs()
    return jsonify(build_top_countries())


@app.route("/api/map_points")
def api_map_points():
    scan_logs()
    return jsonify(build_map_points())


@app.route("/api/timeline")
def api_timeline():
    scan_logs()
    return jsonify(build_timeline())


@app.route("/test_siren", methods=["POST"])
def test_siren():
    settings = load_settings()
    return jsonify({
        "success": True,
        "message": "Siren test ready",
        "file": settings.get("custom_siren_file", "default_alarm.mp3"),
        "seconds": settings.get("siren_seconds", 5)
    })


@app.route("/test_telegram", methods=["POST"])
def test_telegram():
    success, message = send_telegram_message("✅ SentinelSOC Pro test message from settings page.")
    return redirect("/settings?telegram_test=" + ("success" if success else "failed") + "&msg=" + message.replace(" ", "_"))


@app.route("/test_email", methods=["POST"])
def test_email():
    success, message = send_email_message("SentinelSOC Pro Test Email", "This is a test email from SentinelSOC Pro settings page.")
    return redirect("/settings?email_test=" + ("success" if success else "failed") + "&msg=" + message.replace(" ", "_"))


@app.route("/watchlist", methods=["GET", "POST"])
def watchlist():
    settings = load_settings()
    data = load_watchlist()

    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        note = request.form.get("note", "").strip()

        if ip:
            items = data.get("items", [])
            if not any(item.get("ip") == ip for item in items):
                items.append({
                    "ip": ip,
                    "note": note,
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                save_json(WATCHLIST_FILE, {"items": items})

        return redirect("/watchlist")

    return render_template("watchlist.html", items=data.get("items", []), settings=settings)


@app.route("/remove_watchlist", methods=["POST"])
def remove_watchlist():
    ip = request.form.get("ip", "").strip()
    data = load_watchlist()
    items = [item for item in data.get("items", []) if item.get("ip") != ip]
    save_json(WATCHLIST_FILE, {"items": items})
    return redirect("/watchlist")


@app.route("/export/blocklist")
def export_blocklist():
    items = load_watchlist().get("items", [])
    output = io.StringIO()
    for item in items:
        output.write(f"{item.get('ip')}\n")

    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    mem.seek(0)
    output.close()

    return send_file(mem, mimetype="text/plain", as_attachment=True, download_name="sentinelsoc_blocklist.txt")


@app.route("/campaigns")
def campaigns():
    scan_logs()
    settings = load_settings()
    campaigns_data = load_correlations().get("campaigns", [])

    q = request.args.get("q", "").strip().lower()
    level = request.args.get("level", "").strip().upper()

    if q:
        campaigns_data = [
            c for c in campaigns_data
            if q in c.get("source_ip", "").lower()
            or q in " ".join(c.get("sources", [])).lower()
            or q in " ".join(c.get("event_types", [])).lower()
        ]

    if level:
        campaigns_data = [c for c in campaigns_data if c.get("campaign_level", "").upper() == level]

    return render_template("campaigns.html", campaigns=campaigns_data, settings=settings, q=q, level=level)


@app.route("/events")
def events():
    scan_logs()
    settings = load_settings()
    events_data = load_events().get("events", [])

    q = request.args.get("q", "").strip().lower()
    source = request.args.get("source", "").strip().lower()
    severity = request.args.get("severity", "").strip().upper()

    if q:
        events_data = [
            e for e in events_data
            if q in e.get("source_ip", "").lower()
            or q in e.get("event_type", "").lower()
            or q in e.get("source", "").lower()
            or q in e.get("service", "").lower()
            or q in e.get("raw", "").lower()
        ]

    if source:
        events_data = [e for e in events_data if e.get("source", "").lower() == source]

    if severity:
        events_data = [e for e in events_data if e.get("severity", "").upper() == severity]

    return render_template("events.html", events=events_data, settings=settings, q=q, source=source, severity=severity)


@app.route("/alerts")
def alerts():
    scan_logs()
    data = load_alerts()
    settings = load_settings()
    alerts_list = data.get("alerts", [])

    q = request.args.get("q", "").strip().lower()
    severity = request.args.get("severity", "").strip().upper()
    disposition = request.args.get("disposition", "").strip().upper()

    if q:
        alerts_list = [
            a for a in alerts_list
            if q in a.get("source_ip", "").lower()
            or q in a.get("alert_type", "").lower()
            or q in a.get("country", "").lower()
            or q in a.get("city", "").lower()
            or q in a.get("mitre_technique_id", "").lower()
            or q in a.get("mitre_technique_name", "").lower()
        ]

    if severity:
        alerts_list = [a for a in alerts_list if a.get("severity", "") == severity]

    if disposition:
        alerts_list = [a for a in alerts_list if a.get("disposition", "") == disposition]

    return render_template("alerts.html", alerts=alerts_list, settings=settings, q=q, severity=severity, disposition=disposition)


@app.route("/alert/<alert_id>")
def alert_detail(alert_id):
    scan_logs()
    data = load_alerts()
    settings = load_settings()
    alerts_list = data.get("alerts", [])
    alert = next((a for a in alerts_list if a.get("id") == alert_id), None)

    if not alert:
        return "Alert not found", 404

    raw_logs = get_matching_raw_logs(alert["source_ip"])
    return render_template("alert_detail.html", alert=alert, raw_logs=raw_logs, settings=settings)


@app.route("/alert_action", methods=["POST"])
def alert_action():
    alert_id = request.form.get("alert_id", "").strip()
    action = request.form.get("action", "").strip().upper()

    if alert_id and action in ["TRUE_POSITIVE", "FALSE_POSITIVE", "ESCALATED", "UNREVIEWED"]:
        state = load_alert_state()
        state.setdefault(alert_id, {})
        state[alert_id]["disposition"] = action
        state[alert_id]["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        save_json(ALERT_STATE_FILE, state)

    return redirect(f"/alert/{alert_id}")


@app.route("/alert_note", methods=["POST"])
def alert_note():
    alert_id = request.form.get("alert_id", "").strip()
    note = request.form.get("note", "").strip()

    if alert_id and note:
        state = load_alert_state()
        state.setdefault(alert_id, {})
        state[alert_id].setdefault("notes", [])
        state[alert_id]["notes"].append({
            "text": note,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        state[alert_id]["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        save_json(ALERT_STATE_FILE, state)

    return redirect(f"/alert/{alert_id}")


@app.route("/escalate_alert_to_incident", methods=["POST"])
def escalate_alert_to_incident():
    alert_id = request.form.get("alert_id", "").strip()
    data = load_alerts()
    alerts_list = data.get("alerts", [])
    alert = next((a for a in alerts_list if a.get("id") == alert_id), None)

    if alert:
        incidents_data = load_incidents()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        incidents_data.append({
            "id": len(incidents_data) + 1,
            "title": f"Incident from alert {alert.get('source_ip')}",
            "severity": alert.get("severity", "MEDIUM"),
            "priority": alert.get("severity", "MEDIUM"),
            "status": "Open",
            "owner": "",
            "closure_note": "",
            "investigation_summary": "",
            "notes": [
                f"Created from alert {alert.get('source_ip')}",
                f"MITRE: {alert.get('mitre_technique_id', 'N/A')} - {alert.get('mitre_technique_name', 'Unmapped')}"
            ],
            "created_at": now,
            "timeline": [f"{now} - Incident created from alert escalation"]
        })
        save_json(INCIDENT_FILE, incidents_data)

        state = load_alert_state()
        state.setdefault(alert_id, {})
        state[alert_id]["disposition"] = "ESCALATED"
        state[alert_id]["updated_at"] = now
        save_json(ALERT_STATE_FILE, state)

    return redirect(f"/alert/{alert_id}")


@app.route("/incidents", methods=["GET", "POST"])
def incidents():
    settings = load_settings()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        severity = request.form.get("severity", "LOW").strip()
        status = request.form.get("status", "Open").strip()
        note = request.form.get("note", "").strip()
        owner = request.form.get("owner", "").strip()

        if title:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            incidents_data = load_incidents()
            incidents_data.append({
                "id": len(incidents_data) + 1,
                "title": title,
                "severity": severity,
                "priority": severity,
                "status": status,
                "owner": owner,
                "closure_note": "",
                "investigation_summary": "",
                "notes": [note] if note else [],
                "created_at": now,
                "timeline": [f"{now} - Incident created with status {status}"]
            })
            save_json(INCIDENT_FILE, incidents_data)

        return redirect("/incidents")

    incidents_data = load_incidents()
    for inc in incidents_data:
        inc.setdefault("timeline", [f"{inc.get('created_at', 'Unknown time')} - Incident created"])
        inc.setdefault("owner", "")
        inc.setdefault("priority", inc.get("severity", "LOW"))
        inc.setdefault("closure_note", "")
        inc.setdefault("investigation_summary", "")

    return render_template("incidents.html", incidents=incidents_data, settings=settings)


@app.route("/incident_action", methods=["POST"])
def incident_action():
    try:
        incident_id = int(request.form.get("incident_id"))
    except Exception:
        return redirect("/incidents")

    new_status = request.form.get("new_status", "").strip()
    new_note = request.form.get("new_note", "").strip()
    owner = request.form.get("owner", "").strip()
    priority = request.form.get("priority", "").strip()
    closure_note = request.form.get("closure_note", "").strip()
    investigation_summary = request.form.get("investigation_summary", "").strip()

    incidents_data = load_incidents()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for incident in incidents_data:
        if incident["id"] == incident_id:
            incident.setdefault("timeline", [])

            if new_status:
                incident["status"] = new_status
                incident["timeline"].append(f"{now} - Status changed to {new_status}")

            if owner != "":
                old_owner = incident.get("owner", "")
                incident["owner"] = owner
                if owner != old_owner:
                    incident["timeline"].append(f"{now} - Owner updated to {owner or 'Unassigned'}")

            if priority:
                old_priority = incident.get("priority", "")
                incident["priority"] = priority
                if priority != old_priority:
                    incident["timeline"].append(f"{now} - Priority changed to {priority}")

            if investigation_summary != "":
                incident["investigation_summary"] = investigation_summary

            if closure_note != "":
                incident["closure_note"] = closure_note

            if new_note:
                incident.setdefault("notes", [])
                incident["notes"].append(new_note)
                incident["timeline"].append(f"{now} - Analyst note added")

            if new_status == "Closed" and closure_note:
                incident["timeline"].append(f"{now} - Incident closed with closure note")

    save_json(INCIDENT_FILE, incidents_data)
    return redirect("/incidents")


@app.route("/reports")
def reports():
    settings = load_settings()
    report = load_alerts()
    alerts = report.get("alerts", [])

    severity_breakdown = {
        "LOW": len([a for a in alerts if a.get("severity") == "LOW"]),
        "MEDIUM": len([a for a in alerts if a.get("severity") == "MEDIUM"]),
        "HIGH": len([a for a in alerts if a.get("severity") == "HIGH"]),
        "CRITICAL": len([a for a in alerts if a.get("severity") == "CRITICAL"])
    }

    return render_template("reports.html", report=report, settings=settings, severity_breakdown=severity_breakdown)


@app.route("/threat")
def threat():
    scan_logs()
    settings = load_settings()
    intel = build_threat_intel()
    return render_template("threat.html", intel=intel, settings=settings)


@app.route("/settings", methods=["GET", "POST"])
def settings():
    current = load_settings()

    if request.method == "POST":
        raw = {
            "auto_refresh_enabled": True if request.form.get("auto_refresh_enabled") == "on" else False,
            "refresh_seconds": request.form.get("refresh_seconds", "5"),
            "theme": request.form.get("theme", "dark"),
            "auto_open_browser": True if request.form.get("auto_open_browser") == "on" else False,
            "telegram_enabled": True if request.form.get("telegram_enabled") == "on" else False,
            "telegram_bot_token": request.form.get("telegram_bot_token", ""),
            "telegram_chat_id": request.form.get("telegram_chat_id", ""),
            "email_enabled": True if request.form.get("email_enabled") == "on" else False,
            "smtp_host": request.form.get("smtp_host", ""),
            "smtp_port": request.form.get("smtp_port", "587"),
            "smtp_username": request.form.get("smtp_username", ""),
            "smtp_password": request.form.get("smtp_password", ""),
            "email_to": request.form.get("email_to", ""),
            "siren_enabled": True if request.form.get("siren_enabled") == "on" else False,
            "siren_seconds": request.form.get("siren_seconds", "5"),
            "custom_siren_file": request.form.get("custom_siren_file", "default_alarm.mp3"),
            "abuseipdb_enabled": True if request.form.get("abuseipdb_enabled") == "on" else False,
            "abuseipdb_api_key": request.form.get("abuseipdb_api_key", ""),
            "virustotal_enabled": True if request.form.get("virustotal_enabled") == "on" else False,
            "virustotal_api_key": request.form.get("virustotal_api_key", ""),
            "otx_enabled": True if request.form.get("otx_enabled") == "on" else False,
            "otx_api_key": request.form.get("otx_api_key", "")
        }

        validated = validate_settings(raw)
        save_json(SETTINGS_FILE, validated)
        return redirect("/settings?saved=1")

    return render_template("settings.html", settings=current)


@app.route("/export/json")
def export_json():
    return send_file(ALERT_FILE, as_attachment=True)


@app.route("/export/csv")
def export_csv():
    data = load_alerts()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "IP", "Type", "Attempts", "Severity", "Country", "City",
        "MITRE Technique ID", "MITRE Technique Name", "Anomaly Score",
        "Anomaly Level", "Disposition", "Status"
    ])

    for alert in data.get("alerts", []):
        writer.writerow([
            alert.get("source_ip"),
            alert.get("alert_type"),
            alert.get("failed_attempts"),
            alert.get("severity"),
            alert.get("country"),
            alert.get("city"),
            alert.get("mitre_technique_id"),
            alert.get("mitre_technique_name"),
            alert.get("anomaly_score"),
            alert.get("anomaly_level"),
            alert.get("disposition"),
            alert.get("status")
        ])

    mem = io.BytesIO()
    mem.write(output.getvalue().encode("utf-8"))
    mem.seek(0)
    output.close()

    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="sentinelsoc_alerts.csv")


def open_browser():
    settings = load_settings()
    if settings.get("auto_open_browser", True):
        threading.Timer(1.5, lambda: webbrowser.open("http://127.0.0.1:5000")).start()


def start_app():
    ensure_files()
    scan_logs()
    start_monitor()
    open_browser()
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    start_app()
