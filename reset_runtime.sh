#!/bin/bash

cd "$(dirname "$0")"

echo "[*] Resetting runtime data..."

mkdir -p alerts
mkdir -p logs

cat > alerts/alerts.json <<EOF
{
    "total_alerts": 0,
    "top_attacker": "None",
    "alerts": [],
    "last_scan": "N/A"
}
EOF

cat > alerts/events.json <<EOF
{
    "total_events": 0,
    "events": [],
    "last_scan": "N/A"
}
EOF

cat > alerts/correlations.json <<EOF
{
    "total_campaigns": 0,
    "campaigns": [],
    "last_scan": "N/A"
}
EOF

cat > alerts/watchlist.json <<EOF
{
    "items": []
}
EOF

cat > alerts/incidents.json <<EOF
[]
EOF

cat > alerts/geo_cache.json <<EOF
{}
EOF

cat > alerts/alert_state.json <<EOF
{}
EOF

echo "" > logs/auth.log
echo "" > logs/apache.log
echo "" > logs/firewall.log

echo "[+] Runtime data reset complete."
