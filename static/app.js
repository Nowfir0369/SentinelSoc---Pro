let refreshTimer = null;
let severityChart = null;
let timelineChart = null;
let attackMap = null;
let attackMarkers = [];
let previousCritical = null;
let sirenCooldown = false;

function applyTheme(theme) {
    document.body.setAttribute("data-theme", theme || "dark");
}

function buildSeverityChart(initial) {
    const ctx = document.getElementById("severityChart");
    if (!ctx || typeof Chart === "undefined") return;

    severityChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels: ["Critical", "High", "Medium", "Low"],
            datasets: [{
                label: "Alert Count",
                data: [
                    initial.critical_count || 0,
                    initial.high_count || 0,
                    initial.medium_count || 0,
                    initial.low_count || 0
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false
        }
    });

    previousCritical = initial.critical_count || 0;
}

async function buildTimelineChart() {
    const ctx = document.getElementById("timelineChart");
    if (!ctx || typeof Chart === "undefined") return;

    try {
        const res = await fetch("/api/timeline");
        const data = await res.json();

        timelineChart = new Chart(ctx, {
            type: "line",
            data: {
                labels: data.labels,
                datasets: [{
                    label: "Severity Distribution",
                    data: data.counts,
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });
    } catch (e) {
        console.error("Timeline build failed:", e);
    }
}

async function buildAttackMap() {
    const mapDiv = document.getElementById("attack-map");
    if (!mapDiv || typeof L === "undefined") return;

    try {
        if (attackMap) {
            attackMap.remove();
            attackMap = null;
        }

        attackMap = L.map("attack-map").setView([20, 0], 2);

        L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
            maxZoom: 19,
            attribution: "&copy; OpenStreetMap contributors"
        }).addTo(attackMap);

        await refreshMapPoints();
    } catch (e) {
        console.error("Map build failed:", e);
    }
}

async function refreshMapPoints() {
    if (!attackMap) return;

    attackMarkers.forEach(marker => attackMap.removeLayer(marker));
    attackMarkers = [];

    try {
        const res = await fetch("/api/map_points");
        const points = await res.json();

        points.forEach(point => {
            const marker = L.marker([point.lat, point.lon]).addTo(attackMap);
            marker.bindPopup(
                `<strong>${point.ip}</strong><br>${point.city}, ${point.country}<br>Severity: ${point.severity}<br>Attempts: ${point.attempts}`
            );
            attackMarkers.push(marker);
        });
    } catch (e) {
        console.error("Map refresh failed:", e);
    }
}

function playSirenIfNeeded(currentCritical, settings) {
    if (!settings || !settings.siren_enabled) return;
    if (sirenCooldown) return;

    if (previousCritical === null) {
        previousCritical = currentCritical;
        return;
    }

    if (currentCritical > previousCritical) {
        const file = settings.custom_siren_file || "default_alarm.mp3";
        const seconds = settings.siren_seconds || 5;
        const audio = new Audio(`/static/sounds/${file}`);

        sirenCooldown = true;
        audio.play().catch(() => {});
        setTimeout(() => {
            audio.pause();
            audio.currentTime = 0;
        }, seconds * 1000);

        setTimeout(() => {
            sirenCooldown = false;
        }, Math.max(seconds, 5) * 1000);
    }

    previousCritical = currentCritical;
}

async function refreshRecentEvents() {
    const container = document.getElementById("recent-events-feed");
    const ticker = document.getElementById("live-alert-ticker");
    if (!container) return;

    try {
        const res = await fetch("/api/recent_events");
        const data = await res.json();

        if (!data.length) {
            container.innerHTML = "<p>No recent events.</p>";
            if (ticker) ticker.textContent = "SentinelSOC Live Feed Active • No new events";
            return;
        }

        container.innerHTML = data.map(item => `
            <div class="feed-item">
                <div><strong>${item.source_ip}</strong></div>
                <div>${item.event_type}</div>
                <div>${item.source} | ${item.service}</div>
                <div><span class="badge badge-${String(item.severity).toLowerCase()}">${item.severity}</span></div>
            </div>
        `).join("");

        if (ticker) {
            ticker.textContent = data.map(
                item => `${item.source_ip} • ${item.event_type} • ${item.source}`
            ).join("   •   ");
        }
    } catch (e) {
        console.error("Recent events refresh failed:", e);
    }
}

async function refreshRecentCampaigns() {
    const container = document.getElementById("recent-campaigns-feed");
    if (!container) return;

    try {
        const res = await fetch("/api/recent_campaigns");
        const data = await res.json();

        if (!data.length) {
            container.innerHTML = "<p>No correlated campaigns.</p>";
            return;
        }

        container.innerHTML = data.map(item => `
            <div class="feed-item">
                <div><strong>${item.source_ip}</strong></div>
                <div>${item.campaign_level} | Score ${item.correlation_score}</div>
                <div>${item.event_count} events | ${item.sources.join(", ")}</div>
            </div>
        `).join("");
    } catch (e) {
        console.error("Recent campaigns refresh failed:", e);
    }
}

async function refreshRecentAlerts() {
    const container = document.getElementById("recent-alerts-feed");
    if (!container) return;

    try {
        const res = await fetch("/api/recent_alerts");
        const data = await res.json();

        if (!data.length) {
            container.innerHTML = "<p>No recent alerts.</p>";
            return;
        }

        container.innerHTML = data.map(item => `
            <div class="feed-item">
                <div><strong>${item.ip}</strong></div>
                <div>${item.type}</div>
                <div>${item.country} | ${item.attempts} attempts</div>
                <div><span class="badge badge-${String(item.severity).toLowerCase()}">${item.severity}</span></div>
            </div>
        `).join("");
    } catch (e) {
        console.error("Recent alerts refresh failed:", e);
    }
}

async function refreshTopAttackers() {
    const container = document.getElementById("top-attackers-list");
    if (!container) return;

    try {
        const res = await fetch("/api/top_attackers");
        const data = await res.json();

        if (!data.length) {
            container.innerHTML = "<p>No attacker data.</p>";
            return;
        }

        container.innerHTML = data.map(item => `
            <div class="feed-item">
                <div><strong>${item.ip}</strong></div>
                <div>${item.country}</div>
                <div>${item.attempts} attempts</div>
            </div>
        `).join("");
    } catch (e) {
        console.error("Top attackers refresh failed:", e);
    }
}

async function refreshTopCountries() {
    const container = document.getElementById("top-countries-list");
    if (!container) return;

    try {
        const res = await fetch("/api/top_countries");
        const data = await res.json();

        if (!data.length) {
            container.innerHTML = "<p>No country data.</p>";
            return;
        }

        container.innerHTML = data.map(item => `
            <div class="feed-item">
                <div><strong>${item.country}</strong></div>
                <div>${item.count} alert(s)</div>
            </div>
        `).join("");
    } catch (e) {
        console.error("Top countries refresh failed:", e);
    }
}

async function fetchDashboardData() {
    try {
        const res = await fetch("/api/dashboard");
        const data = await res.json();

        const totalEl = document.getElementById("total-alerts");
        const criticalEl = document.getElementById("critical-count");
        const incidentEl = document.getElementById("incident-count");
        const attackerEl = document.getElementById("top-attacker");
        const scanEl = document.getElementById("last-scan");
        const refreshEl = document.getElementById("refresh-status");

        if (totalEl) totalEl.textContent = data.total_alerts;
        if (criticalEl) criticalEl.textContent = data.critical_count;
        if (incidentEl) incidentEl.textContent = data.incident_count;
        if (attackerEl) attackerEl.textContent = data.top_attacker;
        if (scanEl) scanEl.textContent = data.last_scan;
        if (refreshEl) refreshEl.textContent = data.auto_refresh_enabled ? "ON" : "OFF";

        applyTheme(data.theme);

        if (severityChart) {
            severityChart.data.datasets[0].data = [
                data.critical_count || 0,
                data.high_count || 0,
                data.medium_count || 0,
                data.low_count || 0
            ];
            severityChart.update();
        }

        if (timelineChart) {
            const tRes = await fetch("/api/timeline");
            const timeline = await tRes.json();
            timelineChart.data.labels = timeline.labels;
            timelineChart.data.datasets[0].data = timeline.counts;
            timelineChart.update();
        }

        await refreshMapPoints();
        await refreshRecentEvents();
        await refreshRecentCampaigns();
        await refreshRecentAlerts();
        await refreshTopAttackers();
        await refreshTopCountries();

        playSirenIfNeeded(data.critical_count, data);
        startAutoRefresh(data.auto_refresh_enabled, data.refresh_seconds);
    } catch (e) {
        console.error("Dashboard refresh failed:", e);
    }
}

function startAutoRefresh(enabled, seconds) {
    if (refreshTimer) clearInterval(refreshTimer);
    if (!enabled) return;
    refreshTimer = setInterval(fetchDashboardData, seconds * 1000);
}

document.addEventListener("DOMContentLoaded", async () => {
    if (window.SENTINEL_SETTINGS) {
        applyTheme(window.SENTINEL_SETTINGS.theme);
    }

    if (window.SENTINEL_INITIAL) {
        buildSeverityChart(window.SENTINEL_INITIAL);
    }

    await buildTimelineChart();
    await buildAttackMap();
    await refreshRecentEvents();
    await refreshRecentCampaigns();
    await refreshRecentAlerts();
    await refreshTopAttackers();
    await refreshTopCountries();

    if (window.SENTINEL_SETTINGS) {
        startAutoRefresh(
            window.SENTINEL_SETTINGS.auto_refresh_enabled,
            window.SENTINEL_SETTINGS.refresh_seconds
        );
    }
});
