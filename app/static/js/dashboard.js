// NetSential SOC Dashboard JavaScript Logic

document.addEventListener("DOMContentLoaded", () => {
  initDashboard();
});

let eventsTimelineChartInstance = null;
let severityDoughnutChartInstance = null;

async function initDashboard() {
  await Promise.allSettled([
    loadStats(),
    loadEventsTimeline(),
    loadSeverityDistribution(),
    loadRecentActivity(),
  ]);
}

// 1. Load Metric Cards
async function loadStats() {
  try {
    const res = await secureFetch("/api/dashboard/stats");
    const json = await res.json();
    if (!json.success) return;

    const d = json.data;
    document.getElementById("cardTotalEvents").textContent = Number(d.total_events).toLocaleString();
    document.getElementById("cardOpenAlerts").textContent = Number(d.open_alerts).toLocaleString();
    document.getElementById("cardCriticalAlerts").textContent = Number(d.critical_unresolved).toLocaleString();
    document.getElementById("cardFailedLogins").textContent = Number(d.failed_logins).toLocaleString();
    document.getElementById("cardResolvedAlerts").textContent = Number(d.resolved_alerts).toLocaleString();
  } catch (err) {
    console.error("Failed to load dashboard stats:", err);
  }
}

// 2. Events Timeline Chart
async function loadEventsTimeline() {
  const canvas = document.getElementById("eventsTimelineChart");
  if (!canvas) return;

  try {
    const res = await secureFetch("/api/dashboard/events-over-time?days=7");
    const data = await res.json();
    if (!data.success) return;

    const ctx = canvas.getContext("2d");
    if (eventsTimelineChartInstance) {
      eventsTimelineChartInstance.destroy();
    }

    eventsTimelineChartInstance = new Chart(ctx, {
      type: "line",
      data: {
        labels: data.labels,
        datasets: [
          {
            label: "Total Events",
            data: data.totals,
            borderColor: "#06b6d4",
            backgroundColor: "rgba(6, 182, 212, 0.12)",
            borderWidth: 2,
            tension: 0.35,
            fill: true,
            pointBackgroundColor: "#38bdf8",
            pointRadius: 3,
            pointHoverRadius: 6,
          },
          {
            label: "High & Critical",
            data: data.labels.map((_, i) => (data.breakdown.HIGH[i] || 0) + (data.breakdown.CRITICAL[i] || 0)),
            borderColor: "#ef4444",
            backgroundColor: "transparent",
            borderWidth: 2,
            borderDash: [5, 5],
            tension: 0.35,
            pointBackgroundColor: "#ef4444",
            pointRadius: 3,
          }
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "top",
            labels: {
              color: "#94a3b8",
              font: { family: "Inter", size: 12 },
              usePointStyle: true,
            },
          },
          tooltip: {
            backgroundColor: "#162544",
            titleColor: "#ffffff",
            bodyColor: "#94a3b8",
            borderColor: "#1e3256",
            borderWidth: 1,
            padding: 10,
          },
        },
        scales: {
          x: {
            grid: { color: "rgba(30, 50, 86, 0.5)" },
            ticks: { color: "#64748b", font: { family: "Inter", size: 11 } },
          },
          y: {
            grid: { color: "rgba(30, 50, 86, 0.5)" },
            ticks: { color: "#64748b", font: { family: "Inter", size: 11 }, precision: 0 },
            beginAtZero: true,
          },
        },
      },
    });
  } catch (err) {
    console.error("Failed to load events timeline:", err);
  }
}

// 3. Severity Distribution Doughnut Chart
async function loadSeverityDistribution() {
  const canvas = document.getElementById("severityDoughnutChart");
  if (!canvas) return;

  try {
    const res = await secureFetch("/api/dashboard/severity-distribution");
    const data = await res.json();
    if (!data.success) return;

    const sev = data.events_severity;
    const ctx = canvas.getContext("2d");
    if (severityDoughnutChartInstance) {
      severityDoughnutChartInstance.destroy();
    }

    const counts = [sev.LOW || 0, sev.MEDIUM || 0, sev.HIGH || 0, sev.CRITICAL || 0];

    severityDoughnutChartInstance = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        datasets: [
          {
            data: counts,
            backgroundColor: [
              "#10b981", // Low
              "#f59e0b", // Medium
              "#f97316", // High
              "#ef4444", // Critical
            ],
            borderColor: "#111d35",
            borderWidth: 3,
            hoverOffset: 6,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color: "#94a3b8",
              font: { family: "Inter", size: 11 },
              usePointStyle: true,
              boxWidth: 8,
            },
          },
          tooltip: {
            backgroundColor: "#162544",
            titleColor: "#ffffff",
            bodyColor: "#94a3b8",
            borderColor: "#1e3256",
            borderWidth: 1,
          },
        },
        cutout: "68%",
      },
    });

    const legendElem = document.getElementById("severitySummaryLegend");
    if (legendElem) {
      legendElem.innerHTML = `
        <div><span class="text-success fw-bold">${sev.LOW || 0}</span><br>LOW</div>
        <div><span class="text-warning fw-bold">${sev.MEDIUM || 0}</span><br>MED</div>
        <div><span class="text-orange fw-bold" style="color: #fb923c;">${sev.HIGH || 0}</span><br>HIGH</div>
        <div><span class="text-danger fw-bold">${sev.CRITICAL || 0}</span><br>CRIT</div>
      `;
    }
  } catch (err) {
    console.error("Failed to load severity distribution:", err);
  }
}

// 4. Recent Activity Feeds
async function loadRecentActivity() {
  try {
    const res = await secureFetch("/api/dashboard/recent-activity");
    const data = await res.json();
    if (!data.success) return;

    // Render Recent Alerts
    const alertsTbody = document.getElementById("recentAlertsTableBody");
    if (alertsTbody) {
      if (data.alerts.length === 0) {
        alertsTbody.innerHTML = `<tr><td colspan="5" class="text-center py-3 text-muted">No security alerts recorded.</td></tr>`;
      } else {
        alertsTbody.innerHTML = data.alerts.map(a => `
          <tr>
            <td><code class="text-info">${escapeHtml(a.rule_code)}</code></td>
            <td class="text-truncate" style="max-width: 170px;" title="${escapeHtml(a.title)}">${escapeHtml(a.title)}</td>
            <td><span class="badge-sev badge-sev-${a.severity.toLowerCase()}">${a.severity}</span></td>
            <td><span class="badge-sev badge-status-${a.status === 'NEW' ? 'new' : (a.status === 'ACKNOWLEDGED' ? 'ack' : 'res')}">${a.status}</span></td>
            <td class="text-muted small">${formatDate(a.created_at)}</td>
          </tr>
        `).join("");
      }
    }

    // Render Recent Events
    const eventsTbody = document.getElementById("recentEventsTableBody");
    if (eventsTbody) {
      if (data.events.length === 0) {
        eventsTbody.innerHTML = `<tr><td colspan="5" class="text-center py-3 text-muted">No security events ingested yet.</td></tr>`;
      } else {
        eventsTbody.innerHTML = data.events.map(e => `
          <tr>
            <td><span class="badge bg-dark border border-secondary">${escapeHtml(e.event_type)}</span></td>
            <td><code>${escapeHtml(e.source_ip)}</code></td>
            <td class="text-muted">${escapeHtml(e.username || "—")}</td>
            <td><span class="badge-sev badge-sev-${e.severity.toLowerCase()}">${e.severity}</span></td>
            <td class="text-muted small">${formatDate(e.event_time)}</td>
          </tr>
        `).join("");
      }
    }
  } catch (err) {
    console.error("Failed to load recent activity:", err);
  }
}

// Helpers
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatDate(isoStr) {
  if (!isoStr) return "—";
  try {
    const d = new Date(isoStr);
    return d.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
  } catch {
    return isoStr;
  }
}
