// NetSential Threat Alerts JavaScript Logic

let currentAlertPage = 1;
const alertsPerPage = 20;

document.addEventListener("DOMContentLoaded", () => {
  loadAlerts();

  const filterForm = document.getElementById("alertsFilterForm");
  if (filterForm) {
    filterForm.addEventListener("change", () => {
      currentAlertPage = 1;
      loadAlerts();
    });
  }

  const resetBtn = document.getElementById("resetAlertFiltersBtn");
  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      document.getElementById("filterAlertSeverity").value = "ALL";
      document.getElementById("filterAlertStatus").value = "ALL";
      document.getElementById("filterAlertRule").value = "ALL";
      currentAlertPage = 1;
      loadAlerts();
    });
  }

  const prevBtn = document.getElementById("alertPrevBtn");
  const nextBtn = document.getElementById("alertNextBtn");
  if (prevBtn) {
    prevBtn.addEventListener("click", () => {
      if (currentAlertPage > 1) {
        currentAlertPage--;
        loadAlerts();
      }
    });
  }
  if (nextBtn) {
    nextBtn.addEventListener("click", () => {
      currentAlertPage++;
      loadAlerts();
    });
  }

  const detectionBtn = document.getElementById("triggerDetectionBtn");
  if (detectionBtn) {
    detectionBtn.addEventListener("click", async () => {
      detectionBtn.disabled = true;
      detectionBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Running...';
      try {
        const res = await secureFetch("/api/detection/run", { method: "POST" });
        const data = await res.json();
        if (data.success) {
          alert(`Threat detection completed!\nNew alerts generated: ${data.new_alerts_count}`);
          loadAlerts();
        } else {
          alert("Error: " + (data.error || "Failed to run detection"));
        }
      } catch (err) {
        alert("Network error: " + err.message);
      } finally {
        detectionBtn.disabled = false;
        detectionBtn.innerHTML = '<i class="bi bi-play-circle-fill"></i> Run Detection';
      }
    });
  }

  const exportBtn = document.getElementById("exportFilteredAlertsBtn");
  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      const sev = document.getElementById("filterAlertSeverity")?.value || "ALL";
      const stat = document.getElementById("filterAlertStatus")?.value || "ALL";
      window.location.href = `/api/reports/export?type=alerts&severity=${encodeURIComponent(sev)}&status=${encodeURIComponent(stat)}`;
    });
  }
});

async function loadAlerts() {
  const tbody = document.getElementById("alertsTableBody");
  if (!tbody) return;

  const severity = document.getElementById("filterAlertSeverity")?.value || "ALL";
  const status = document.getElementById("filterAlertStatus")?.value || "ALL";
  const ruleCode = document.getElementById("filterAlertRule")?.value || "ALL";

  const params = new URLSearchParams({
    page: currentAlertPage,
    per_page: alertsPerPage,
    severity: severity,
    status: status,
    rule_code: ruleCode,
  });

  tbody.innerHTML = `<tr><td colspan="8" class="text-center py-4 text-muted"><span class="spinner-border spinner-border-sm"></span> Querying alerts...</td></tr>`;

  try {
    const res = await secureFetch(`/api/alerts?${params.toString()}`);
    const data = await res.json();
    if (!data.success) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center py-4 text-danger">Error: ${data.error}</td></tr>`;
      return;
    }

    const items = data.items;
    const badge = document.getElementById("totalAlertsBadge");
    if (badge) badge.textContent = `${data.total.toLocaleString()} alerts`;

    const info = document.getElementById("alertPaginationInfo");
    if (info) {
      const startNum = data.total === 0 ? 0 : (data.page - 1) * data.per_page + 1;
      const endNum = Math.min(data.page * data.per_page, data.total);
      info.textContent = `Showing ${startNum} - ${endNum} of ${data.total.toLocaleString()} (Page ${data.page} of ${Math.max(1, data.pages)})`;
    }

    const prevBtn = document.getElementById("alertPrevBtn");
    const nextBtn = document.getElementById("alertNextBtn");
    if (prevBtn) prevBtn.disabled = data.page <= 1;
    if (nextBtn) nextBtn.disabled = data.page >= data.pages;

    if (items.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" class="text-center py-5">
            <div class="soc-empty-state">
              <div class="soc-empty-icon"><i class="bi bi-shield-check text-success"></i></div>
              <h6 class="text-dark">No security alerts found</h6>
              <p class="text-muted small">No active threats match the selected filter criteria.</p>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = items.map(a => `
      <tr>
        <td class="text-muted">#${a.id}</td>
        <td class="text-nowrap small text-muted">${formatDate(a.created_at)}</td>
        <td><code class="text-info">${escapeHtml(a.rule_code)}</code></td>
        <td class="fw-semibold text-dark text-truncate" style="max-width: 230px;" title="${escapeHtml(a.title)}">${escapeHtml(a.title)}</td>
        <td><span class="badge-sev badge-sev-${a.severity.toLowerCase()}">${a.severity}</span></td>
        <td><span class="badge-sev badge-status-${a.status === 'NEW' ? 'new' : (a.status === 'ACKNOWLEDGED' ? 'ack' : 'res')}">${a.status}</span></td>
        <td><span class="badge bg-light border text-dark">Event #${a.event_id}</span></td>
        <td class="text-end">
          <button class="btn btn-sm btn-soc-secondary py-0 px-2" onclick="investigateAlert(${a.id})" title="Investigate Threat Alert">
            <i class="bi bi-search"></i> Inspect
          </button>
        </td>
      </tr>
    `).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center py-4 text-danger">Network Error: ${err.message}</td></tr>`;
  }
}

async function investigateAlert(alertId) {
  const modalElem = document.getElementById("alertInvestigationModal");
  const modalBody = document.getElementById("alertModalBody");
  const modalActions = document.getElementById("alertModalActions");
  if (!modalElem || !modalBody) return;

  const bsModal = new bootstrap.Modal(modalElem);
  modalBody.innerHTML = `<div class="text-center py-4"><span class="spinner-border text-info"></span></div>`;
  modalActions.innerHTML = "";
  bsModal.show();

  try {
    const res = await secureFetch(`/api/alerts/${alertId}`);
    const data = await res.json();
    if (!data.success) {
      modalBody.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
      return;
    }

    const a = data.alert;
    const ev = a.event;

    modalBody.innerHTML = `
      <div class="row g-3">
        <div class="col-md-6">
          <label class="text-muted small text-uppercase">Alert ID & Rule</label>
          <div class="fw-bold text-dark">#${a.id} &mdash; <code class="text-info">${escapeHtml(a.rule_code)}</code></div>
        </div>
        <div class="col-md-6">
          <label class="text-muted small text-uppercase">Detection Time</label>
          <div class="fw-bold text-dark">${formatDate(a.created_at)} UTC</div>
        </div>
        <div class="col-md-6">
          <label class="text-muted small text-uppercase">Severity</label>
          <div><span class="badge-sev badge-sev-${a.severity.toLowerCase()}">${a.severity}</span></div>
        </div>
        <div class="col-md-6">
          <label class="text-muted small text-uppercase">Investigation Status</label>
          <div><span class="badge-sev badge-status-${a.status === 'NEW' ? 'new' : (a.status === 'ACKNOWLEDGED' ? 'ack' : 'res')}">${a.status}</span></div>
        </div>
        <div class="col-12">
          <label class="text-muted small text-uppercase">Threat Description</label>
          <div class="p-3 rounded bg-light border text-dark">${escapeHtml(a.description)}</div>
        </div>

        ${ev ? `
        <div class="col-12 mt-3">
          <h6 class="text-dark border-bottom pb-2 mb-3"><i class="bi bi-lightning-charge text-warning"></i> Triggering Source Event (#${ev.id})</h6>
          <div class="row g-2 small">
            <div class="col-sm-4 text-muted">Source IP: <code>${escapeHtml(ev.source_ip)}</code></div>
            <div class="col-sm-4 text-muted">Target User: <strong class="text-dark">${escapeHtml(ev.username || 'N/A')}</strong></div>
            <div class="col-sm-4 text-muted">Event Type: <span class="badge bg-secondary">${escapeHtml(ev.event_type)}</span></div>
            <div class="col-12 text-muted mt-2">Log Message:</div>
            <div class="col-12"><div class="soc-code p-2">${escapeHtml(ev.message)}</div></div>
          </div>
        </div>
        ` : ''}

        ${a.status === 'RESOLVED' ? `
        <div class="col-12 mt-3 p-2 rounded bg-success-subtle border border-success-subtle">
          <div class="small text-success-emphasis"><i class="bi bi-check-circle-fill"></i> Resolved by <strong>${escapeHtml(a.resolver_username || 'Analyst')}</strong> at ${formatDate(a.resolved_at)}</div>
        </div>
        ` : ''}
      </div>
    `;

    // Setup action buttons based on status
    let actionButtons = "";
    if (a.status === "NEW") {
      actionButtons += `
        <button class="btn btn-sm btn-outline-warning me-2" onclick="updateAlertStatus(${a.id}, 'ACKNOWLEDGED')">
          <i class="bi bi-eye-fill"></i> Acknowledge
        </button>
        <button class="btn btn-sm btn-success me-2" onclick="updateAlertStatus(${a.id}, 'RESOLVED')">
          <i class="bi bi-check2-circle"></i> Resolve Alert
        </button>
      `;
    } else if (a.status === "ACKNOWLEDGED") {
      actionButtons += `
        <button class="btn btn-sm btn-success me-2" onclick="updateAlertStatus(${a.id}, 'RESOLVED')">
          <i class="bi bi-check2-circle"></i> Resolve Alert
        </button>
      `;
    } else if (a.status === "RESOLVED") {
      actionButtons += `
        <button class="btn btn-sm btn-outline-secondary me-2" onclick="updateAlertStatus(${a.id}, 'ACKNOWLEDGED')">
          <i class="bi bi-arrow-counterclockwise"></i> Reopen Alert
        </button>
      `;
    }
    modalActions.innerHTML = actionButtons;

  } catch (err) {
    modalBody.innerHTML = `<div class="alert alert-danger">Error: ${err.message}</div>`;
  }
}

async function updateAlertStatus(alertId, newStatus) {
  try {
    const res = await secureFetch(`/api/alerts/${alertId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: newStatus }),
    });
    const data = await res.json();
    if (data.success) {
      // Close modal
      const modalElem = document.getElementById("alertInvestigationModal");
      const modalInstance = bootstrap.Modal.getInstance(modalElem);
      if (modalInstance) modalInstance.hide();
      loadAlerts();
    } else {
      alert("Failed to update alert: " + data.error);
    }
  } catch (err) {
    alert("Network error: " + err.message);
  }
}
