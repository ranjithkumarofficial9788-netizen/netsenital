// NetSential Security Events Explorer JavaScript Logic

let currentEventPage = 1;
const eventsPerPage = 20;

document.addEventListener("DOMContentLoaded", () => {
  loadEvents();

  const filterForm = document.getElementById("eventsFilterForm");
  if (filterForm) {
    filterForm.addEventListener("submit", (e) => {
      e.preventDefault();
      currentEventPage = 1;
      loadEvents();
    });
  }

  const resetBtn = document.getElementById("resetFiltersBtn");
  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      document.getElementById("filterSearch").value = "";
      document.getElementById("filterSeverity").value = "ALL";
      document.getElementById("filterEventType").value = "all";
      document.getElementById("filterStartDate").value = "";
      document.getElementById("filterEndDate").value = "";
      currentEventPage = 1;
      loadEvents();
    });
  }

  const prevBtn = document.getElementById("prevPageBtn");
  const nextBtn = document.getElementById("nextPageBtn");
  if (prevBtn) {
    prevBtn.addEventListener("click", () => {
      if (currentEventPage > 1) {
        currentEventPage--;
        loadEvents();
      }
    });
  }
  if (nextBtn) {
    nextBtn.addEventListener("click", () => {
      currentEventPage++;
      loadEvents();
    });
  }

  const exportBtn = document.getElementById("exportFilteredEventsBtn");
  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      const q = document.getElementById("filterSearch").value.trim();
      const sev = document.getElementById("filterSeverity").value;
      const start = document.getElementById("filterStartDate").value;
      const end = document.getElementById("filterEndDate").value;
      let exportUrl = `/api/reports/export?type=events&severity=${encodeURIComponent(sev)}&start_date=${encodeURIComponent(start)}&end_date=${encodeURIComponent(end)}`;
      window.location.href = exportUrl;
    });
  }
});

async function loadEvents() {
  const tbody = document.getElementById("eventsTableBody");
  if (!tbody) return;

  const q = document.getElementById("filterSearch")?.value.trim() || "";
  const severity = document.getElementById("filterSeverity")?.value || "ALL";
  const eventType = document.getElementById("filterEventType")?.value || "all";
  const startDate = document.getElementById("filterStartDate")?.value || "";
  const endDate = document.getElementById("filterEndDate")?.value || "";

  const params = new URLSearchParams({
    page: currentEventPage,
    per_page: eventsPerPage,
    q: q,
    severity: severity,
    event_type: eventType,
    start_date: startDate,
    end_date: endDate,
  });

  tbody.innerHTML = `<tr><td colspan="9" class="text-center py-4 text-muted"><span class="spinner-border spinner-border-sm"></span> Querying security events...</td></tr>`;

  try {
    const res = await secureFetch(`/api/events?${params.toString()}`);
    const data = await res.json();
    if (!data.success) {
      tbody.innerHTML = `<tr><td colspan="9" class="text-center py-4 text-danger">Error: ${data.error || 'Failed to fetch events'}</td></tr>`;
      return;
    }

    const items = data.items;
    const badge = document.getElementById("totalEventsBadge");
    if (badge) badge.textContent = `${data.total.toLocaleString()} events`;

    const info = document.getElementById("paginationInfo");
    if (info) {
      const startNum = data.total === 0 ? 0 : (data.page - 1) * data.per_page + 1;
      const endNum = Math.min(data.page * data.per_page, data.total);
      info.textContent = `Showing ${startNum} - ${endNum} of ${data.total.toLocaleString()} (Page ${data.page} of ${Math.max(1, data.pages)})`;
    }

    const prevBtn = document.getElementById("prevPageBtn");
    const nextBtn = document.getElementById("nextPageBtn");
    if (prevBtn) prevBtn.disabled = data.page <= 1;
    if (nextBtn) nextBtn.disabled = data.page >= data.pages;

    if (items.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="9" class="text-center py-5">
            <div class="soc-empty-state">
              <div class="soc-empty-icon"><i class="bi bi-shield-slash"></i></div>
              <h6 class="text-dark">No security events found</h6>
              <p class="text-muted small">Try relaxing your search terms or date range filters.</p>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = items.map(ev => `
      <tr>
        <td class="text-muted">#${ev.id}</td>
        <td class="text-nowrap small text-muted">${formatDate(ev.event_time)}</td>
        <td><span class="badge bg-light border text-dark">${escapeHtml(ev.event_type)}</span></td>
        <td><code>${escapeHtml(ev.source_ip)}</code></td>
        <td class="text-muted">${escapeHtml(ev.username || "—")}</td>
        <td><span class="badge bg-light border text-secondary text-uppercase" style="font-size: 0.7rem;">${escapeHtml(ev.status)}</span></td>
        <td><span class="badge-sev badge-sev-${ev.severity.toLowerCase()}">${ev.severity}</span></td>
        <td class="text-truncate" style="max-width: 250px;" title="${escapeHtml(ev.message)}">${escapeHtml(ev.message)}</td>
        <td class="text-end">
          <button class="btn btn-sm btn-soc-secondary py-0 px-2" onclick="viewEventDetails(${ev.id})" title="Inspect Event">
            <i class="bi bi-eye"></i>
          </button>
        </td>
      </tr>
    `).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="9" class="text-center py-4 text-danger">Network Error: ${err.message}</td></tr>`;
  }
}

async function viewEventDetails(eventId) {
  const modalElem = document.getElementById("eventDetailModal");
  const modalBody = document.getElementById("eventModalBody");
  if (!modalElem || !modalBody) return;

  const bsModal = new bootstrap.Modal(modalElem);
  modalBody.innerHTML = `<div class="text-center py-4"><span class="spinner-border text-info"></span></div>`;
  bsModal.show();

  try {
    const res = await secureFetch(`/api/events/${eventId}`);
    const data = await res.json();
    if (!data.success) {
      modalBody.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
      return;
    }

    const ev = data.event;
    let alertsHtml = `<span class="text-muted">None triggered for this event.</span>`;
    if (ev.alerts && ev.alerts.length > 0) {
      alertsHtml = ev.alerts.map(a => `
        <div class="p-2 mb-2 rounded bg-light border d-flex justify-content-between align-items-center">
          <div>
            <span class="badge-sev badge-sev-${a.severity.toLowerCase()} me-2">${a.severity}</span>
            <strong class="text-dark">${escapeHtml(a.title)}</strong>
            <div class="small text-muted">${escapeHtml(a.description)}</div>
          </div>
          <span class="badge bg-secondary">${a.status}</span>
        </div>
      `).join("");
    }

    modalBody.innerHTML = `
      <div class="row g-3">
        <div class="col-md-6">
          <label class="text-muted small text-uppercase">Event ID</label>
          <div class="fw-bold text-dark">#${ev.id}</div>
        </div>
        <div class="col-md-6">
          <label class="text-muted small text-uppercase">Timestamp</label>
          <div class="fw-bold text-dark">${formatDate(ev.event_time)} UTC</div>
        </div>
        <div class="col-md-6">
          <label class="text-muted small text-uppercase">Source IP</label>
          <div><code>${escapeHtml(ev.source_ip)}</code></div>
        </div>
        <div class="col-md-6">
          <label class="text-muted small text-uppercase">Username</label>
          <div class="fw-bold text-dark">${escapeHtml(ev.username || "Anonymous / N/A")}</div>
        </div>
        <div class="col-md-6">
          <label class="text-muted small text-uppercase">Event Type</label>
          <div><span class="badge bg-light border text-dark">${escapeHtml(ev.event_type)}</span></div>
        </div>
        <div class="col-md-6">
          <label class="text-muted small text-uppercase">Severity / Status</label>
          <div>
            <span class="badge-sev badge-sev-${ev.severity.toLowerCase()} me-2">${ev.severity}</span>
            <span class="badge bg-secondary text-uppercase">${escapeHtml(ev.status)}</span>
          </div>
        </div>
        <div class="col-12">
          <label class="text-muted small text-uppercase">Raw Security Log Message</label>
          <div class="soc-code">${escapeHtml(ev.message)}</div>
        </div>
        <div class="col-12 mt-3">
          <label class="text-muted small text-uppercase fw-semibold mb-2">Correlated Threat Alerts (${ev.alerts ? ev.alerts.length : 0})</label>
          <div>${alertsHtml}</div>
        </div>
      </div>
    `;
  } catch (err) {
    modalBody.innerHTML = `<div class="alert alert-danger">Failed to load event details: ${err.message}</div>`;
  }
}
