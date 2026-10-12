from datetime import datetime, timezone
from flask import render_template, request, Response, jsonify
from flask_login import login_required, current_user
from app.reports import reports_bp
from app.models import SecurityEvent, Alert
from app.services.report_service import export_events_csv, export_alerts_csv
from app.utils import log_audit


@reports_bp.route("/reports")
@login_required
def index():
    """Security Incident & Compliance Reporting view."""
    return render_template("reports.html")


@reports_bp.route("/api/reports/export", methods=["GET"])
@login_required
def export_csv():
    """
    Generate and stream sanitized CSV exports of Security Events or Alerts.
    Protects against CSV Formula Injection (CWE-1236).
    """
    report_type = request.args.get("type", "events").strip().lower()
    severity = request.args.get("severity", "").strip().upper()
    start_date_str = request.args.get("start_date", "").strip()
    end_date_str = request.args.get("end_date", "").strip()
    limit = max(1, min(int(request.args.get("limit", 2000)), 10000))

    now_utc = datetime.now(timezone.utc)
    timestamp_str = now_utc.strftime("%Y%m%d_%H%M%S")

    if report_type == "alerts":
        query = Alert.query
        status = request.args.get("status", "").strip().upper()
        if status and status != "ALL":
            query = query.filter(Alert.status == status)
        if severity and severity != "ALL":
            query = query.filter(Alert.severity == severity)
        if start_date_str:
            try:
                query = query.filter(Alert.created_at >= datetime.fromisoformat(start_date_str))
            except ValueError:
                pass
        if end_date_str:
            try:
                query = query.filter(Alert.created_at <= datetime.fromisoformat(end_date_str))
            except ValueError:
                pass

        records = query.order_by(Alert.created_at.desc()).limit(limit).all()
        csv_content = export_alerts_csv(records)
        filename = f"netsential_alerts_export_{timestamp_str}.csv"
        record_count = len(records)

    else:
        # Default: Events
        query = SecurityEvent.query
        if severity and severity != "ALL":
            query = query.filter(SecurityEvent.severity == severity)
        if start_date_str:
            try:
                query = query.filter(SecurityEvent.event_time >= datetime.fromisoformat(start_date_str))
            except ValueError:
                pass
        if end_date_str:
            try:
                query = query.filter(SecurityEvent.event_time <= datetime.fromisoformat(end_date_str))
            except ValueError:
                pass

        records = query.order_by(SecurityEvent.event_time.desc()).limit(limit).all()
        csv_content = export_events_csv(records)
        filename = f"netsential_events_export_{timestamp_str}.csv"
        record_count = len(records)

    # Record audit log
    log_audit(
        action="REPORT_EXPORT",
        details=f"Exported {record_count} {report_type} records to CSV ({filename})",
        user_id=current_user.id,
    )

    return Response(
        csv_content,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=\"{filename}\"",
            "Content-Type": "text/csv; charset=utf-8",
            "Cache-Control": "no-cache, no-store, must-revalidate",
        }
    )
