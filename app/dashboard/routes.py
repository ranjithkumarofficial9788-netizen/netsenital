from datetime import datetime, timedelta, timezone
from flask import render_template, jsonify, request
from flask_login import login_required
from sqlalchemy import func, or_
from app.dashboard import dashboard_bp
from app.models import SecurityEvent, Alert, AuditLog
from app.extensions import db


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def index():
    """SOC Analyst Overview Dashboard."""
    return render_template("dashboard.html")


@dashboard_bp.route("/api/dashboard/stats", methods=["GET"])
@login_required
def dashboard_stats():
    """Return aggregated security metrics for top dashboard summary cards."""
    # 1. Total events
    total_events = db.session.query(func.count(SecurityEvent.id)).scalar() or 0

    # 2. Open alerts (NEW or ACKNOWLEDGED)
    open_alerts = db.session.query(func.count(Alert.id)).filter(
        Alert.status.in_(["NEW", "ACKNOWLEDGED"])
    ).scalar() or 0

    # 3. Critical unresolved alerts
    critical_unresolved = db.session.query(func.count(Alert.id)).filter(
        Alert.status.in_(["NEW", "ACKNOWLEDGED"]),
        Alert.severity == "CRITICAL"
    ).scalar() or 0

    # 4. Failed login attempts
    failed_logins = db.session.query(func.count(SecurityEvent.id)).filter(
        or_(
            SecurityEvent.status.in_(["failure", "denied", "blocked"]),
            SecurityEvent.event_type.ilike("%fail%")
        ),
        or_(
            SecurityEvent.event_type.ilike("%login%"),
            SecurityEvent.event_type.ilike("%auth%")
        )
    ).scalar() or 0

    # 5. Resolved alerts
    resolved_alerts = db.session.query(func.count(Alert.id)).filter(
        Alert.status == "RESOLVED"
    ).scalar() or 0

    return jsonify({
        "success": True,
        "data": {
            "total_events": total_events,
            "open_alerts": open_alerts,
            "critical_unresolved": critical_unresolved,
            "failed_logins": failed_logins,
            "resolved_alerts": resolved_alerts,
        }
    })


@dashboard_bp.route("/api/dashboard/events-over-time", methods=["GET"])
@login_required
def events_over_time():
    """Return chronological event aggregation grouped by day for Chart.js."""
    try:
        days = int(request.args.get("days", 7))
        days = max(1, min(days, 60))  # limit between 1 and 60 days
    except ValueError:
        days = 7

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    start_date = now - timedelta(days=days)

    # Fetch events within window
    events = db.session.query(SecurityEvent.event_time, SecurityEvent.severity).filter(
        SecurityEvent.event_time >= start_date
    ).order_by(SecurityEvent.event_time.asc()).all()

    # Create daily bucket map for consistent date series
    daily_buckets = {}
    for i in range(days + 1):
        d_str = (start_date + timedelta(days=i)).strftime("%Y-%m-%d")
        daily_buckets[d_str] = {"total": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    for ev_time, sev in events:
        if ev_time:
            d_str = ev_time.strftime("%Y-%m-%d")
            if d_str in daily_buckets:
                daily_buckets[d_str]["total"] += 1
                sev_key = (sev or "LOW").upper()
                if sev_key in daily_buckets[d_str]:
                    daily_buckets[d_str][sev_key] += 1

    labels = sorted(daily_buckets.keys())
    totals = [daily_buckets[k]["total"] for k in labels]
    low_counts = [daily_buckets[k]["LOW"] for k in labels]
    med_counts = [daily_buckets[k]["MEDIUM"] for k in labels]
    high_counts = [daily_buckets[k]["HIGH"] for k in labels]
    crit_counts = [daily_buckets[k]["CRITICAL"] for k in labels]

    return jsonify({
        "success": True,
        "labels": labels,
        "totals": totals,
        "breakdown": {
            "LOW": low_counts,
            "MEDIUM": med_counts,
            "HIGH": high_counts,
            "CRITICAL": crit_counts,
        }
    })


@dashboard_bp.route("/api/dashboard/severity-distribution", methods=["GET"])
@login_required
def severity_distribution():
    """Return event and alert count breakdown by severity."""
    # Events severity
    ev_counts = db.session.query(
        SecurityEvent.severity, func.count(SecurityEvent.id)
    ).group_by(SecurityEvent.severity).all()

    events_by_sev = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for sev, cnt in ev_counts:
        sev_upper = (sev or "LOW").upper()
        if sev_upper in events_by_sev:
            events_by_sev[sev_upper] = cnt

    # Alerts status distribution
    alert_status_counts = db.session.query(
        Alert.status, func.count(Alert.id)
    ).group_by(Alert.status).all()

    alerts_by_status = {"NEW": 0, "ACKNOWLEDGED": 0, "RESOLVED": 0}
    for stat, cnt in alert_status_counts:
        stat_upper = (stat or "NEW").upper()
        if stat_upper in alerts_by_status:
            alerts_by_status[stat_upper] = cnt

    return jsonify({
        "success": True,
        "events_severity": events_by_sev,
        "alerts_status": alerts_by_status,
    })


@dashboard_bp.route("/api/dashboard/recent-activity", methods=["GET"])
@login_required
def recent_activity():
    """Return the most recent security events and alerts for live SOC feed."""
    recent_events = SecurityEvent.query.order_by(SecurityEvent.event_time.desc()).limit(10).all()
    recent_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(5).all()

    return jsonify({
        "success": True,
        "events": [e.to_dict() for e in recent_events],
        "alerts": [a.to_dict() for a in recent_alerts],
    })
