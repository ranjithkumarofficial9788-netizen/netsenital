from flask import render_template, request, jsonify, current_app
from flask_login import login_required, current_user
from app.alerts import alerts_bp
from app.models import Alert, SecurityEvent, utcnow
from app.services.detection_engine import ThreatDetectionEngine
from app.utils import log_audit
from app.extensions import db

VALID_ALERT_STATUSES = {"NEW", "ACKNOWLEDGED", "RESOLVED"}


@alerts_bp.route("/alerts")
@login_required
def index():
    """Threat Alerts investigation HTML page."""
    return render_template("alerts.html")


@alerts_bp.route("/api/alerts", methods=["GET"])
@login_required
def list_alerts():
    """REST API endpoint to search, filter, and paginate Threat Alerts."""
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = max(1, min(int(request.args.get("per_page", 20)), 100))
    except ValueError:
        return jsonify({"success": False, "error": "Invalid pagination parameters"}), 400

    query = Alert.query

    # 1. Filter by severity
    severity = request.args.get("severity", "").strip().upper()
    if severity and severity != "ALL":
        if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            query = query.filter(Alert.severity == severity)

    # 2. Filter by status
    status = request.args.get("status", "").strip().upper()
    if status and status != "ALL":
        if status in VALID_ALERT_STATUSES:
            query = query.filter(Alert.status == status)

    # 3. Filter by rule_code
    rule_code = request.args.get("rule_code", "").strip().upper()
    if rule_code and rule_code != "ALL":
        query = query.filter(Alert.rule_code == rule_code)

    # Order newest first
    query = query.order_by(Alert.created_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        "success": True,
        "items": [item.to_dict() for item in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        "pages": pagination.pages,
        "per_page": pagination.per_page,
    })


@alerts_bp.route("/api/alerts/<int:alert_id>", methods=["GET"])
@login_required
def get_alert(alert_id: int):
    """Retrieve full detail for a single alert including triggered event data."""
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify({"success": False, "error": f"Alert #{alert_id} not found"}), 404

    return jsonify({
        "success": True,
        "alert": alert.to_dict(),
    })


@alerts_bp.route("/api/alerts/<int:alert_id>", methods=["PATCH"])
@login_required
def update_alert(alert_id: int):
    """
    Update alert status (e.g. Acknowledge, Resolve, Reopen).
    Validates state transitions and records audit trail.
    """
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify({"success": False, "error": f"Alert #{alert_id} not found"}), 404

    data = request.get_json(silent=True) or request.form
    new_status = (data.get("status") or "").strip().upper()

    if new_status not in VALID_ALERT_STATUSES:
        return jsonify({
            "success": False,
            "error": f"Invalid status '{new_status}'. Allowed: {', '.join(sorted(VALID_ALERT_STATUSES))}"
        }), 400

    old_status = alert.status
    if old_status == new_status:
        return jsonify({"success": True, "alert": alert.to_dict(), "message": "No change needed"}), 200

    # Apply status update
    alert.status = new_status
    if new_status == "RESOLVED":
        alert.resolved_at = utcnow()
        alert.resolved_by = current_user.id
    elif new_status in ("NEW", "ACKNOWLEDGED"):
        alert.resolved_at = None
        alert.resolved_by = None

    db.session.commit()

    log_audit(
        action="ALERT_UPDATE",
        details=f"Alert #{alert.id} ({alert.rule_code}) status changed from '{old_status}' to '{new_status}'",
        user_id=current_user.id,
    )

    return jsonify({
        "success": True,
        "message": f"Alert #{alert.id} updated to {new_status}",
        "alert": alert.to_dict(),
    })


@alerts_bp.route("/api/detection/run", methods=["POST"])
@login_required
def trigger_detection():
    """On-demand threat detection engine execution across all stored events."""
    engine = ThreatDetectionEngine.from_config(current_app.config)
    new_alerts = engine.run_detection()

    log_audit(
        action="DETECTION_RUN",
        details=f"Threat detection manually triggered; generated {len(new_alerts)} new alerts",
        user_id=current_user.id,
    )

    return jsonify({
        "success": True,
        "message": f"Threat detection completed. Generated {len(new_alerts)} new alerts.",
        "new_alerts_count": len(new_alerts),
        "alerts": [a.to_dict() for a in new_alerts],
    })
