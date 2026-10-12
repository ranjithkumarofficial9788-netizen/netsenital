from datetime import datetime
from flask import render_template, request, jsonify, abort
from flask_login import login_required
from sqlalchemy import or_
from app.events import events_bp
from app.models import SecurityEvent, Alert
from app.extensions import db


@events_bp.route("/events")
@login_required
def index():
    """Security Events Explorer HTML page."""
    # Pre-fetch distinct event types for filter dropdown
    distinct_types = [
        r[0] for r in db.session.query(SecurityEvent.event_type).distinct().order_by(SecurityEvent.event_type).all()
        if r[0]
    ]
    return render_template("events.html", event_types=distinct_types)


@events_bp.route("/api/events", methods=["GET"])
@login_required
def list_events():
    """REST API endpoint to search, filter, and paginate Security Events."""
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = max(1, min(int(request.args.get("per_page", 20)), 100))
    except ValueError:
        return jsonify({"success": False, "error": "Invalid pagination parameters"}), 400

    query = SecurityEvent.query

    # 1. Free-text search (IP, username, message)
    q = request.args.get("q", "").strip()
    if q:
        search_pattern = f"%{q}%"
        query = query.filter(
            or_(
                SecurityEvent.source_ip.ilike(search_pattern),
                SecurityEvent.username.ilike(search_pattern),
                SecurityEvent.message.ilike(search_pattern),
                SecurityEvent.event_type.ilike(search_pattern),
            )
        )

    # 2. Filter by severity
    severity = request.args.get("severity", "").strip().upper()
    if severity and severity != "ALL":
        if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            query = query.filter(SecurityEvent.severity == severity)

    # 3. Filter by event_type
    event_type = request.args.get("event_type", "").strip().lower()
    if event_type and event_type != "all":
        query = query.filter(SecurityEvent.event_type == event_type)

    # 4. Filter by date range
    start_date_str = request.args.get("start_date", "").strip()
    if start_date_str:
        try:
            start_date = datetime.fromisoformat(start_date_str)
            query = query.filter(SecurityEvent.event_time >= start_date)
        except ValueError:
            pass

    end_date_str = request.args.get("end_date", "").strip()
    if end_date_str:
        try:
            end_date = datetime.fromisoformat(end_date_str)
            query = query.filter(SecurityEvent.event_time <= end_date)
        except ValueError:
            pass

    # 5. Sorting
    sort_order = request.args.get("sort", "desc").lower()
    if sort_order == "asc":
        query = query.order_by(SecurityEvent.event_time.asc())
    else:
        query = query.order_by(SecurityEvent.event_time.desc())

    # Paginate
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        "success": True,
        "items": [item.to_dict() for item in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        "pages": pagination.pages,
        "per_page": pagination.per_page,
    })


@events_bp.route("/api/events/<int:event_id>", methods=["GET"])
@login_required
def get_event(event_id: int):
    """Retrieve full detail for a single security event including triggering alerts."""
    event = db.session.get(SecurityEvent, event_id)
    if not event:
        return jsonify({"success": False, "error": f"Security event #{event_id} not found"}), 404

    alerts = Alert.query.filter_by(event_id=event.id).all()
    event_data = event.to_dict()
    event_data["alerts"] = [a.to_dict() for a in alerts]

    return jsonify({
        "success": True,
        "event": event_data,
    })
