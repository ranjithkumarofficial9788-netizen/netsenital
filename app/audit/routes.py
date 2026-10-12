from flask import render_template, request, jsonify
from flask_login import login_required
from app.audit import audit_bp
from app.models import AuditLog


@audit_bp.route("/audit-logs")
@login_required
def index():
    """Security Audit Trail review page."""
    return render_template("audit_logs.html")


@audit_bp.route("/api/audit-logs", methods=["GET"])
@login_required
def list_audit_logs():
    """REST API endpoint to paginate and inspect the immutable audit trail."""
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = max(1, min(int(request.args.get("per_page", 25)), 100))
    except ValueError:
        return jsonify({"success": False, "error": "Invalid pagination parameters"}), 400

    query = AuditLog.query

    action = request.args.get("action", "").strip()
    if action and action != "ALL":
        query = query.filter(AuditLog.action == action)

    query = query.order_by(AuditLog.created_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        "success": True,
        "items": [item.to_dict() for item in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        "pages": pagination.pages,
        "per_page": pagination.per_page,
    })
