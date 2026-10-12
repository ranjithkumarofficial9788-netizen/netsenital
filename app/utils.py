from functools import wraps
from flask import request, jsonify, abort, redirect, url_for, flash
from flask_login import current_user
from app.models import AuditLog, utcnow
from app.extensions import db


def admin_required(f):
    """Decorator to enforce administrator role for sensitive SOC actions."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Authentication required"}), 401
            return redirect(url_for("auth.login", next=request.url))

        if not current_user.is_admin():
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Administrator privileges required"}), 403
            flash("Access denied: Administrator privileges required.", "danger")
            abort(403)

        return f(*args, **kwargs)
    return decorated_function


def log_audit(action: str, details: str = None, user_id: int = None, ip_address: str = None):
    """
    Record an immutable action in the audit trail.
    Gracefully handles anonymous or system operations and extracts client IP.
    """
    try:
        resolved_user_id = user_id
        if resolved_user_id is None and current_user and current_user.is_authenticated:
            resolved_user_id = current_user.id

        resolved_ip = ip_address
        if resolved_ip is None and request:
            # Check for standard reverse proxy forwarded IP or direct remote address
            resolved_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            if resolved_ip and "," in resolved_ip:
                resolved_ip = resolved_ip.split(",")[0].strip()
            if resolved_ip:
                resolved_ip = resolved_ip[:45]

        audit_entry = AuditLog(
            user_id=resolved_user_id,
            action=action[:64],
            details=details[:2000] if details else None,
            ip_address=resolved_ip,
            created_at=utcnow(),
        )
        db.session.add(audit_entry)
        db.session.commit()
    except Exception as e:
        # Audit logging failure should not crash the parent transaction, but log to stderr
        db.session.rollback()
        print(f"[SECURITY ALERT] Audit logging failed for action '{action}': {str(e)}")
