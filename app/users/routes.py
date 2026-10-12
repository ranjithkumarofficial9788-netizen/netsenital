import re
from flask import render_template, request, jsonify, flash, redirect, url_for
from flask_login import current_user
from email_validator import validate_email, EmailNotValidError
from app.users import users_bp
from app.models import User, utcnow
from app.utils import admin_required, log_audit
from app.extensions import db


def validate_user_email(email_str: str) -> str:
    """Validate email address with support for public and internal SOC lab domains."""
    if not email_str or "@" not in email_str:
        raise ValueError("Invalid email format.")
    email_clean = email_str.strip().lower()
    try:
        valid_info = validate_email(email_clean, check_deliverability=False)
        return valid_info.normalized
    except EmailNotValidError:
        # Check standard RFC regex for private / internal SOC lab domains (.local, .internal, .lan, etc.)
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if re.match(pattern, email_clean):
            return email_clean
        raise ValueError("Invalid email address format.")


@users_bp.route("/users")
@admin_required
def index():
    """Administrator User Management view."""
    users = User.query.order_by(User.id.asc()).all()
    return render_template("users.html", users=users)


@users_bp.route("/api/users", methods=["GET"])
@admin_required
def list_users():
    """REST API endpoint to list all system users (admin only)."""
    users = User.query.order_by(User.id.asc()).all()
    return jsonify({
        "success": True,
        "users": [u.to_dict() for u in users],
    })


@users_bp.route("/api/users", methods=["POST"])
@admin_required
def create_user():
    """REST API endpoint to create a new user account (admin only)."""
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    email_raw = (data.get("email") or "").strip()
    password = data.get("password") or ""
    role = (data.get("role") or "analyst").strip().lower()

    # 1. Validate username
    if not username or len(username) < 3 or len(username) > 64:
        return jsonify({"success": False, "error": "Username must be between 3 and 64 characters."}), 400
    if not re.match(r"^[a-zA-Z0-9_\.-]+$", username):
        return jsonify({"success": False, "error": "Username contains invalid characters."}), 400

    # 2. Validate email
    try:
        email = validate_user_email(email_raw)
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400

    # 3. Validate password complexity
    if not password or len(password) < 8:
        return jsonify({"success": False, "error": "Password must be at least 8 characters long."}), 400

    # 4. Validate role
    if role not in ("analyst", "admin"):
        return jsonify({"success": False, "error": "Role must be 'analyst' or 'admin'."}), 400

    # 5. Check uniqueness
    if User.query.filter_by(username=username).first():
        return jsonify({"success": False, "error": f"Username '{username}' is already in use."}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"success": False, "error": f"Email '{email}' is already in use."}), 409

    new_user = User(
        username=username,
        email=email,
        role=role,
        is_active=True,
        created_at=utcnow(),
    )
    new_user.set_password(password)

    db.session.add(new_user)
    db.session.commit()

    log_audit(
        action="USER_CREATE",
        details=f"Admin '{current_user.username}' created new user '{username}' with role '{role}'",
        user_id=current_user.id,
    )

    return jsonify({
        "success": True,
        "message": f"User '{username}' created successfully.",
        "user": new_user.to_dict(),
    }), 201


@users_bp.route("/api/users/<int:user_id>", methods=["PATCH"])
@admin_required
def update_user(user_id: int):
    """REST API endpoint to update role or toggle is_active status (admin only)."""
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"success": False, "error": f"User #{user_id} not found."}), 404

    data = request.get_json(silent=True) or request.form

    # Prevent admin from deactivating or demoting themselves
    if user.id == current_user.id:
        if "is_active" in data and not data.get("is_active"):
            return jsonify({"success": False, "error": "You cannot deactivate your own administrative account."}), 400
        if "role" in data and data.get("role") != "admin":
            return jsonify({"success": False, "error": "You cannot remove administrator role from yourself."}), 400

    updated_fields = []

    if "is_active" in data:
        new_active = bool(data["is_active"])
        if user.is_active != new_active:
            user.is_active = new_active
            updated_fields.append(f"is_active={new_active}")

    if "role" in data:
        new_role = str(data["role"]).strip().lower()
        if new_role in ("analyst", "admin") and user.role != new_role:
            user.role = new_role
            updated_fields.append(f"role={new_role}")

    if updated_fields:
        db.session.commit()
        log_audit(
            action="USER_UPDATE",
            details=f"Admin '{current_user.username}' updated user '{user.username}': {', '.join(updated_fields)}",
            user_id=current_user.id,
        )

    return jsonify({
        "success": True,
        "message": f"User #{user.id} updated successfully.",
        "user": user.to_dict(),
    })
