from flask import render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_user, logout_user, login_required, current_user
from app.auth import auth_bp
from app.models import User
from app.utils import log_audit
from app.extensions import limiter, db


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config.get("RATELIMIT_LOGIN", "5 per minute"), methods=["POST"])
def login():
    """Security Analyst and Administrator Login endpoint."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("login.html"), 400

        user = User.query.filter_by(username=username).first()

        # Constant-time comparison / generic failure response
        if user is None or not user.check_password(password):
            log_audit(
                action="LOGIN_FAILED",
                details=f"Failed login attempt for username '{username}'",
                user_id=user.id if user else None,
            )
            flash("Invalid username or password.", "danger")
            return render_template("login.html"), 401

        if not user.is_active:
            log_audit(
                action="LOGIN_BLOCKED",
                details=f"Inactive account login attempt for user '{username}'",
                user_id=user.id,
            )
            flash("Account is disabled. Contact your SOC administrator.", "danger")
            return render_template("login.html"), 403

        login_user(user, remember=False)
        log_audit(
            action="LOGIN_SUCCESS",
            details=f"User '{user.username}' logged in successfully with role '{user.role}'",
            user_id=user.id,
        )

        next_page = request.args.get("next")
        if not next_page or not next_page.startswith("/"):
            next_page = url_for("dashboard.index")

        return redirect(next_page)

    return render_template("login.html")


@auth_bp.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    """Sign out the current analyst session."""
    user_id = current_user.id
    username = current_user.username
    logout_user()
    log_audit(
        action="LOGOUT",
        details=f"User '{username}' signed out of SOC console",
        user_id=user_id,
    )
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


# -------------------------------------------------------------------------
# REST API Authentication Endpoints
# -------------------------------------------------------------------------

@auth_bp.route("/api/auth/login", methods=["POST"])
@limiter.limit(lambda: current_app.config.get("RATELIMIT_LOGIN", "5 per minute"))
def api_login():
    """REST API Login endpoint returning JSON authentication status."""
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"success": False, "error": "Username and password required"}), 400

    user = User.query.filter_by(username=username).first()

    if user is None or not user.check_password(password):
        log_audit(
            action="API_LOGIN_FAILED",
            details=f"API failed login attempt for username '{username}'",
            user_id=user.id if user else None,
        )
        return jsonify({"success": False, "error": "Invalid username or password"}), 401

    if not user.is_active:
        log_audit(
            action="API_LOGIN_BLOCKED",
            details=f"API login attempt on disabled account for user '{username}'",
            user_id=user.id,
        )
        return jsonify({"success": False, "error": "Account is disabled. Contact SOC administrator."}), 403

    login_user(user, remember=False)
    log_audit(
        action="API_LOGIN_SUCCESS",
        details=f"API login success for user '{user.username}'",
        user_id=user.id,
    )

    return jsonify({
        "success": True,
        "message": "Authentication successful",
        "user": user.to_dict(),
    }), 200


@auth_bp.route("/api/auth/logout", methods=["POST"])
@login_required
def api_logout():
    """REST API Logout endpoint."""
    user_id = current_user.id
    username = current_user.username
    logout_user()
    log_audit(
        action="API_LOGOUT",
        details=f"API logout for user '{username}'",
        user_id=user_id,
    )
    return jsonify({"success": True, "message": "Signed out successfully"}), 200
