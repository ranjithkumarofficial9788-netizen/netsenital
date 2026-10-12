import os
import click
from datetime import datetime, timezone
from flask import Flask, jsonify, render_template, request
from config import config_by_name, Config
from app.extensions import db, migrate, login_manager, csrf, limiter


def create_app(config_name: str = None) -> Flask:
    """Application factory for NetSential SOC Platform."""
    if config_name is None:
        config_name = os.getenv("FLASK_ENV", "default")

    app = Flask(__name__)
    config_class = config_by_name.get(config_name, Config)
    app.config.from_object(config_class)

    # Initialize Flask Extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Register Blueprints
    from app.auth import auth_bp
    from app.dashboard import dashboard_bp
    from app.events import events_bp
    from app.alerts import alerts_bp
    from app.uploads import uploads_bp
    from app.reports import reports_bp
    from app.audit import audit_bp
    from app.users import users_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(uploads_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(users_bp)

    # Register Global Template Context Processors
    @app.context_processor
    def inject_global_data():
        return {
            "current_year": datetime.now(timezone.utc).year,
            "soc_name": "NetSential SOC",
        }

    # Error Handlers with Dual Support (API JSON vs Browser HTML)
    @app.errorhandler(400)
    def bad_request_error(error):
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": str(error)}), 400
        return render_template("base.html", error_title="400 - Bad Request", error_message=str(error)), 400

    @app.errorhandler(403)
    def forbidden_error(error):
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Access forbidden: insufficient privileges"}), 403
        return render_template("base.html", error_title="403 - Forbidden", error_message="You lack permissions to access this resource."), 403

    @app.errorhandler(404)
    def not_found_error(error):
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Requested resource not found"}), 404
        return render_template("base.html", error_title="404 - Not Found", error_message="The requested SOC resource was not found."), 404

    @app.errorhandler(429)
    def ratelimit_handler(e):
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": f"Rate limit exceeded: {e.description}"}), 429
        return render_template("base.html", error_title="429 - Rate Limit Exceeded", error_message="Too many requests. Please slow down and try again later."), 429

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "error": "Internal security server error"}), 500
        return render_template("base.html", error_title="500 - Server Error", error_message="An internal system error occurred. Security team notified."), 500

    # Register CLI Commands
    register_cli_commands(app)

    return app


def register_cli_commands(app: Flask):
    """Register custom administrative and maintenance Flask CLI commands."""

    @app.cli.command("check-db")
    def check_db():
        """Verify database connectivity and check existing schema tables."""
        from sqlalchemy.exc import OperationalError
        with app.app_context():
            uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
            # Mask password in URI
            masked_uri = uri
            if "@" in uri and "://" in uri:
                prefix, rest = uri.split("://", 1)
                creds, host_part = rest.split("@", 1)
                user = creds.split(":", 1)[0]
                masked_uri = f"{prefix}://{user}:****@{host_part}"

            click.secho(f"Checking database connection: {masked_uri}", fg="cyan")
            try:
                conn = db.engine.connect()
                click.secho("SUCCESS: Successfully connected to database engine!", fg="green")
                # Check tables
                tables = list(db.metadata.tables.keys())
                click.secho(f"Models defined in metadata ({len(tables)}): {', '.join(tables)}", fg="cyan")
                conn.close()
            except OperationalError as oe:
                click.secho("FAILED: Could not establish connection to the database server.", fg="red", bold=True)
                click.secho(f"Details: {str(oe.orig) if hasattr(oe, 'orig') else str(oe)}", fg="yellow")
                click.secho("\nTroubleshooting tips:", fg="white", bold=True)
                click.secho("1. Ensure MySQL Server is installed and the Windows Service is running (e.g. 'Start-Service MySQL80').", fg="white")
                click.secho("2. Check host, port, username, and password in your .env file.", fg="white")
                click.secho("3. Ensure database 'netsential_db' was created (see schema.sql).", fg="white")
            except Exception as e:
                click.secho(f"Unexpected error: {str(e)}", fg="red")

    @app.cli.command("create-admin")
    @click.option("--username", prompt="Admin username", help="Administrator username")
    @click.option("--email", prompt="Admin email", help="Administrator email address")
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True, help="Secure password")
    def create_admin(username, email, password):
        """Provision the initial SOC administrator account securely."""
        from sqlalchemy.exc import OperationalError
        from app.models import User, utcnow
        
        with app.app_context():
            try:
                # Check if user already exists
                existing = User.query.filter((User.username == username) | (User.email == email)).first()
                if existing:
                    click.secho(f"Error: User with username '{username}' or email '{email}' already exists.", fg="red")
                    return

                admin_user = User(
                    username=username.strip(),
                    email=email.strip().lower(),
                    role="admin",
                    is_active=True,
                    created_at=utcnow(),
                )
                admin_user.set_password(password)
                db.session.add(admin_user)
                db.session.commit()
                click.secho(f"Success: Administrator account '{username}' created successfully.", fg="green")
            except OperationalError as oe:
                db.session.rollback()
                click.secho("Database Connection Error: Could not reach MySQL database server.", fg="red", bold=True)
                click.secho(f"Run 'flask check-db' for connection diagnostics.", fg="yellow")

    @app.cli.command("seed-data")
    @click.option("--admin-pass", default="AdminPass123!", help="Default password for seeded demo accounts")
    def seed_data(admin_pass):
        """Seed synthetic users, normalized security events, alerts, and audit logs."""
        from sqlalchemy.exc import OperationalError
        from app.models import User, SecurityEvent, Alert, AuditLog, UploadBatch, utcnow
        from datetime import datetime, timedelta, timezone

        with app.app_context():
            try:
                db.create_all()

                # 1. Create default admin and analyst if missing
                admin = User.query.filter_by(username="soc_admin").first()
                if not admin:
                    admin = User(
                        username="soc_admin",
                        email="admin@netsential.local",
                        role="admin",
                        is_active=True,
                        created_at=utcnow(),
                    )
                    admin.set_password(admin_pass)
                    db.session.add(admin)

                analyst = User.query.filter_by(username="soc_analyst").first()
                if not analyst:
                    analyst = User(
                        username="soc_analyst",
                        email="analyst@netsential.local",
                        role="analyst",
                        is_active=True,
                        created_at=utcnow(),
                    )
                    analyst.set_password(admin_pass)
                    db.session.add(analyst)

                db.session.commit()
                click.secho(f"Seeded accounts: 'soc_admin' (admin), 'soc_analyst' (analyst) [Password: {admin_pass}]", fg="cyan")

                # 2. Create demo batch
                batch = UploadBatch.query.filter_by(original_filename="synthetic_seed_events.csv").first()
                if not batch:
                    batch = UploadBatch(
                        original_filename="synthetic_seed_events.csv",
                        uploaded_by=admin.id,
                        total_rows=15,
                        accepted_rows=15,
                        rejected_rows=0,
                        status="completed",
                        created_at=utcnow(),
                    )
                    db.session.add(batch)
                    db.session.flush()

                # 3. Create synthetic security events if table is empty
                if SecurityEvent.query.count() == 0:
                    base_time = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=2)
                    seed_events_data = [
                        # Brute force attack sequence (matches AUTH-001)
                        {"t": base_time + timedelta(minutes=1), "type": "login_failure", "ip": "198.51.100.23", "user": "root", "stat": "failure", "sev": "HIGH", "msg": "Failed authentication attempt via SSH"},
                        {"t": base_time + timedelta(minutes=2), "type": "login_failure", "ip": "198.51.100.23", "user": "root", "stat": "failure", "sev": "HIGH", "msg": "Failed password for root"},
                        {"t": base_time + timedelta(minutes=2, seconds=30), "type": "login_failure", "ip": "198.51.100.23", "user": "root", "stat": "failure", "sev": "HIGH", "msg": "SSH authentication failure for user root"},
                        {"t": base_time + timedelta(minutes=3), "type": "login_failure", "ip": "198.51.100.23", "user": "root", "stat": "failure", "sev": "HIGH", "msg": "PAM authentication error for user root"},
                        {"t": base_time + timedelta(minutes=4), "type": "login_failure", "ip": "198.51.100.23", "user": "root", "stat": "failure", "sev": "HIGH", "msg": "Multiple consecutive failed logins detected"},
                        # Watchlisted IP match (matches IP-001)
                        {"t": base_time + timedelta(minutes=10), "type": "port_scan", "ip": "203.0.113.50", "user": None, "stat": "blocked", "sev": "MEDIUM", "msg": "SYN scan detected across ports 22, 80, 443, 3306"},
                        # Critical source event (matches EVENT-001)
                        {"t": base_time + timedelta(minutes=15), "type": "privilege_escalation", "ip": "10.0.4.15", "user": "appuser", "stat": "attempt", "sev": "CRITICAL", "msg": "Unexpected sudo execution invoking /bin/bash via CVE exploit pattern"},
                        # Normal events
                        {"t": base_time + timedelta(minutes=20), "type": "login_success", "ip": "192.168.1.50", "user": "analyst1", "stat": "success", "sev": "LOW", "msg": "User successfully logged into Web Console"},
                        {"t": base_time + timedelta(minutes=25), "type": "file_access", "ip": "10.0.1.20", "user": "dbadmin", "stat": "success", "sev": "LOW", "msg": "Read access to /etc/mysql/my.cnf"},
                        {"t": base_time + timedelta(minutes=30), "type": "login_success", "ip": "192.168.1.10", "user": "admin", "stat": "success", "sev": "LOW", "msg": "Administrator session started"},
                    ]

                    created_events = []
                    for sed in seed_events_data:
                        ev = SecurityEvent(
                            event_type=sed["type"],
                            source_ip=sed["ip"],
                            username=sed["user"],
                            status=sed["stat"],
                            severity=sed["sev"],
                            message=sed["msg"],
                            event_time=sed["t"],
                            created_at=utcnow(),
                            upload_batch_id=batch.id if batch else None,
                        )
                        db.session.add(ev)
                        created_events.append(ev)

                    db.session.commit()
                    click.secho(f"Created {len(created_events)} synthetic security events.", fg="green")

                    # Run threat detection engine on seeded events
                    from app.services.detection_engine import ThreatDetectionEngine
                    engine = ThreatDetectionEngine.from_config(app.config)
                    alerts = engine.run_detection()
                    click.secho(f"Detection engine generated {len(alerts)} initial alerts.", fg="yellow")

                # 4. Audit Log
                log = AuditLog.query.first()
                if not log and admin:
                    db.session.add(AuditLog(
                        user_id=admin.id,
                        action="SYSTEM_INIT",
                        details="NetSential SOC system initialized and synthetic seed data loaded.",
                        ip_address="127.0.0.1",
                        created_at=utcnow(),
                    ))
                    db.session.commit()

                click.secho("Seed completed successfully.", fg="green")
            except OperationalError as oe:
                db.session.rollback()
                click.secho("Database Connection Error: Could not reach MySQL database server.", fg="red", bold=True)
                click.secho("Run 'flask check-db' for connection diagnostics.", fg="yellow")

    @app.cli.command("run-detection")
    def run_detection_cli():
        """Run threat detection engine rules against all stored security events."""
        from app.services.detection_engine import ThreatDetectionEngine
        with app.app_context():
            engine = ThreatDetectionEngine.from_config(app.config)
            new_alerts = engine.run_detection()
            click.secho(f"Detection completed. Generated {len(new_alerts)} new alerts.", fg="green")

    @app.cli.command("reset-db")
    @click.confirmation_option(prompt="Are you sure you want to drop all tables and reset the database?")
    def reset_db():
        """Reset and recreate all tables in development database."""
        with app.app_context():
            db.drop_all()
            db.create_all()
            click.secho("Database tables dropped and recreated cleanly.", fg="yellow")
