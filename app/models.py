from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from sqlalchemy import UniqueConstraint
from app.extensions import db, login_manager

def utcnow():
    """Return timezone-naive UTC datetime for standard database storage."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    """User account model supporting Analyst and Administrator SOC roles."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="analyst")  # 'admin' or 'analyst'
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    # Relationships
    uploads = db.relationship("UploadBatch", backref="uploader", lazy="dynamic")
    resolved_alerts = db.relationship("Alert", backref="resolver", foreign_keys="Alert.resolved_by", lazy="dynamic")
    audit_logs = db.relationship("AuditLog", backref="user", lazy="dynamic")

    def set_password(self, password: str):
        """Hash and store user password using Werkzeug's secure hashing."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify entered plaintext password against stored hash."""
        return check_password_hash(self.password_hash, password)

    def is_admin(self) -> bool:
        """Helper to verify if user has administrator privileges."""
        return self.role == "admin"

    def to_dict(self):
        """Serialize user data (excluding password hash)."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<User {self.username} [{self.role}]>"


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login user loader."""
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None


class UploadBatch(db.Model):
    """Log file upload tracking batch."""
    __tablename__ = "upload_batches"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    original_filename = db.Column(db.String(255), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    total_rows = db.Column(db.Integer, default=0, nullable=False)
    accepted_rows = db.Column(db.Integer, default=0, nullable=False)
    rejected_rows = db.Column(db.Integer, default=0, nullable=False)
    status = db.Column(db.String(30), default="completed", nullable=False)  # 'processing', 'completed', 'failed'
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    # Relationships
    events = db.relationship("SecurityEvent", backref="upload_batch", cascade="all, delete-orphan", lazy="dynamic")

    def to_dict(self):
        return {
            "id": self.id,
            "original_filename": self.original_filename,
            "uploaded_by": self.uploaded_by,
            "uploader_name": self.uploader.username if self.uploader else "System/Unknown",
            "total_rows": self.total_rows,
            "accepted_rows": self.accepted_rows,
            "rejected_rows": self.rejected_rows,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<UploadBatch {self.id}: {self.original_filename} ({self.status})>"


class SecurityEvent(db.Model):
    """Normalized security log event."""
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)  # Supports IPv4 and IPv6
    username = db.Column(db.String(64), nullable=True, index=True)
    status = db.Column(db.String(30), nullable=False, default="failure")  # 'failure', 'success', 'attempt', 'denied'
    severity = db.Column(db.String(20), nullable=False, index=True)  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    message = db.Column(db.Text, nullable=False)
    event_time = db.Column(db.DateTime, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    upload_batch_id = db.Column(db.Integer, db.ForeignKey("upload_batches.id", ondelete="SET NULL"), nullable=True, index=True)

    # Relationships
    alerts = db.relationship("Alert", backref="event", cascade="all, delete-orphan", lazy="dynamic")

    def to_dict(self):
        return {
            "id": self.id,
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "username": self.username,
            "status": self.status,
            "severity": self.severity,
            "message": self.message,
            "event_time": self.event_time.isoformat() if self.event_time else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "upload_batch_id": self.upload_batch_id,
            "alert_count": self.alerts.count() if hasattr(self, "alerts") else 0,
        }

    def __repr__(self):
        return f"<SecurityEvent {self.id}: {self.event_type} {self.source_ip} [{self.severity}]>"


class Alert(db.Model):
    """Security alert generated by detection engine rules."""
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("event_id", "rule_code", name="uq_alert_event_rule"),
    )

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    event_id = db.Column(db.Integer, db.ForeignKey("security_events.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_code = db.Column(db.String(32), nullable=False, index=True)
    title = db.Column(db.String(150), nullable=False)
    severity = db.Column(db.String(20), nullable=False, index=True)  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default="NEW", index=True)  # 'NEW', 'ACKNOWLEDGED', 'RESOLVED'
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "event_id": self.event_id,
            "rule_code": self.rule_code,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolved_by": self.resolved_by,
            "resolver_username": self.resolver.username if self.resolver else None,
            "event": self.event.to_dict() if self.event else None,
        }

    def __repr__(self):
        return f"<Alert {self.id}: [{self.rule_code}] {self.title} ({self.status})>"


class AuditLog(db.Model):
    """Immutable audit trail of security analyst and administrator actions."""
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action = db.Column(db.String(64), nullable=False, index=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.user.username if self.user else "Anonymous/System",
            "action": self.action,
            "details": self.details,
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<AuditLog {self.id}: {self.action} by User {self.user_id}>"
