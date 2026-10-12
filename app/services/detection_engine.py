from datetime import timedelta
from typing import List, Dict, Set, Tuple
from app.models import SecurityEvent, Alert, utcnow
from app.extensions import db


class DetectionRule:
    """Base class for explainable detection rules."""
    def __init__(self, code: str, title: str, severity: str, description: str):
        self.code = code
        self.title = title
        self.severity = severity
        self.description = description


class ThreatDetectionEngine:
    """Independent threat detection engine for rule-based security event analysis."""

    def __init__(
        self,
        auth_failed_threshold: int = 5,
        auth_failed_window_minutes: int = 5,
        auth_volume_threshold: int = 10,
        auth_volume_window_minutes: int = 10,
        ip_watchlist: Set[str] = None,
    ):
        self.auth_failed_threshold = auth_failed_threshold
        self.auth_failed_window = timedelta(minutes=auth_failed_window_minutes)
        self.auth_volume_threshold = auth_volume_threshold
        self.auth_volume_window = timedelta(minutes=auth_volume_window_minutes)
        self.ip_watchlist = set(ip_watchlist) if ip_watchlist else set()

    @classmethod
    def from_config(cls, app_config):
        """Instantiate detection engine using Flask application configuration."""
        return cls(
            auth_failed_threshold=getattr(app_config, "AUTH_FAILED_THRESHOLD", 5),
            auth_failed_window_minutes=getattr(app_config, "AUTH_FAILED_WINDOW_MINUTES", 5),
            auth_volume_threshold=getattr(app_config, "AUTH_VOLUME_THRESHOLD", 10),
            auth_volume_window_minutes=getattr(app_config, "AUTH_VOLUME_WINDOW_MINUTES", 10),
            ip_watchlist=getattr(app_config, "IP_WATCHLIST", set()),
        )

    def evaluate_events(
        self,
        events: List[SecurityEvent],
        existing_alert_keys: Set[Tuple[int, str]] = None
    ) -> List[Dict]:
        """
        Evaluate a sequence of SecurityEvent objects against all detection rules.
        Uses efficient sliding-window algorithms to maintain O(N log N) performance.
        Returns a list of alert dictionaries ready for persistence.
        """
        if not events:
            return []

        if existing_alert_keys is None:
            existing_alert_keys = set()

        alerts_to_create = []
        # Sort events chronologically to allow accurate sliding-window analysis
        sorted_events = sorted(events, key=lambda e: (e.event_time, e.id if e.id else 0))

        # Sliding window state
        # (source_ip, username) -> list of (event_time, event_id)
        failed_logins_by_user_ip: Dict[Tuple[str, str], List[Tuple]] = {}
        # source_ip -> list of (event_time, event_id)
        login_volume_by_ip: Dict[str, List[Tuple]] = {}

        for event in sorted_events:
            ev_id = event.id
            ev_time = event.event_time
            ev_type = (event.event_type or "").lower()
            ev_status = (event.status or "").lower()
            ev_ip = event.source_ip
            ev_user = (event.username or "").strip()
            ev_sev = (event.severity or "").upper()

            # -------------------------------------------------------------
            # Rule IP-001: Watchlisted IP Detection
            # -------------------------------------------------------------
            if ev_ip in self.ip_watchlist:
                key = (ev_id, "IP-001")
                if key not in existing_alert_keys:
                    alerts_to_create.append({
                        "event_id": ev_id,
                        "rule_code": "IP-001",
                        "title": f"Watchlisted IP Activity Detected ({ev_ip})",
                        "severity": "HIGH",
                        "description": (
                            f"Event matches locally maintained threat intelligence watchlist for IP address {ev_ip}. "
                            f"Action '{ev_type}' observed. Note: This indicates a local watchlist match, "
                            f"not absolute evidence of remote compromise."
                        ),
                    })
                    existing_alert_keys.add(key)

            # -------------------------------------------------------------
            # Rule EVENT-001: Critical Source Event
            # -------------------------------------------------------------
            if ev_sev == "CRITICAL":
                key = (ev_id, "EVENT-001")
                if key not in existing_alert_keys:
                    alerts_to_create.append({
                        "event_id": ev_id,
                        "rule_code": "EVENT-001",
                        "title": f"Critical Source Event: {ev_type.upper()}",
                        "severity": "CRITICAL",
                        "description": (
                            f"Source log marked this event as CRITICAL severity: '{event.message}'. "
                            f"Origin IP: {ev_ip}, User: {ev_user or 'N/A'}. "
                            f"Source-provided severity must be investigated and mapped according to internal incident response policy."
                        ),
                    })
                    existing_alert_keys.add(key)

            # -------------------------------------------------------------
            # Login Event Filtering for AUTH-001 and AUTH-002
            # -------------------------------------------------------------
            is_login_type = any(term in ev_type for term in ("login", "auth", "signin", "session"))

            if is_login_type:
                # Track for AUTH-002 (Volume)
                vol_window_start = ev_time - self.auth_volume_window
                ip_vol_history = login_volume_by_ip.setdefault(ev_ip, [])
                ip_vol_history.append((ev_time, ev_id))
                # Purge items outside rolling window
                ip_vol_history = [item for item in ip_vol_history if item[0] >= vol_window_start]
                login_volume_by_ip[ev_ip] = ip_vol_history

                if len(ip_vol_history) >= self.auth_volume_threshold:
                    key = (ev_id, "AUTH-002")
                    if key not in existing_alert_keys:
                        alerts_to_create.append({
                            "event_id": ev_id,
                            "rule_code": "AUTH-002",
                            "title": f"Excessive Login Attempts Volume from {ev_ip}",
                            "severity": "MEDIUM",
                            "description": (
                                f"Observed {len(ip_vol_history)} authentication attempts from IP {ev_ip} "
                                f"within a rolling {int(self.auth_volume_window.total_seconds() / 60)}-minute window. "
                                f"Exceeds configured volume threshold of {self.auth_volume_threshold}."
                            ),
                        })
                        existing_alert_keys.add(key)

                # Track for AUTH-001 (Failed logins)
                is_failure = ev_status in ("failure", "denied", "blocked", "error") or "fail" in ev_type
                if is_failure and ev_user:
                    user_ip_key = (ev_ip, ev_user)
                    fail_window_start = ev_time - self.auth_failed_window
                    fail_history = failed_logins_by_user_ip.setdefault(user_ip_key, [])
                    fail_history.append((ev_time, ev_id))
                    # Purge items outside rolling window
                    fail_history = [item for item in fail_history if item[0] >= fail_window_start]
                    failed_logins_by_user_ip[user_ip_key] = fail_history

                    if len(fail_history) >= self.auth_failed_threshold:
                        key = (ev_id, "AUTH-001")
                        if key not in existing_alert_keys:
                            alerts_to_create.append({
                                "event_id": ev_id,
                                "rule_code": "AUTH-001",
                                "title": f"Repeated Failed Logins / Brute Force Suspected ({ev_user})",
                                "severity": "HIGH",
                                "description": (
                                    f"Detected {len(fail_history)} consecutive failed login attempts for target user '{ev_user}' "
                                    f"from source IP {ev_ip} within {int(self.auth_failed_window.total_seconds() / 60)} minutes. "
                                    f"Exceeds configured brute-force threshold of {self.auth_failed_threshold}."
                                ),
                            })
                            existing_alert_keys.add(key)

        return alerts_to_create

    def run_detection(self, session=None, event_ids: List[int] = None) -> List[Alert]:
        """
        Execute detection engine against database events and persist deduplicated alerts.
        """
        sess = session or db.session

        if event_ids:
            # Query specified events plus any recent context events needed for sliding windows
            target_events = sess.query(SecurityEvent).filter(SecurityEvent.id.in_(event_ids)).all()
            if not target_events:
                return []
            earliest_time = min(e.event_time for e in target_events) - max(self.auth_failed_window, self.auth_volume_window)
            latest_time = max(e.event_time for e in target_events)
            events_to_evaluate = sess.query(SecurityEvent).filter(
                SecurityEvent.event_time >= earliest_time,
                SecurityEvent.event_time <= latest_time
            ).order_by(SecurityEvent.event_time.asc()).all()
        else:
            # Evaluate all events
            events_to_evaluate = sess.query(SecurityEvent).order_by(SecurityEvent.event_time.asc()).all()

        if not events_to_evaluate:
            return []

        # Load existing alerts to prevent duplicate generation
        existing_rows = sess.query(Alert.event_id, Alert.rule_code).all()
        existing_alert_keys = {(row.event_id, row.rule_code) for row in existing_rows}

        raw_alerts = self.evaluate_events(events_to_evaluate, existing_alert_keys)

        created_alerts = []
        for alert_data in raw_alerts:
            # Double check deduplication in case of duplicate in batch
            new_alert = Alert(
                event_id=alert_data["event_id"],
                rule_code=alert_data["rule_code"],
                title=alert_data["title"],
                severity=alert_data["severity"],
                description=alert_data["description"],
                status="NEW",
                created_at=utcnow(),
            )
            sess.add(new_alert)
            created_alerts.append(new_alert)

        if created_alerts:
            sess.commit()

        return created_alerts
