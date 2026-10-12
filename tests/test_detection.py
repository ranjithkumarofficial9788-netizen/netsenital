from datetime import datetime, timedelta, timezone
from app.models import SecurityEvent, Alert, utcnow
from app.services.detection_engine import ThreatDetectionEngine


def test_rule_auth_001_repeated_failed_logins(db_session):
    """Test AUTH-001: 5 failed logins within 5 minutes triggers HIGH alert."""
    engine = ThreatDetectionEngine(
        auth_failed_threshold=5,
        auth_failed_window_minutes=5,
        ip_watchlist=set()
    )

    base_time = datetime.now(timezone.utc).replace(tzinfo=None)
    events = []
    for i in range(5):
        ev = SecurityEvent(
            id=i + 1,
            event_type="login_failure",
            source_ip="198.51.100.44",
            username="target_user",
            status="failure",
            severity="HIGH",
            message=f"Failed password attempt {i+1}",
            event_time=base_time + timedelta(seconds=i * 30),
            created_at=utcnow(),
        )
        events.append(ev)

    alerts = engine.evaluate_events(events)
    assert len(alerts) == 1
    assert alerts[0]["rule_code"] == "AUTH-001"
    assert alerts[0]["severity"] == "HIGH"
    assert "target_user" in alerts[0]["description"]
    assert "198.51.100.44" in alerts[0]["description"]


def test_rule_auth_001_time_window_boundary(db_session):
    """Test AUTH-001 time-window: 5 failed logins spread over 20 minutes should NOT alert."""
    engine = ThreatDetectionEngine(
        auth_failed_threshold=5,
        auth_failed_window_minutes=5,
        ip_watchlist=set()
    )

    base_time = datetime.now(timezone.utc).replace(tzinfo=None)
    events = []
    # 5 attempts spaced 4 minutes apart = 16 minutes total span
    for i in range(5):
        ev = SecurityEvent(
            id=i + 1,
            event_type="login_failure",
            source_ip="198.51.100.44",
            username="target_user",
            status="failure",
            severity="HIGH",
            message=f"Failed attempt {i+1}",
            event_time=base_time + timedelta(minutes=i * 4),
            created_at=utcnow(),
        )
        events.append(ev)

    alerts = engine.evaluate_events(events)
    # Should not produce AUTH-001 because no rolling 5-minute slice contains >= 5 events
    auth_001_alerts = [a for a in alerts if a["rule_code"] == "AUTH-001"]
    assert len(auth_001_alerts) == 0


def test_rule_ip_001_watchlist_match():
    """Test IP-001: Match against local threat intelligence watchlist."""
    watchlist = {"203.0.113.99", "198.51.100.77"}
    engine = ThreatDetectionEngine(ip_watchlist=watchlist)

    base_time = datetime.now(timezone.utc).replace(tzinfo=None)
    ev = SecurityEvent(
        id=10,
        event_type="port_scan",
        source_ip="203.0.113.99",
        username=None,
        status="blocked",
        severity="MEDIUM",
        message="Port scan attempt",
        event_time=base_time,
        created_at=utcnow(),
    )

    alerts = engine.evaluate_events([ev])
    assert len(alerts) == 1
    assert alerts[0]["rule_code"] == "IP-001"
    assert alerts[0]["severity"] == "HIGH"
    assert "203.0.113.99" in alerts[0]["title"]


def test_rule_auth_002_excessive_login_volume():
    """Test AUTH-002: Excessive login attempt volume from a single IP."""
    engine = ThreatDetectionEngine(
        auth_volume_threshold=10,
        auth_volume_window_minutes=10,
        ip_watchlist=set()
    )

    base_time = datetime.now(timezone.utc).replace(tzinfo=None)
    events = []
    for i in range(10):
        ev = SecurityEvent(
            id=i + 1,
            event_type="login_attempt",
            source_ip="192.0.2.55",
            username=f"user_{i}",
            status="failure" if i % 2 == 0 else "success",
            severity="LOW",
            message=f"Login attempt {i+1}",
            event_time=base_time + timedelta(seconds=i * 20),
            created_at=utcnow(),
        )
        events.append(ev)

    alerts = engine.evaluate_events(events)
    auth_002 = [a for a in alerts if a["rule_code"] == "AUTH-002"]
    assert len(auth_002) == 1
    assert auth_002[0]["severity"] == "MEDIUM"


def test_rule_event_001_critical_source_event():
    """Test EVENT-001: Event marked CRITICAL by source creates alert."""
    engine = ThreatDetectionEngine(ip_watchlist=set())
    base_time = datetime.now(timezone.utc).replace(tzinfo=None)

    ev = SecurityEvent(
        id=42,
        event_type="ransomware_detected",
        source_ip="10.0.1.50",
        username="operator",
        status="blocked",
        severity="CRITICAL",
        message="Endpoint defense flagged ransomware execution",
        event_time=base_time,
        created_at=utcnow(),
    )

    alerts = engine.evaluate_events([ev])
    event_001 = [a for a in alerts if a["rule_code"] == "EVENT-001"]
    assert len(event_001) == 1
    assert event_001[0]["severity"] == "CRITICAL"


def test_alert_deduplication(db_session):
    """Test that running detection engine repeatedly prevents duplicate alerts."""
    engine = ThreatDetectionEngine(ip_watchlist={"198.51.100.23"})
    base_time = datetime.now(timezone.utc).replace(tzinfo=None)

    ev = SecurityEvent(
        event_type="port_scan",
        source_ip="198.51.100.23",
        username=None,
        status="blocked",
        severity="MEDIUM",
        message="SYN scan",
        event_time=base_time,
        created_at=utcnow(),
    )
    db_session.add(ev)
    db_session.commit()

    # First run
    alerts_1 = engine.run_detection(session=db_session)
    assert len(alerts_1) == 1
    assert Alert.query.count() == 1

    # Second run on same event
    alerts_2 = engine.run_detection(session=db_session)
    assert len(alerts_2) == 0
    assert Alert.query.count() == 1
