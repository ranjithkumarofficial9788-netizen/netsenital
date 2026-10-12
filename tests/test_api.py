from datetime import datetime, timedelta, timezone
from app.models import SecurityEvent, Alert, User, utcnow


def test_dashboard_stats_api(client, analyst_user, db_session):
    """Test dashboard aggregation endpoints compute metrics directly from database."""
    client.post("/login", data={
        "username": analyst_user.username,
        "password": "AnalystSecurePass123!",
    })

    # Seed events
    ev1 = SecurityEvent(event_type="login_failure", source_ip="192.168.1.1", status="failure", severity="HIGH", message="m1", event_time=utcnow(), created_at=utcnow())
    ev2 = SecurityEvent(event_type="login_success", source_ip="192.168.1.2", status="success", severity="LOW", message="m2", event_time=utcnow(), created_at=utcnow())
    db_session.add_all([ev1, ev2])
    db_session.flush()

    # Seed alerts
    al1 = Alert(event_id=ev1.id, rule_code="R1", title="A1", severity="CRITICAL", description="d1", status="NEW", created_at=utcnow())
    al2 = Alert(event_id=ev2.id, rule_code="R2", title="A2", severity="LOW", description="d2", status="RESOLVED", created_at=utcnow())
    db_session.add_all([al1, al2])
    db_session.commit()

    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    data = res.get_json()["data"]

    assert data["total_events"] == 2
    assert data["open_alerts"] == 1
    assert data["critical_unresolved"] == 1
    assert data["failed_logins"] == 1
    assert data["resolved_alerts"] == 1


def test_events_api_filtering_and_search(client, analyst_user, db_session):
    """Test events search API with text and severity filters."""
    client.post("/login", data={
        "username": analyst_user.username,
        "password": "AnalystSecurePass123!",
    })

    ev1 = SecurityEvent(event_type="port_scan", source_ip="203.0.113.10", username="hacker", status="blocked", severity="HIGH", message="Port scan detected", event_time=utcnow(), created_at=utcnow())
    ev2 = SecurityEvent(event_type="file_access", source_ip="10.0.0.5", username="admin", status="success", severity="LOW", message="Normal file read", event_time=utcnow(), created_at=utcnow())
    db_session.add_all([ev1, ev2])
    db_session.commit()

    # Search for "hacker"
    res1 = client.get("/api/events?q=hacker")
    assert res1.status_code == 200
    data1 = res1.get_json()
    assert data1["total"] == 1
    assert data1["items"][0]["source_ip"] == "203.0.113.10"

    # Filter severity "LOW"
    res2 = client.get("/api/events?severity=LOW")
    assert res2.status_code == 200
    data2 = res2.get_json()
    assert data2["total"] == 1
    assert data2["items"][0]["event_type"] == "file_access"


def test_user_provisioning_api(client, admin_user, analyst_user, db_session):
    """Test administrator can provision new users, but analyst cannot."""
    # Analyst attempt (should fail 403)
    client.post("/login", data={
        "username": analyst_user.username,
        "password": "AnalystSecurePass123!",
    })
    res_analyst = client.post("/api/users", json={
        "username": "new_analyst",
        "email": "new@soc.local",
        "password": "Password123!",
        "role": "analyst",
    })
    assert res_analyst.status_code == 403

    # Logout and login as Admin
    client.post("/logout")
    client.post("/login", data={
        "username": admin_user.username,
        "password": "AdminSecurePass123!",
    })

    # Admin attempt (should succeed 201)
    res_admin = client.post("/api/users", json={
        "username": "new_analyst",
        "email": "new@soc.local",
        "password": "Password123!",
        "role": "analyst",
    })
    assert res_admin.status_code == 201
    created_user = User.query.filter_by(username="new_analyst").first()
    assert created_user is not None
    assert created_user.check_password("Password123!") is True


def test_dashboard_charts_apis(client, analyst_user, db_session):
    """Test dashboard timeline and severity distribution endpoints."""
    client.post("/login", data={
        "username": analyst_user.username,
        "password": "AnalystSecurePass123!",
    })

    ev = SecurityEvent(
        event_type="test_probe",
        source_ip="192.168.1.5",
        status="failure",
        severity="HIGH",
        message="Test probe",
        event_time=utcnow(),
        created_at=utcnow(),
    )
    db_session.add(ev)
    db_session.commit()

    # Timeline
    timeline_res = client.get("/api/dashboard/events-over-time?days=7")
    assert timeline_res.status_code == 200
    timeline_data = timeline_res.get_json()
    assert timeline_data["success"] is True
    assert len(timeline_data["labels"]) > 0

    # Severity distribution
    sev_res = client.get("/api/dashboard/severity-distribution")
    assert sev_res.status_code == 200
    sev_data = sev_res.get_json()
    assert sev_data["success"] is True
    assert sev_data["events_severity"]["HIGH"] == 1

    # Recent activity
    rec_res = client.get("/api/dashboard/recent-activity")
    assert rec_res.status_code == 200
    rec_data = rec_res.get_json()
    assert rec_data["success"] is True
    assert len(rec_data["events"]) == 1


def test_audit_logs_api(client, analyst_user, db_session):
    """Test audit log querying and filtering."""
    client.post("/login", data={
        "username": analyst_user.username,
        "password": "AnalystSecurePass123!",
    })

    res = client.get("/api/audit-logs")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["total"] >= 1  # Login audit log created


def test_alert_export_csv_api(client, analyst_user, db_session):
    """Test alerts export endpoint."""
    client.post("/login", data={
        "username": analyst_user.username,
        "password": "AnalystSecurePass123!",
    })

    ev = SecurityEvent(event_type="test", source_ip="1.1.1.1", status="failure", severity="HIGH", message="msg", event_time=utcnow(), created_at=utcnow())
    db_session.add(ev)
    db_session.flush()

    al = Alert(event_id=ev.id, rule_code="TEST-01", title="Title", severity="HIGH", description="desc", status="NEW", created_at=utcnow())
    db_session.add(al)
    db_session.commit()

    res = client.get("/api/reports/export?type=alerts")
    assert res.status_code == 200
    assert res.mimetype == "text/csv"
    assert "TEST-01" in res.data.decode("utf-8")
