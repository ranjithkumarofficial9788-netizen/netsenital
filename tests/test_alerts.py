from app.models import SecurityEvent, Alert, AuditLog, utcnow


def test_alert_lifecycle(client, analyst_user, db_session):
    """Test full threat alert investigation workflow: Create -> Ack -> Resolve."""
    client.post("/login", data={
        "username": analyst_user.username,
        "password": "AnalystSecurePass123!",
    })

    # Create dummy event and alert
    ev = SecurityEvent(
        event_type="login_failure",
        source_ip="198.51.100.23",
        username="root",
        status="failure",
        severity="HIGH",
        message="Brute force test",
        event_time=utcnow(),
        created_at=utcnow(),
    )
    db_session.add(ev)
    db_session.flush()

    alert = Alert(
        event_id=ev.id,
        rule_code="AUTH-001",
        title="Brute Force Suspected",
        severity="HIGH",
        description="5 failed logins observed",
        status="NEW",
        created_at=utcnow(),
    )
    db_session.add(alert)
    db_session.commit()

    # 1. Fetch Alert Details
    get_res = client.get(f"/api/alerts/{alert.id}")
    assert get_res.status_code == 200
    alert_json = get_res.get_json()["alert"]
    assert alert_json["status"] == "NEW"
    assert alert_json["rule_code"] == "AUTH-001"

    # 2. Transition NEW -> ACKNOWLEDGED
    ack_res = client.patch(f"/api/alerts/{alert.id}", json={"status": "ACKNOWLEDGED"})
    assert ack_res.status_code == 200
    updated_alert = db_session.get(Alert, alert.id)
    assert updated_alert.status == "ACKNOWLEDGED"

    # 3. Transition ACKNOWLEDGED -> RESOLVED
    res_res = client.patch(f"/api/alerts/{alert.id}", json={"status": "RESOLVED"})
    assert res_res.status_code == 200
    resolved_alert = db_session.get(Alert, alert.id)
    assert resolved_alert.status == "RESOLVED"
    assert resolved_alert.resolved_by == analyst_user.id
    assert resolved_alert.resolved_at is not None

    # 4. Verify Audit Log entry created
    audit = AuditLog.query.filter_by(action="ALERT_UPDATE").first()
    assert audit is not None
    assert f"Alert #{alert.id}" in audit.details


def test_invalid_alert_status_transition(client, analyst_user, db_session):
    """Test rejection of invalid alert status."""
    client.post("/login", data={
        "username": analyst_user.username,
        "password": "AnalystSecurePass123!",
    })

    ev = SecurityEvent(
        event_type="test",
        source_ip="10.0.0.1",
        status="failure",
        severity="LOW",
        message="Test",
        event_time=utcnow(),
        created_at=utcnow(),
    )
    db_session.add(ev)
    db_session.flush()

    alert = Alert(
        event_id=ev.id,
        rule_code="TEST-001",
        title="Test Alert",
        severity="LOW",
        description="Test",
        status="NEW",
        created_at=utcnow(),
    )
    db_session.add(alert)
    db_session.commit()

    res = client.patch(f"/api/alerts/{alert.id}", json={"status": "INVALID_STATUS"})
    assert res.status_code == 400
    json_data = res.get_json()
    assert json_data["success"] is False
    assert "Invalid status" in json_data["error"]
