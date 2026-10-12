from app.models import SecurityEvent, Alert, AuditLog, utcnow
from app.services.report_service import sanitize_csv_cell


def test_csv_formula_injection_sanitization():
    """Verify CWE-1236 mitigation: formula injection cells are prefixed with single quote."""
    dangerous_inputs = [
        "=cmd|' /C calc'!A0",
        "+SUM(A1:A10)",
        "-2+3+cmd|' /C notepad'!A0",
        "@SUM(1+1)",
        "\tmalicious_tab",
        "\rmalicious_return",
    ]

    for payload in dangerous_inputs:
        sanitized = sanitize_csv_cell(payload)
        assert sanitized.startswith("'"), f"Payload '{payload}' was not escaped with leading single quote"

    # Benign inputs should remain unchanged
    benign = "Normal Log Message from 192.168.1.1"
    assert sanitize_csv_cell(benign) == benign


def test_report_export_events(client, analyst_user, db_session):
    """Test generating a sanitized CSV events report with audit trail logging."""
    client.post("/login", data={
        "username": analyst_user.username,
        "password": "AnalystSecurePass123!",
    })

    # Add an event with a formula-like string to test live export sanitization
    ev = SecurityEvent(
        event_type="formula_test",
        source_ip="10.0.0.99",
        username="attacker",
        status="failure",
        severity="HIGH",
        message="=1+1; EXECUTE CALC",
        event_time=utcnow(),
        created_at=utcnow(),
    )
    db_session.add(ev)
    db_session.commit()

    res = client.get("/api/reports/export?type=events")
    assert res.status_code == 200
    assert res.mimetype == "text/csv"
    assert "attachment; filename=" in res.headers.get("Content-Disposition", "")

    csv_text = res.data.decode("utf-8")
    assert "Event ID" in csv_text
    assert "'=1+1; EXECUTE CALC" in csv_text  # properly escaped!

    # Verify audit log was recorded
    audit = AuditLog.query.filter_by(action="REPORT_EXPORT").first()
    assert audit is not None
    assert "Exported 1 events records" in audit.details


def test_unauthorized_report_export(client):
    """Ensure unauthenticated clients cannot download reports."""
    res = client.get("/api/reports/export?type=events")
    assert res.status_code == 302
    assert "/login" in res.headers.get("Location", "")
