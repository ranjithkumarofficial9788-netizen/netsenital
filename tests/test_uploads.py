import io
from app.models import UploadBatch, SecurityEvent, Alert


def test_valid_csv_upload(client, analyst_user):
    """Test importing a valid security log CSV file."""
    client.post("/login", data={
        "username": analyst_user.username,
        "password": "AnalystSecurePass123!",
    })

    csv_data = (
        "timestamp,event_type,source_ip,username,status,severity,message\n"
        "2026-10-12 10:00:00,login_failure,198.51.100.23,root,failure,HIGH,Failed password\n"
        "2026-10-12 10:00:30,login_success,192.168.1.10,jdoe,success,LOW,User session started\n"
    )

    data = {
        "log_file": (io.BytesIO(csv_data.encode("utf-8")), "auth_events.csv")
    }

    res = client.post("/api/logs/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 201
    json_data = res.get_json()
    assert json_data["success"] is True
    assert json_data["accepted_count"] == 2
    assert json_data["rejected_count"] == 0
    assert SecurityEvent.query.count() == 2
    assert UploadBatch.query.count() == 1


def test_valid_jsonl_upload(client, analyst_user):
    """Test importing a valid JSON Lines security log file."""
    client.post("/login", data={
        "username": analyst_user.username,
        "password": "AnalystSecurePass123!",
    })

    jsonl_data = (
        '{"timestamp": "2026-10-12T10:00:00Z", "event_type": "port_scan", "source_ip": "203.0.113.50", "status": "blocked", "severity": "HIGH", "message": "SYN scan"}\n'
        '{"timestamp": "2026-10-12T10:01:00Z", "event_type": "web_req", "source_ip": "10.0.0.1", "status": "success", "severity": "LOW", "message": "GET /api"}\n'
    )

    data = {
        "log_file": (io.BytesIO(jsonl_data.encode("utf-8")), "security_stream.jsonl")
    }

    res = client.post("/api/logs/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 201
    json_data = res.get_json()
    assert json_data["success"] is True
    assert json_data["accepted_count"] == 2
    assert SecurityEvent.query.count() == 2


def test_malformed_csv_upload_graceful_rejection(client, analyst_user):
    """Test that malformed rows are rejected while valid rows are saved."""
    client.post("/login", data={
        "username": analyst_user.username,
        "password": "AnalystSecurePass123!",
    })

    csv_data = (
        "timestamp,event_type,source_ip,username,status,severity,message\n"
        "2026-10-12 10:00:00,login_failure,INVALID_IP,root,failure,HIGH,Bad IP address\n"
        "2026-10-12 10:00:30,login_success,192.168.1.10,jdoe,success,LOW,Valid row\n"
        "not-a-date,login_failure,192.168.1.11,admin,failure,LOW,Bad timestamp\n"
    )

    data = {
        "log_file": (io.BytesIO(csv_data.encode("utf-8")), "mixed_logs.csv")
    }

    res = client.post("/api/logs/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 201
    json_data = res.get_json()
    assert json_data["accepted_count"] == 1
    assert json_data["rejected_count"] == 2
    assert SecurityEvent.query.count() == 1


def test_invalid_file_extension(client, analyst_user):
    """Test rejecting files with unsupported extensions."""
    client.post("/login", data={
        "username": analyst_user.username,
        "password": "AnalystSecurePass123!",
    })

    data = {
        "log_file": (io.BytesIO(b"binary content"), "payload.exe")
    }

    res = client.post("/api/logs/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    json_data = res.get_json()
    assert json_data["success"] is False
    assert "not supported" in json_data["error"]


def test_empty_file_upload(client, analyst_user):
    """Test rejecting empty files."""
    client.post("/login", data={
        "username": analyst_user.username,
        "password": "AnalystSecurePass123!",
    })

    data = {
        "log_file": (io.BytesIO(b""), "empty.csv")
    }

    res = client.post("/api/logs/upload", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    json_data = res.get_json()
    assert json_data["success"] is False
