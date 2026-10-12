import pytest


def test_login_success(client, analyst_user):
    """Test successful authentication with valid credentials."""
    response = client.post("/login", data={
        "username": analyst_user.username,
        "password": "AnalystSecurePass123!",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Security Operations Dashboard" in response.data or b"Overview" in response.data


def test_login_invalid_password(client, analyst_user):
    """Test authentication failure with incorrect password."""
    response = client.post("/login", data={
        "username": analyst_user.username,
        "password": "WrongPassword!",
    }, follow_redirects=True)
    assert response.status_code == 401
    assert b"Invalid username or password" in response.data


def test_login_nonexistent_user(client, db_session):
    """Test generic failure response for non-existent account."""
    response = client.post("/login", data={
        "username": "ghost_user",
        "password": "AnyPassword123!",
    }, follow_redirects=True)
    assert response.status_code == 401
    assert b"Invalid username or password" in response.data


def test_login_inactive_user(client, inactive_user):
    """Test login prevention for disabled accounts."""
    response = client.post("/login", data={
        "username": inactive_user.username,
        "password": "DisabledPass123!",
    }, follow_redirects=True)
    assert response.status_code == 403
    assert b"Account is disabled" in response.data


def test_logout(client, analyst_user):
    """Test logout invalidates session."""
    client.post("/login", data={
        "username": analyst_user.username,
        "password": "AnalystSecurePass123!",
    })
    logout_res = client.post("/logout", follow_redirects=True)
    assert logout_res.status_code == 200
    # Following requests to protected views should redirect to login
    dash_res = client.get("/dashboard")
    assert dash_res.status_code == 302


def test_unauthenticated_protected_routes(client):
    """Verify unauthorized requests to sensitive routes redirect to login."""
    protected_paths = [
        "/dashboard",
        "/events",
        "/alerts",
        "/uploads",
        "/reports",
        "/audit-logs",
        "/users",
    ]
    for path in protected_paths:
        res = client.get(path)
        assert res.status_code == 302, f"Route {path} did not redirect unauthenticated client"
        assert "/login" in res.headers.get("Location", "")


def test_rbac_analyst_cannot_access_user_management(client, analyst_user):
    """Ensure Security Analysts cannot access User Management (RBAC enforcement)."""
    client.post("/login", data={
        "username": analyst_user.username,
        "password": "AnalystSecurePass123!",
    })
    # HTML route
    res = client.get("/users")
    assert res.status_code == 403

    # API route
    api_res = client.get("/api/users")
    assert api_res.status_code == 403


def test_rbac_admin_can_access_user_management(client, admin_user):
    """Ensure Administrators can access User Management."""
    client.post("/login", data={
        "username": admin_user.username,
        "password": "AdminSecurePass123!",
    })
    res = client.get("/users")
    assert res.status_code == 200

    api_res = client.get("/api/users")
    assert api_res.status_code == 200
    json_data = api_res.get_json()
    assert json_data["success"] is True
