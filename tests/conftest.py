import pytest
from app import create_app
from app.extensions import db
from app.models import User, utcnow


@pytest.fixture(scope="session")
def app():
    """Create Flask application instance configured for isolated testing."""
    test_app = create_app("testing")
    return test_app


@pytest.fixture(scope="function")
def db_session(app):
    """Provide a clean database session for each test."""
    with app.app_context():
        db.create_all()
        yield db.session
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app, db_session):
    """Test client bound to clean database session."""
    return app.test_client()


@pytest.fixture
def admin_user(db_session):
    """Create a verified test SOC Administrator."""
    user = User(
        username="test_admin",
        email="admin@test.local",
        role="admin",
        is_active=True,
        created_at=utcnow(),
    )
    user.set_password("AdminSecurePass123!")
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def analyst_user(db_session):
    """Create a verified test SOC Security Analyst."""
    user = User(
        username="test_analyst",
        email="analyst@test.local",
        role="analyst",
        is_active=True,
        created_at=utcnow(),
    )
    user.set_password("AnalystSecurePass123!")
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def inactive_user(db_session):
    """Create a disabled user account."""
    user = User(
        username="disabled_user",
        email="disabled@test.local",
        role="analyst",
        is_active=False,
        created_at=utcnow(),
    )
    user.set_password("DisabledPass123!")
    db_session.add(user)
    db_session.commit()
    return user
