import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base application configuration."""
    SECRET_KEY = os.getenv("SECRET_KEY", "soc-dev-secret-key-default-change-me")
    
    # MySQL Database Connection URL (MySQL 8+ compatible)
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "mysql+pymysql://netsential_user:netsential_pass@localhost:3306/netsential_db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 280,
        "pool_pre_ping": True,
    }
    
    # File Upload Security Controls
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", 5 * 1024 * 1024))  # 5 MB max
    ALLOWED_EXTENSIONS = {"csv", "jsonl", "log", "json"}
    UPLOAD_MAX_ROWS = int(os.getenv("UPLOAD_MAX_ROWS", 5000))  # Max events processed per batch
    
    # Session Cookie Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1")
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours
    
    # Rate Limiting Controls
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "200 per day; 50 per hour")
    RATELIMIT_LOGIN = os.getenv("RATELIMIT_LOGIN", "5 per minute")
    
    # Threat Detection Engine Rules Thresholds
    # Rule AUTH-001: Repeated Failed Logins
    AUTH_FAILED_THRESHOLD = int(os.getenv("AUTH_FAILED_THRESHOLD", 5))
    AUTH_FAILED_WINDOW_MINUTES = int(os.getenv("AUTH_FAILED_WINDOW_MINUTES", 5))
    
    # Rule AUTH-002: Excessive Login Volume
    AUTH_VOLUME_THRESHOLD = int(os.getenv("AUTH_VOLUME_THRESHOLD", 10))
    AUTH_VOLUME_WINDOW_MINUTES = int(os.getenv("AUTH_VOLUME_WINDOW_MINUTES", 10))
    
    # Rule IP-001: Local Watchlist of Malicious / Monitored IP Addresses
    _raw_watchlist = os.getenv("IP_WATCHLIST", "198.51.100.23,203.0.113.50,192.0.2.100,45.33.32.156")
    IP_WATCHLIST = set(ip.strip() for ip in _raw_watchlist.split(",") if ip.strip())


class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = True


class ProductionConfig(Config):
    """Production environment configuration with hardened defaults."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True


class TestingConfig(Config):
    """Testing environment configuration using synthetic isolated environment."""
    TESTING = True
    DEBUG = False
    # Test database defaults to in-memory SQLite if TEST_DATABASE_URL is not set,
    # ensuring test suite runs cleanly in isolated CI/local test environments.
    SQLALCHEMY_DATABASE_URI = os.getenv("TEST_DATABASE_URL", "sqlite:///:memory:")
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
