# NetSential — Cybersecurity Monitoring & Threat Detection Platform

[![Platform](https://img.shields.io/badge/Platform-Flask%20%7C%20MySQL%208+-0A2540.svg)](https://flask.palletsprojects.com/)
[![Security](https://img.shields.io/badge/Security-SOC%20Engine-00F2FE.svg)](#threat-detection-engine)
[![Tests](https://img.shields.io/badge/Tests-30%20Passed-10B981.svg)](#automated-testing)
[![Architecture](https://img.shields.io/badge/Architecture-Modular%20Blueprints-3B82F6.svg)](#architecture)

NetSential is a web-based Security Operations Center (SOC) monitoring and explainable threat detection platform designed for security analysts and incident response teams. It provides end-to-end ingestion of normalized security log records, rule-based behavioral threat correlation, alert lifecycle triage, immutable audit logging, and sanitized compliance report exports.

---

## 1. Problem Statement & Mission

Modern security teams need rapid visibility into emerging authentication abuse, reconnaissance scans, and endpoint indicators without the overwhelming complexity and licensing friction of proprietary enterprise SIEM solutions.

**NetSential** provides an accessible yet production-hardened platform for security personnel to:
1. Securely ingest standardized CSV and JSON Lines (JSONL) security event logs.
2. Normalize disparate log streams into a structured, indexed MySQL repository.
3. Automatically correlate events against explainable, configurable detection rules (brute-force detection, threat-intel IP watchlist matches, high-volume anomaly detection, and critical source flags).
4. Triage, acknowledge, and resolve alerts within an interactive SOC console.
5. Generate sanitized CSV compliance reports resistant to spreadsheet formula injection attacks (CWE-1236).

> **Important Responsible-Use Disclaimer:** NetSential operates exclusively on uploaded log files and verified database records. It does not perform active external network scanning, vulnerability exploitation, or unauthorized packet sniffing.

---

## 2. Key Features

- **SOC Dark Dashboard**: High-contrast, responsive interface featuring real-time metric counters, Chart.js chronological event trends, severity distribution graphs, and live activity streams.
- **Rule-Based Threat Detection Engine**: Independent, testable detection service implementing sliding-window aggregation and deduplicated alert correlation.
- **Multi-Format Log Ingestion**: Drag-and-drop ingestion of `.csv` and `.jsonl` security logs with strict IP address validation (`IPv4`/`IPv6`), timestamp normalization (UTC), and error resilience.
- **Alert Triage & Lifecycle Management**: Modal-driven investigation drawer allowing analysts to track alert states (`NEW` &rarr; `ACKNOWLEDGED` &rarr; `RESOLVED`) and record investigator attribution.
- **Role-Based Access Control (RBAC)**: Enforced segregation between Security Analysts (monitoring, alert investigation) and SOC Administrators (account provisioning, status toggles, user lifecycle).
- **Hardened Reporting**: Secure CSV report generation sanitizing untrusted inputs against CSV Formula Injection (CWE-1236).
- **Immutable Audit Trail**: Automatic recording of security-critical actions (logins, failures, uploads, detection runs, alert state changes, and report downloads) with remote IP tracking.
- **Brute-Force & Rate Limiting Defense**: Hardened login flow protected by Flask-Limiter and Werkzeug constant-time password hashing.

---

## 3. Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Backend** | Python 3.10+, Flask 3.0, Flask-SQLAlchemy, Flask-Login, Flask-WTF, Flask-Limiter, PyMySQL, python-dotenv |
| **Frontend** | HTML5, CSS3 (SOC Dark Navy Theme), Vanilla JavaScript (ES6+), Bootstrap 5, Bootstrap Icons, Chart.js 4.4 |
| **Database** | MySQL 8.0+ (InnoDB, UTF8mb4), SQLAlchemy ORM, Flask-Migrate (Alembic) |
| **Security Controls** | CSRF Protection (`Flask-WTF`), Rate Limiting (`Flask-Limiter`), Formula Injection Sanitization, Parametric SQL (`SQLAlchemy ORM`), Secure Cookies (`HttpOnly`, `SameSite=Lax`) |
| **Testing** | pytest 8.2, pytest-cov, Flask Test Client |

---

## 4. System Architecture

```mermaid
flowchart TD
    subgraph Ingestion["Log Ingestion Layer"]
        A1[CSV Security Logs] --> B[Log Parser Service]
        A2[JSONL Security Logs] --> B
        B -->|Validation & Normalization| C[UploadBatch & SecurityEvent Store]
    end

    subgraph Detection["Threat Detection Engine"]
        C --> D[Sliding Window Correlator]
        D -->|Rule: AUTH-001| E1[Repeated Failed Logins]
        D -->|Rule: IP-001| E2[Watchlisted IP Match]
        D -->|Rule: AUTH-002| E3[Excessive Login Volume]
        D -->|Rule: EVENT-001| E4[Critical Source Flag]
        E1 --> F[Alert Deduplication]
        E2 --> F
        E3 --> F
        E4 --> F
        F --> G[(MySQL 8 Database)]
    end

    subgraph SOC["Security Operations Console"]
        G --> H[Dashboard REST APIs]
        G --> I[Alerts Investigation]
        G --> J[Events Explorer]
        G --> K[Audit Trail Logger]
        H --> L[Chart.js / Responsive UI]
        I --> L
        J --> L
        K --> L
    end
```

---

## 5. Threat Detection Engine Rules

The detection engine (`app/services/detection_engine.py`) operates independently of HTTP routes and evaluates events chronologically using sliding-window state tracking:

| Rule Code | Title | Threshold / Trigger Condition | Default Severity | Description |
| :--- | :--- | :--- | :--- | :--- |
| **AUTH-001** | Brute Force Suspected | &ge; 5 failed login events for the same `(source_ip, username)` within 5 minutes | `HIGH` | Identifies credential stuffing or dictionary attacks against specific accounts. |
| **IP-001** | Watchlisted IP Activity | Event `source_ip` matches local IOC watchlist (`IP_WATCHLIST`) | `HIGH` | Flags activity from locally tracked malicious infrastructure. |
| **AUTH-002** | High Volume Login Activity | &ge; 10 login attempts from a single `source_ip` within 10 minutes | `MEDIUM` | Detects volumetric authentication flooding across distributed target names. |
| **EVENT-001** | Critical Source Event | Normalized event ingested with `severity == 'CRITICAL'` | `CRITICAL` | Escalates high-risk endpoint defense indicators (ransomware, unauthorized sudo). |

*All thresholds and watchlist addresses are configurable via `.env`.*

---

## 6. Database Schema Overview

```mermaid
erDiagram
    USERS ||--o{ UPLOAD_BATCHES : "uploads"
    USERS ||--o{ ALERTS : "resolves"
    USERS ||--o{ AUDIT_LOGS : "acts"
    UPLOAD_BATCHES ||--o{ SECURITY_EVENTS : "contains"
    SECURITY_EVENTS ||--o{ ALERTS : "triggers"

    USERS {
        int id PK
        varchar(64) username UK
        varchar(120) email UK
        varchar(255) password_hash
        varchar(20) role
        boolean is_active
        datetime created_at
    }

    UPLOAD_BATCHES {
        int id PK
        varchar(255) original_filename
        int uploaded_by FK
        int total_rows
        int accepted_rows
        int rejected_rows
        varchar(30) status
        datetime created_at
    }

    SECURITY_EVENTS {
        int id PK
        varchar(64) event_type
        varchar(45) source_ip
        varchar(64) username
        varchar(30) status
        varchar(20) severity
        text message
        datetime event_time
        datetime created_at
        int upload_batch_id FK
    }

    ALERTS {
        int id PK
        int event_id FK
        varchar(32) rule_code
        varchar(150) title
        varchar(20) severity
        text description
        varchar(20) status
        datetime created_at
        datetime resolved_at
        int resolved_by FK
    }

    AUDIT_LOGS {
        int id PK
        int user_id FK
        varchar(64) action
        text details
        varchar(45) ip_address
        datetime created_at
    }
```

The database includes explicit unique constraints (`uq_alert_event_rule`), cascade deletes from events to alerts, and indexes on frequently queried fields (`event_type`, `source_ip`, `event_time`, `severity`, `rule_code`, `status`).

---

## 7. REST API Documentation

All state-changing endpoints (`POST`, `PATCH`) require authentication and valid CSRF tokens (`X-CSRFToken` header).

| Endpoint | Method | Role | Description |
| :--- | :--- | :--- | :--- |
| `/api/auth/login` | `POST` | Public (Rate Limited) | Authenticate user session and return analyst profile. |
| `/api/auth/logout` | `POST` | Authenticated | Terminate active user session. |
| `/api/dashboard/stats` | `GET` | Analyst / Admin | Total events, open alerts, critical unresolved, failed logins, resolved count. |
| `/api/dashboard/events-over-time` | `GET` | Analyst / Admin | Chronological event volume buckets for Chart.js. Query param: `?days=7`. |
| `/api/dashboard/severity-distribution` | `GET` | Analyst / Admin | Event and alert counts categorized by severity. |
| `/api/dashboard/recent-activity` | `GET` | Analyst / Admin | Recent 10 events and recent 5 security alerts. |
| `/api/events` | `GET` | Analyst / Admin | Paginated security events with `q`, `severity`, `event_type`, and date filters. |
| `/api/events/<id>` | `GET` | Analyst / Admin | Event detail including correlated alerts. |
| `/api/logs/upload` | `POST` | Analyst / Admin | Multipart log ingestion (`.csv`, `.jsonl`). Triggers real-time detection. |
| `/api/logs/uploads` | `GET` | Analyst / Admin | Paginated log upload batch records. |
| `/api/detection/run` | `POST` | Analyst / Admin | On-demand threat detection engine execution across events. |
| `/api/alerts` | `GET` | Analyst / Admin | Paginated alerts with `severity`, `status`, and `rule_code` filtering. |
| `/api/alerts/<id>` | `GET` | Analyst / Admin | Alert investigation detail and correlated source event. |
| `/api/alerts/<id>` | `PATCH` | Analyst / Admin | Update alert status (`NEW`, `ACKNOWLEDGED`, `RESOLVED`). |
| `/api/reports/export` | `GET` | Analyst / Admin | Generate sanitized CSV export (`?type=events` or `?type=alerts`). |
| `/api/audit-logs` | `GET` | Analyst / Admin | Paginated immutable audit trail with category filter. |
| `/api/users` | `GET` | Admin Only | List all analyst and administrator accounts. |
| `/api/users` | `POST` | Admin Only | Provision new analyst or administrator account. |
| `/api/users/<id>` | `PATCH` | Admin Only | Update role or toggle account active/disabled state. |

---

## 8. Installation & Setup Guide

### 8.1. Prerequisites

- **Python**: Version 3.10 or higher.
- **MySQL**: MySQL Server 8.0+ running on `localhost:3306` (or a remote host).

---

### 8.2. Windows (PowerShell) Setup

1. **Clone and enter the directory**:
   ```powershell
   cd "c:\Users\Mini\Documents\Cyber Level 5"
   ```

2. **Create and activate the virtual environment**:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. **Install dependencies**:
   ```powershell
   pip install -r requirements.txt
   ```

4. **Configure environment variables**:
   Copy `.env.example` to `.env`:
   ```powershell
   Copy-Item .env.example .env
   ```
   *Edit `.env` to match your local MySQL credentials.*

5. **Configure MySQL Database**:
   Log into MySQL as root and create the application database and dedicated least-privileged user:
   ```sql
   CREATE DATABASE IF NOT EXISTS netsential_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   CREATE USER IF NOT EXISTS 'netsential_user'@'localhost' IDENTIFIED BY 'netsential_pass';
   GRANT ALL PRIVILEGES ON netsential_db.* TO 'netsential_user'@'localhost';
   FLUSH PRIVILEGES;
   ```

6. **Initialize Database Tables**:
   Execute either via Flask-Migrate or direct schema:
   ```powershell
   # Option A: Using Flask-Migrate (Recommended)
   flask db upgrade

   # Option B: Using Direct SQL Script
   Get-Content schema.sql | mysql -u netsential_user -p netsential_db
   ```

7. **Create Initial Administrator Account**:
   ```powershell
   flask create-admin --username admin_sec --email admin@netsential.local
   # Enter password securely when prompted
   ```

8. **(Optional) Load Synthetic Demonstration Data**:
   Populates analyst accounts, normalized logs, triggered alerts, and audit entries:
   ```powershell
   flask seed-data --admin-pass "AdminPass123!"
   ```
   *Default seeded accounts: `soc_admin` (Admin) & `soc_analyst` (Analyst) [Password: `AdminPass123!`]*

9. **Run the Development Server**:
   ```powershell
   python run.py
   ```
   *Navigate to [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.*

---

### 8.3. Linux / macOS (Bash) Setup

```bash
# 1. Virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Dependencies
pip install -r requirements.txt

# 3. Environment configuration
cp .env.example .env

# 4. Database migrations & bootstrap
flask db upgrade
flask create-admin --username admin_sec --email admin@netsential.local
flask seed-data

# 5. Start application
python run.py
```

---

## 9. Deploying to Vercel

The Flask application runs as a Vercel Python Function. Vercel's function filesystem
is temporary, so production requires a reachable hosted MySQL database; do not use
SQLite or rely on local files for persistent data. Uploaded logs are parsed during
the request and their records are stored in MySQL.

1. Create a MySQL 8-compatible hosted database that allows connections from Vercel.
   Apply the schema to it from your local machine using the database URL:

   ```powershell
   $env:DATABASE_URL = "mysql+pymysql://USER:PASSWORD@HOST:3306/DATABASE"
   .\.venv\Scripts\flask.exe --app run.py db upgrade
   .\.venv\Scripts\flask.exe --app run.py create-admin
   Remove-Item Env:DATABASE_URL
   ```

   Use a URL-encoded password if it contains characters such as `@`, `:`, `/`, or `#`.
   The administrator command prompts for the account details and password.

2. In the [Vercel dashboard](https://vercel.com/new), import this GitHub repository.
   Keep the project root directory at the repository root. Vercel uses
   `api/index.py`, `vercel.json`, and the root `requirements.txt` to build and route
   the Flask application; no frontend build command is needed.

3. In the Vercel project's **Settings → Environment Variables**, add these variables
   for Production (and Preview too, if you will deploy previews):

   | Name | Value |
   | --- | --- |
   | `DATABASE_URL` | `mysql+pymysql://USER:PASSWORD@HOST:3306/DATABASE` |
   | `SECRET_KEY` | A unique, random secret; generate locally with `python -c "import secrets; print(secrets.token_hex(32))"` |
   | `MAX_CONTENT_LENGTH` | `4194304` (4 MiB, below Vercel's request-body limit) |

   Keep these values in Vercel's environment settings, not in Git or the repository's
   `.env` file. The app uses secure session cookies in production.

4. Deploy (or redeploy after adding the environment variables), then open the
   deployment URL. Sign in with the administrator account created in step 1.

---

## 10. Automated Testing

NetSential includes an automated test suite verifying detection rules, sliding windows, log parser resilience, RBAC enforcement, CSV injection sanitization, and REST APIs.

Run tests with pytest:
```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

Run test suite with code coverage:
```powershell
.\.venv\Scripts\python.exe -m pytest --cov=app --cov-report=term-missing
```

### Verified Test Suite Results (Observed):
```text
tests/test_alerts.py::test_alert_lifecycle PASSED                        [  3%]
tests/test_alerts.py::test_invalid_alert_status_transition PASSED        [  6%]
tests/test_api.py::test_dashboard_stats_api PASSED                       [ 10%]
tests/test_api.py::test_events_api_filtering_and_search PASSED           [ 13%]
tests/test_api.py::test_user_provisioning_api PASSED                     [ 16%]
tests/test_api.py::test_dashboard_charts_apis PASSED                     [ 20%]
tests/test_api.py::test_audit_logs_api PASSED                            [ 23%]
tests/test_api.py::test_alert_export_csv_api PASSED                      [ 26%]
tests/test_auth.py::test_login_success PASSED                            [ 30%]
tests/test_auth.py::test_login_invalid_password PASSED                   [ 33%]
tests/test_auth.py::test_login_nonexistent_user PASSED                   [ 36%]
tests/test_auth.py::test_login_inactive_user PASSED                      [ 40%]
tests/test_auth.py::test_logout PASSED                                   [ 43%]
tests/test_auth.py::test_unauthenticated_protected_routes PASSED         [ 46%]
tests/test_auth.py::test_rbac_analyst_cannot_access_user_management PASSED [ 50%]
tests/test_auth.py::test_rbac_admin_can_access_user_management PASSED    [ 53%]
tests/test_detection.py::test_rule_auth_001_repeated_failed_logins PASSED [ 56%]
tests/test_detection.py::test_rule_auth_001_time_window_boundary PASSED  [ 60%]
tests/test_detection.py::test_rule_ip_001_watchlist_match PASSED         [ 63%]
tests/test_detection.py::test_rule_auth_002_excessive_login_volume PASSED [ 66%]
tests/test_detection.py::test_rule_event_001_critical_source_event PASSED [ 70%]
tests/test_detection.py::test_alert_deduplication PASSED                 [ 73%]
tests/test_reports.py::test_csv_formula_injection_sanitization PASSED    [ 76%]
tests/test_reports.py::test_report_export_events PASSED                  [ 80%]
tests/test_reports.py::test_unauthorized_report_export PASSED            [ 83%]
tests/test_uploads.py::test_valid_csv_upload PASSED                      [ 86%]
tests/test_uploads.py::test_valid_jsonl_upload PASSED                    [ 90%]
tests/test_uploads.py::test_malformed_csv_upload_graceful_rejection PASSED [ 93%]
tests/test_uploads.py::test_invalid_file_extension PASSED                [ 96%]
tests/test_uploads.py::test_empty_file_upload PASSED                     [100%]

============================= 30 passed in 5.23s ==============================
```

---

## 11. Security Hardening Measures

1. **SQL Injection Defense**: All database operations utilize SQLAlchemy ORM with bound parameters and prepared statements.
2. **Cross-Site Scripting (XSS)**: Strict Jinja2 template auto-escaping combined with standard DOM text encoding for dynamic JavaScript renders.
3. **Cross-Site Request Forgery (CSRF)**: Flask-WTF CSRF tokens required on state-changing requests; automated CSRF injection in `secureFetch()` frontend client.
4. **CSV Formula Injection Mitigation (CWE-1236)**: Cells beginning with `=`, `+`, `-`, `@`, `\t`, or `\r` are sanitized with leading single quotes before export.
5. **Rate Limiting**: Flask-Limiter protects `/login` and `/api/auth/login` (5 attempts per minute per IP).
6. **Session Hardening**: Cookies configured with `HttpOnly=True`, `SameSite=Lax`, and `SESSION_COOKIE_SECURE` in production.
7. **Least Privilege**: Application database operations are segregated under a dedicated `netsential_user` MySQL account.

---

## 12. Known Limitations & Roadmap

### Known Limitations:
- Log ingestion is currently file-based (batch upload of `.csv` or `.jsonl`). It does not yet include continuous syslog (RFC 5424) socket listeners.
- Real-time notification webhooks (Slack/Teams/PagerDuty) are not yet integrated.
- The local Windows environment currently does not have an active MySQL server service installed; database instructions for installing and connecting to MySQL 8+ are documented in Section 8.

### Future Improvements:
- Native Syslog / TLS UDP/TCP listener daemon.
- Automated Sigma rule converter for detection engine rule expansion.
- PDF executive incident briefing export.
- Multi-factor authentication (TOTP/WebAuthn) for SOC analysts.

---

## 13. License & Author

Developed by the **NetSential Cybersecurity Engineering Team**. Released under the MIT License for portfolio, educational, and authorized security monitoring applications.
