import csv
import io
import json
import ipaddress
from datetime import datetime, timezone

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_STATUSES = {"success", "failure", "attempt", "denied", "blocked", "error", "unknown"}

DATETIME_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y/%m/%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
]


def parse_timestamp(value: str) -> datetime:
    """Parse various timestamp string formats into a timezone-naive UTC datetime."""
    if not value or not str(value).strip():
        raise ValueError("Missing timestamp")
    val_str = str(value).strip()
    
    # Try ISO fromisoformat first
    try:
        dt = datetime.fromisoformat(val_str.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        pass

    for fmt in DATETIME_FORMATS:
        try:
            dt = datetime.strptime(val_str, fmt)
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except ValueError:
            continue

    raise ValueError(f"Invalid timestamp format: '{value}'")


def validate_ip(ip_str: str) -> str:
    """Validate IPv4 or IPv6 address and return normalized string."""
    if not ip_str or not str(ip_str).strip():
        raise ValueError("Missing IP address")
    clean = str(ip_str).strip()
    # ipaddress.ip_address handles IPv4 and IPv6 validation strictly
    parsed = ipaddress.ip_address(clean)
    return str(parsed)


def normalize_record(raw: dict, row_num: int) -> dict:
    """Validate and normalize a raw security event dictionary."""
    # 1. Timestamp
    raw_time = raw.get("timestamp") or raw.get("event_time") or raw.get("time") or raw.get("@timestamp")
    event_time = parse_timestamp(raw_time)

    # 2. Source IP
    raw_ip = raw.get("source_ip") or raw.get("src_ip") or raw.get("ip") or raw.get("client_ip")
    source_ip = validate_ip(raw_ip)

    # 3. Event Type
    raw_type = raw.get("event_type") or raw.get("type") or raw.get("action")
    if not raw_type or not str(raw_type).strip():
        raise ValueError("Missing event_type")
    event_type = str(raw_type).strip().lower()[:64]

    # 4. Severity
    raw_sev = raw.get("severity") or raw.get("level") or "LOW"
    severity = str(raw_sev).strip().upper()
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity '{severity}'. Allowed: {', '.join(sorted(VALID_SEVERITIES))}")

    # 5. Status
    raw_status = raw.get("status") or raw.get("outcome") or "failure"
    status = str(raw_status).strip().lower()[:30]
    if status not in VALID_STATUSES:
        status = "unknown"

    # 6. Username
    raw_user = raw.get("username") or raw.get("user") or raw.get("account")
    username = str(raw_user).strip()[:64] if raw_user and str(raw_user).strip() else None

    # 7. Message
    raw_msg = raw.get("message") or raw.get("msg") or raw.get("description")
    if not raw_msg or not str(raw_msg).strip():
        message = f"Security event {event_type} from {source_ip}"
    else:
        message = str(raw_msg).strip()[:2000]

    return {
        "event_time": event_time,
        "source_ip": source_ip,
        "event_type": event_type,
        "severity": severity,
        "status": status,
        "username": username,
        "message": message,
    }


def parse_csv_stream(stream, max_rows: int = 5000):
    """Parse security logs from a CSV stream."""
    accepted = []
    rejected = []
    
    # Read text with universal newlines
    if isinstance(stream, bytes):
        text_data = stream.decode("utf-8", errors="replace")
    elif hasattr(stream, "read"):
        content = stream.read()
        text_data = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
    else:
        text_data = str(stream)

    if not text_data or not text_data.strip():
        raise ValueError("Uploaded CSV file is completely empty")

    reader = csv.DictReader(io.StringIO(text_data))
    if not reader.fieldnames:
        raise ValueError("CSV file contains no headers or is empty")

    # Normalize header names (lowercase, stripped)
    cleaned_fieldnames = {col: col.strip().lower() for col in reader.fieldnames if col}
    
    for idx, row in enumerate(reader, start=1):
        if idx > max_rows:
            rejected.append({"row": idx, "error": f"Upload limit exceeded (max {max_rows} rows)"})
            break

        # Map row keys to lowercase
        normalized_row = {cleaned_fieldnames.get(k, k): v for k, v in row.items() if k is not None}
        
        try:
            record = normalize_record(normalized_row, idx)
            accepted.append(record)
        except Exception as e:
            rejected.append({"row": idx, "error": str(e), "data_snippet": str(row)[:120]})

    return accepted, rejected


def parse_jsonl_stream(stream, max_rows: int = 5000):
    """Parse security logs from a JSON Lines (JSONL) stream."""
    accepted = []
    rejected = []

    if isinstance(stream, bytes):
        text_data = stream.decode("utf-8", errors="replace")
    elif hasattr(stream, "read"):
        content = stream.read()
        text_data = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
    else:
        text_data = str(stream)

    if not text_data or not text_data.strip():
        raise ValueError("Uploaded JSONL file is completely empty")

    lines = text_data.splitlines()
    for idx, line in enumerate(lines, start=1):
        clean_line = line.strip()
        if not clean_line:
            continue
        if idx > max_rows:
            rejected.append({"row": idx, "error": f"Upload limit exceeded (max {max_rows} rows)"})
            break

        try:
            raw_dict = json.loads(clean_line)
            if not isinstance(raw_dict, dict):
                raise ValueError("JSON line is not a valid object/dictionary")
            record = normalize_record(raw_dict, idx)
            accepted.append(record)
        except json.JSONDecodeError as jde:
            rejected.append({"row": idx, "error": f"Malformed JSON: {str(jde)}", "data_snippet": clean_line[:120]})
        except Exception as e:
            rejected.append({"row": idx, "error": str(e), "data_snippet": clean_line[:120]})

    return accepted, rejected


def parse_log_file(filename: str, file_stream, max_rows: int = 5000):
    """Detect file format based on extension/content and execute parsing."""
    fname = filename.lower()
    if fname.endswith(".jsonl") or fname.endswith(".json"):
        return parse_jsonl_stream(file_stream, max_rows=max_rows)
    elif fname.endswith(".csv") or fname.endswith(".log"):
        # Attempt CSV parsing
        return parse_csv_stream(file_stream, max_rows=max_rows)
    else:
        raise ValueError(f"Unsupported file format for '{filename}'. Supported: .csv, .jsonl, .json, .log")
