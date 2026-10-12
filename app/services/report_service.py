import csv
import io
from datetime import datetime, timezone
from typing import List, Any
from app.models import SecurityEvent, Alert


def sanitize_csv_cell(value: Any) -> str:
    """
    Sanitize cell value to protect against CSV formula injection (CSV Injection / CWE-1236).
    If a cell begins with '=', '+', '-', '@', '\t', '\r', it could be interpreted as a dynamic
    formula by spreadsheet applications (Microsoft Excel, LibreOffice Calc, etc.).
    Prefixing with a single quote (') forces spreadsheet parsers to treat it as plain text.
    """
    if value is None:
        return ""
    val_str = str(value)
    if val_str and val_str[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{val_str}"
    return val_str


def export_events_csv(events: List[SecurityEvent]) -> str:
    """Generate secure CSV export for filtered SecurityEvent records."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    # Header comments / metadata
    writer.writerow(["# NetSential Security Operations Center - Events Export"])
    writer.writerow(["# Generated At (UTC)", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")])
    writer.writerow(["# Total Records", len(events)])
    writer.writerow([])

    # Table headers
    headers = [
        "Event ID",
        "Timestamp (UTC)",
        "Event Type",
        "Source IP",
        "Username",
        "Status",
        "Severity",
        "Message",
        "Upload Batch ID",
    ]
    writer.writerow(headers)

    for ev in events:
        row = [
            sanitize_csv_cell(ev.id),
            sanitize_csv_cell(ev.event_time.strftime("%Y-%m-%d %H:%M:%S") if ev.event_time else ""),
            sanitize_csv_cell(ev.event_type),
            sanitize_csv_cell(ev.source_ip),
            sanitize_csv_cell(ev.username or "N/A"),
            sanitize_csv_cell(ev.status),
            sanitize_csv_cell(ev.severity),
            sanitize_csv_cell(ev.message),
            sanitize_csv_cell(ev.upload_batch_id or "Direct/Manual"),
        ]
        writer.writerow(row)

    return output.getvalue()


def export_alerts_csv(alerts: List[Alert]) -> str:
    """Generate secure CSV export for filtered Alert records."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    writer.writerow(["# NetSential Security Operations Center - Alerts Export"])
    writer.writerow(["# Generated At (UTC)", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")])
    writer.writerow(["# Total Records", len(alerts)])
    writer.writerow([])

    headers = [
        "Alert ID",
        "Created (UTC)",
        "Rule Code",
        "Title",
        "Severity",
        "Status",
        "Triggering Event ID",
        "Resolved At (UTC)",
        "Resolved By User",
        "Description",
    ]
    writer.writerow(headers)

    for al in alerts:
        row = [
            sanitize_csv_cell(al.id),
            sanitize_csv_cell(al.created_at.strftime("%Y-%m-%d %H:%M:%S") if al.created_at else ""),
            sanitize_csv_cell(al.rule_code),
            sanitize_csv_cell(al.title),
            sanitize_csv_cell(al.severity),
            sanitize_csv_cell(al.status),
            sanitize_csv_cell(al.event_id),
            sanitize_csv_cell(al.resolved_at.strftime("%Y-%m-%d %H:%M:%S") if al.resolved_at else "Unresolved"),
            sanitize_csv_cell(al.resolver.username if al.resolver else "N/A"),
            sanitize_csv_cell(al.description),
        ]
        writer.writerow(row)

    return output.getvalue()
