"""Validate event CSV files without modifying source data."""

import csv
from pathlib import Path

from .data_loader import DEFAULT_DATA_DIR, is_valid_timestamp


CSV_REQUIRED_FIELDS = {
    "azure_activity.csv": [
        "event_id", "timestamp", "principal_id",
        "operation", "resource_id", "source_ip",
        "status", "correlation_id",
    ],
    "entra_signins.csv": [
        "event_id", "timestamp", "user_id",
        "user_principal_name", "app", "source_ip",
        "result", "mfa_satisfied", "device_compliant",
        "client_app",
    ],
    "network_flows.csv": [
        "event_id", "timestamp", "source_ip",
        "destination_ip", "destination_port",
        "protocol", "action", "bytes_out",
        "bytes_in", "zone",
    ],
}


def validate_csv_data(data_dir=DEFAULT_DATA_DIR):
    results = {}

    for filename, required_fields in CSV_REQUIRED_FIELDS.items():
        path = Path(data_dir) / "events" / filename

        with path.open(encoding="utf-8", newline="") as file:
            reader = csv.DictReader(file)
            headers = reader.fieldnames or []
            records = list(reader)

        issues = []
        seen_ids = set()

        for field in required_fields:
            if field not in headers:
                issues.append({
                    "error": "missing_column",
                    "field": field,
                })

        for row_number, record in enumerate(records, start=2):
            for field in required_fields:
                if field in headers and not str(
                    record.get(field) or ""
                ).strip():
                    issues.append({
                        "error": "missing_value",
                        "row": row_number,
                        "field": field,
                    })

            event_id = record.get("event_id")

            if event_id:
                if event_id in seen_ids:
                    issues.append({
                        "error": "duplicate_event_id",
                        "row": row_number,
                        "id": event_id,
                    })
                seen_ids.add(event_id)

            timestamp = record.get("timestamp")

            if timestamp and not is_valid_timestamp(timestamp):
                issues.append({
                    "error": "invalid_timestamp",
                    "row": row_number,
                })

        results[filename] = {
            "records": len(records),
            "issues": issues,
        }

    return results
