import csv

from ztlab.csv_validation import (
    CSV_REQUIRED_FIELDS,
    validate_csv_data,
)


def create_test_data(tmp_path, error=None):
    folder = tmp_path / "events"
    folder.mkdir(parents=True, exist_ok=True)

    for filename, fields in CSV_REQUIRED_FIELDS.items():
        headers = list(fields)

        if error == "missing_column" and filename == "azure_activity.csv":
            headers.remove("source_ip")

        row = {field: "sample" for field in headers}
        row["event_id"] = "evt-001"
        row["timestamp"] = "2026-10-14T12:00:00Z"

        if error == "invalid_timestamp" and filename == "entra_signins.csv":
            row["timestamp"] = "invalid-date"

        if error == "missing_value" and filename == "network_flows.csv":
            row["source_ip"] = ""

        rows = [row]

        if error == "duplicate" and filename == "azure_activity.csv":
            rows.append(dict(row))

        with (folder / filename).open("w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)


def test_original_csv_data():
    results = validate_csv_data()
    assert all(not result["issues"] for result in results.values())


def test_independent_clean_data(tmp_path):
    create_test_data(tmp_path)
    results = validate_csv_data(tmp_path)
    assert all(not result["issues"] for result in results.values())


def test_duplicate_event_id(tmp_path):
    create_test_data(tmp_path, "duplicate")
    results = validate_csv_data(tmp_path)
    issues = results["azure_activity.csv"]["issues"]
    assert any(i["error"] == "duplicate_event_id" for i in issues)


def test_invalid_timestamp(tmp_path):
    create_test_data(tmp_path, "invalid_timestamp")
    results = validate_csv_data(tmp_path)
    issues = results["entra_signins.csv"]["issues"]
    assert any(i["error"] == "invalid_timestamp" for i in issues)


def test_missing_column_and_value(tmp_path):
    create_test_data(tmp_path, "missing_column")
    results = validate_csv_data(tmp_path)
    assert any(
        i["error"] == "missing_column"
        for i in results["azure_activity.csv"]["issues"]
    )

    create_test_data_again = tmp_path / "second"
    create_test_data(create_test_data_again, "missing_value")
    results = validate_csv_data(create_test_data_again)
    assert any(
        i["error"] == "missing_value"
        for i in results["network_flows.csv"]["issues"]
    )
