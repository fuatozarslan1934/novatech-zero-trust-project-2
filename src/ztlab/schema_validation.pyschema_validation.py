"""Validate required fields in NovaTech datasets."""

from pathlib import Path

from .data_loader import (
    DEFAULT_DATA_DIR,
    read_json,
    find_missing_required_fields,
)


SCHEMAS = {
    "identity/users.json": (
        "users",
        ["id", "upn", "enabled", "account_type"],
    ),
    "identity/groups.json": (
        "groups",
        ["id", "name"],
    ),
    "azure/rbac_assignments.json": (
        "assignments",
        ["id", "principal_id", "role", "scope", "assignment_type"],
    ),
}


def validate_schemas(data_dir: Path = DEFAULT_DATA_DIR) -> dict:
    results = {}

    for filename, (key, required) in SCHEMAS.items():
        path = Path(data_dir) / filename
        records = read_json(path)[key]

        results[filename] = find_missing_required_fields(
            records, required
        )

    return results