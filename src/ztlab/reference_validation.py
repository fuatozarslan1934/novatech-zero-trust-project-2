"""Validate RBAC, PIM, and workload identity references."""

from pathlib import Path

from .data_loader import (
    DEFAULT_DATA_DIR,
    read_json,
    find_invalid_references,
)


def validate_access_references(data_dir=DEFAULT_DATA_DIR):
    base = Path(data_dir)

    users = read_json(base / "identity/users.json")["users"]
    groups = read_json(base / "identity/groups.json")["groups"]
    workloads = read_json(
        base / "identity/workload_identities.json"
    )

    rbac = read_json(
        base / "azure/rbac_assignments.json"
    )["assignments"]

    pim = read_json(
        base / "identity/pim_assignments.json"
    )["pim_assignments"]

    credentials = read_json(
        base / "identity/workload_credentials.json"
    )["credentials"]

    user_ids = {u["id"] for u in users}
    group_ids = {g["id"] for g in groups}

    service_ids = {
        s["id"] for s in workloads["service_principals"]
    }

    managed_ids = {
        m["id"] for m in workloads["managed_identities"]
    }

    all_principals = (
        user_ids | group_ids | service_ids | managed_ids
    )

    return {
        "invalid_rbac_principals": find_invalid_references(
            rbac, "principal_id", all_principals
        ),
        "invalid_pim_principals": find_invalid_references(
            pim, "principal_id", user_ids
        ),
        "invalid_credential_principals": find_invalid_references(
            credentials, "principal_id", service_ids
        ),
    }
    