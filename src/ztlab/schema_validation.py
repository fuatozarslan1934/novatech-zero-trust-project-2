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


EXTENDED_SCHEMAS = {
    "azure/resources.json": {
        "resources": ["id", "name", "type", "subscription_id", "resource_group"],
    },
    "azure/secret_metadata.json": {
        "secrets": ["vault_name", "secret_name", "value_included"],
    },
    "azure/subscriptions.json": {
        "subscriptions": ["id", "name", "environment"],
        "resource_groups": ["id", "name", "subscription_id"],
    },
    "identity/conditional_access_policies.json": {
        "policies": ["id", "name", "state", "apps", "conditions", "controls"],
    },
    "identity/group_memberships.json": {
        "memberships": ["group_id", "member_id", "member_type"],
    },
    "identity/named_locations.json": {
        "named_locations": ["id", "label", "cidrs"],
    },
    "identity/pim_assignments.json": {
        "pim_assignments": ["id", "principal_id", "role", "scope", "state"],
    },
    "identity/workload_credentials.json": {
        "credentials": ["principal_id", "credential_type"],
    },
    "identity/workload_identities.json": {
        "service_principals": ["id", "name", "kind", "owner"],
        "managed_identities": ["id", "name", "kind", "resource_name"],
    },
    "network/cisco_acl_exports.json": {
        "acls": ["device", "acl", "seq", "action", "protocol", "src", "dst", "dst_port"],
    },
    "network/network_controls.json": {
        "zones": ["name", "cidr"],
        "nsg_rules": ["nsg", "priority", "action", "protocol", "source", "port"],
    },
}


def validate_all_schemas(data_dir=DEFAULT_DATA_DIR):
    results = validate_schemas(data_dir)

    for filename, collections in EXTENDED_SCHEMAS.items():
        data = read_json(Path(data_dir) / filename)
        issues = []

        for collection, required_fields in collections.items():
            records = data.get(collection)

            if not isinstance(records, list):
                issues.append({
                    "collection": collection,
                    "error": "missing_or_invalid_list",
                })
                continue

            for index, record in enumerate(records):
                if not isinstance(record, dict):
                    issues.append({
                        "collection": collection,
                        "row": index,
                        "error": "invalid_record_type",
                    })
                    continue

                missing = find_missing_required_fields(
                    [record], required_fields
                )

                if missing:
                    issues.append({
                        "collection": collection,
                        "row": index,
                        "missing_fields": missing[0]["missing_fields"],
                    })

        results[filename] = issues

    object_schemas = {
        "azure/role_capability_map.json": ("role_capabilities", list),
        "schema/data_dictionary.json": ("formats", str),
    }

    for filename, (field, value_type) in object_schemas.items():
        data = read_json(Path(data_dir) / filename)
        value = data.get(field)

        if (
            not isinstance(value, dict)
            or not value
            or not all(
                isinstance(k, str) and isinstance(v, value_type)
                for k, v in value.items()
            )
        ):
            results[filename] = [{"error": "invalid_mapping", "field": field}]
        else:
            results[filename] = []

    return results
