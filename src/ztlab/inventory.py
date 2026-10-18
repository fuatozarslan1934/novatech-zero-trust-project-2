"""Build a basic inventory of NovaTech cloud identities and resources."""

from pathlib import Path

from .data_loader import DEFAULT_DATA_DIR, read_json


def build_inventory(data_dir: Path = DEFAULT_DATA_DIR) -> dict:
    data_dir = Path(data_dir)

    users = read_json(data_dir / "identity" / "users.json")["users"]
    groups = read_json(data_dir / "identity" / "groups.json")["groups"]
    memberships = read_json(
        data_dir / "identity" / "group_memberships.json"
    )["memberships"]

    workloads = read_json(
        data_dir / "identity" / "workload_identities.json"
    )

    subscriptions = read_json(
        data_dir / "azure" / "subscriptions.json"
    )["subscriptions"]

    resources = read_json(
        data_dir / "azure" / "resources.json"
    )["resources"]

    assignments = read_json(
        data_dir / "azure" / "rbac_assignments.json"
    )["assignments"]

    policies = read_json(
        data_dir / "identity" / "conditional_access_policies.json"
    )["policies"]

    return {
        "users": len(users),
        "enabled_users": sum(
            user.get("enabled") is True for user in users
        ),
        "groups": len(groups),
        "group_memberships": len(memberships),
        "service_principals": len(workloads["service_principals"]),
        "managed_identities": len(workloads["managed_identities"]),
        "subscriptions": len(subscriptions),
        "resources": len(resources),
        "rbac_assignments": len(assignments),
        "conditional_access_policies": len(policies),
    }