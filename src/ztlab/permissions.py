"""Offline, evidence-traceable Azure RBAC effective permissions (training model).

Only ACTIVE RBAC assignments are evaluated. This is not an Azure authorization
engine; PIM, denies, conditions, management-plane differences, and Conditional
Access are outside Phase 2. Capabilities come only from the supplied project
role_capability_map.json, not from Microsoft production role definitions.
"""

from collections import defaultdict
from pathlib import Path

from .data_loader import DEFAULT_DATA_DIR, read_json


RESOURCE_CAPABILITY_TYPES = {
    "vm.": {"vm"},
    "network.": {"nsg", "vnet"},
    "storage.blob.": {"storage"},
    "keyvault.secret.": {"key_vault"},
    "sql.": {"sql_server"},
}

MODEL_NOTE = (
    "Simplified role capability map; active RBAC assignments only. "
    "Does not evaluate PIM, deny assignments, assignment conditions, "
    "Conditional Access, or network reachability."
)


def _load(data_dir):
    base = Path(data_dir)
    identity = read_json(base / "identity/workload_identities.json")
    users = read_json(base / "identity/users.json")["users"]
    groups = read_json(base / "identity/groups.json")["groups"]
    return {
        "users": users,
        "groups": groups,
        "service_principals": identity["service_principals"],
        "managed_identities": identity["managed_identities"],
        "memberships": read_json(base / "identity/group_memberships.json")["memberships"],
        "assignments": read_json(base / "azure/rbac_assignments.json")["assignments"],
        "resources": read_json(base / "azure/resources.json")["resources"],
        "role_capabilities": read_json(base / "azure/role_capability_map.json")["role_capabilities"],
    }


def _principal_ids(data):
    return {
        item["id"]
        for collection in ("users", "groups", "service_principals", "managed_identities")
        for item in data[collection]
    }


def _membership_paths(principal_id, memberships):
    """Each path goes from a principal through containing (possibly nested) groups.

    Track visited IDs per path so malformed cycles cannot loop forever.
    Multiple distinct paths to the same group are retained for provenance.
    """
    parent_groups = defaultdict(set)
    for member in memberships:
        if member.get("member_type") in {"user", "group", "service_principal"}:
            parent_groups[member["member_id"]].add(member["group_id"])

    paths = [[principal_id]]
    frontier = [[principal_id]]
    while frontier:
        chain = frontier.pop()
        for parent in sorted(parent_groups.get(chain[-1], ())):
            if parent in chain:
                continue
            next_chain = chain + [parent]
            paths.append(next_chain)
            frontier.append(next_chain)
    return sorted(paths, key=lambda p: (len(p), p))


def _scope_includes(scope, resource_id):
    """Azure-style hierarchy with a path segment boundary (not string prefix)."""
    scope = scope.rstrip("/").casefold()
    resource_id = resource_id.rstrip("/").casefold()
    return resource_id == scope or resource_id.startswith(scope + "/")


def _applicable_capabilities(capabilities, resource_type):
    allowed = []
    for capability in capabilities:
        matching_prefixes = [
            prefix for prefix in RESOURCE_CAPABILITY_TYPES
            if capability.startswith(prefix)
        ]
        if not matching_prefixes or any(
            resource_type in RESOURCE_CAPABILITY_TYPES[prefix]
            for prefix in matching_prefixes
        ):
            allowed.append(capability)
    return sorted(set(allowed))


def _resource_grants(data, principal_id, resource):
    chains = _membership_paths(principal_id, data["memberships"])
    chains_by_holder = defaultdict(list)
    for chain in chains:
        chains_by_holder[chain[-1]].append(chain)

    grants = []
    for assignment in data["assignments"]:
        if assignment.get("assignment_type") != "active":
            continue
        holder = assignment["principal_id"]
        if holder not in chains_by_holder:
            continue
        if not _scope_includes(assignment["scope"], resource["id"]):
            continue
        capabilities = _applicable_capabilities(
            data["role_capabilities"].get(assignment["role"], []),
            resource["type"],
        )
        if not capabilities:
            continue
        for chain in chains_by_holder[holder]:
            grants.append({
                "assignment_id": assignment["id"],
                "granted_via": holder,
                "membership_chain": chain,
                "role": assignment["role"],
                "scope": assignment["scope"],
                "capabilities": capabilities,
            })
    grants.sort(key=lambda grant: (grant["assignment_id"], grant["membership_chain"]))
    return grants


def _resource_result(resource, grants):
    return {
        "resource_id": resource["id"],
        "resource_name": resource["name"],
        "resource_type": resource["type"],
        "roles": sorted({grant["role"] for grant in grants}),
        "capabilities": sorted({
            cap for grant in grants for cap in grant["capabilities"]
        }),
        "grant_evidence": grants,
    }


def principal_access(principal_id: str, data_dir=DEFAULT_DATA_DIR) -> dict:
    """Report effective permissions of a principal on each matching resource."""
    data = _load(data_dir)
    if principal_id not in _principal_ids(data):
        raise ValueError(f"Unknown principal: {principal_id}")
    matched = []
    for resource in data["resources"]:
        grants = _resource_grants(data, principal_id, resource)
        if grants:
            matched.append(_resource_result(resource, grants))
    matched.sort(key=lambda item: item["resource_id"])
    return {
        "principal_id": principal_id,
        "resource_count": len(matched),
        "resources": matched,
        "model_limitations": MODEL_NOTE,
    }


def resource_access(resource_name_or_id: str, data_dir=DEFAULT_DATA_DIR) -> dict:
    """Report all principals with project-modeled access to one resource."""
    data = _load(data_dir)
    resources = [
        resource for resource in data["resources"]
        if resource["id"] == resource_name_or_id
        or resource["name"] == resource_name_or_id
    ]
    if not resources:
        raise ValueError(f"Unknown resource: {resource_name_or_id}")
    if len(resources) > 1:
        raise ValueError("Ambiguous resource name; use the full resource ID")

    resource = resources[0]
    principals = []
    for principal_id in sorted(_principal_ids(data)):
        grants = _resource_grants(data, principal_id, resource)
        if grants:
            entry = _resource_result(resource, grants)
            principals.append({
                "principal_id": principal_id,
                "roles": entry["roles"],
                "capabilities": entry["capabilities"],
                "grant_evidence": grants,
            })
    return {
        "resource_id": resource["id"],
        "resource_name": resource["name"],
        "principal_count": len(principals),
        "principals": principals,
        "model_limitations": MODEL_NOTE,
    }
