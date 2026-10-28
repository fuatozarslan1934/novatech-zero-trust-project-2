"""Offline PIM lifecycle and least-privilege review for synthetic NovaTech data.

The snapshot is from identity/pim_assignments.json, NOT the machine clock.
An eligible PIM entry never creates active access by itself. The training RBAC
`access` command remains a separate standing-RBAC view in this project.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from .data_loader import DEFAULT_DATA_DIR, read_json
from .permissions import _membership_paths


HIGH_PRIVILEGE_ROLES = frozenset({"Owner", "Contributor", "User Access Administrator"})
MODEL_LIMITATIONS = (
    "Offline snapshot-based PIM/RBAC review. PIM activations are reported separately "
    "and not merged into the Phase 2 'access' command; real Entra PIM approvals, "
    "RBAC deny assignments/conditions, Conditional Access, and network reachability "
    "are not evaluated. Findings require business-context review, not proof of misuse."
)


def _utc(value, label="timestamp"):
    """Parse an explicitly timezone-aware ISO-8601 timestamp into UTC."""
    if isinstance(value, datetime):
        timestamp = value
    elif isinstance(value, str):
        try:
            timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Invalid {label}: {value!r}") from exc
    else:
        raise ValueError(f"Missing or invalid {label}: {value!r}")
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError(f"Timezone required for {label}: {value!r}")
    return timestamp.astimezone(timezone.utc)


def _iso(timestamp):
    return timestamp.isoformat(timespec="seconds").replace("+00:00", "Z")


def pim_status(record, snapshot):
    """Return active, eligible, expired, scheduled, or invalid for one PIM record.

    'active' requires BOTH an active state flag and a covering time window.
    A half-open activation interval [start, end) expires at its end instant.
    """
    snapshot = _utc(snapshot, "snapshot")
    state = record.get("state")
    if state == "eligible":
        if record.get("activation_start") is not None or record.get("activation_end") is not None:
            return "invalid"
        return "eligible"
    if state not in {"active", "expired"}:
        return "invalid"
    if not record.get("activation_start") or not record.get("activation_end"):
        return "invalid"
    try:
        start = _utc(record["activation_start"], "activation_start")
        end = _utc(record["activation_end"], "activation_end")
    except ValueError:
        return "invalid"
    if end <= start:
        return "invalid"
    if state == "expired":
        return "expired" if snapshot >= end else "invalid"
    if snapshot >= end:
        return "expired"
    if snapshot < start:
        return "scheduled"
    return "active"


def _finding(kind, severity, principal_id, assignment_ids, evidence, recommendation):
    return {
        "type": kind,
        "severity": severity,
        "principal_id": principal_id,
        "assignment_ids": assignment_ids,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _is_subscription_scope(scope):
    return isinstance(scope, str) and bool(scope) and "/" not in scope.strip("/")


def analyze_privileges(data_dir=DEFAULT_DATA_DIR, as_of=None, stale_days=30, expiring_days=30):
    """Create an auditable, independent privileged-access review.

    `as_of` optionally overrides the dataset snapshot for independent fixtures.
    The caller can alter thresholds without editing any source code.
    """
    if stale_days < 0 or expiring_days < 0:
        raise ValueError("Review thresholds must be non-negative")
    root = Path(data_dir)
    pim_doc = read_json(root / "identity/pim_assignments.json")
    snapshot = _utc(
        as_of if as_of is not None else pim_doc.get("snapshot_time_utc"),
        "snapshot_time_utc",
    )
    users = read_json(root / "identity/users.json")["users"]
    memberships = read_json(root / "identity/group_memberships.json")["memberships"]
    assignments = read_json(root / "azure/rbac_assignments.json")["assignments"]
    workloads = read_json(root / "identity/workload_identities.json")
    credentials = read_json(root / "identity/workload_credentials.json")["credentials"]
    service_principals = {p["id"]: p for p in workloads["service_principals"]}

    pim_records = []
    findings = []
    for entry in pim_doc["pim_assignments"]:
        status = pim_status(entry, snapshot)
        pim_records.append({
            "assignment_id": entry["id"],
            "principal_id": entry["principal_id"],
            "role": entry["role"],
            "scope": entry["scope"],
            "declared_state": entry.get("state"),
            "evaluated_state": status,
            "effective_at_snapshot": status == "active",
            "activation_start": entry.get("activation_start"),
            "activation_end": entry.get("activation_end"),
        })
        if status == "invalid":
            findings.append(_finding(
                "pim_record_inconsistent", "medium", entry["principal_id"],
                [entry["id"]], {"declared_state": entry.get("state"),
                                "activation_start": entry.get("activation_start"),
                                "activation_end": entry.get("activation_end")},
                "Reconcile PIM status and activation timestamps before treating this as effective access.",
            ))
        if status == "active" and (
            entry.get("requires_mfa") is not True or entry.get("requires_justification") is not True
        ):
            findings.append(_finding(
                "active_pim_control_review", "medium", entry["principal_id"],
                [entry["id"]], {"requires_mfa": entry.get("requires_mfa"),
                                "requires_justification": entry.get("requires_justification")},
                "Review MFA and justification requirements for the active PIM role.",
            ))

    # Standing RBAC review (separate from the PIM activation inventory).
    active_roles = [a for a in assignments if a.get("assignment_type") == "active"]
    for assignment in active_roles:
        role = assignment.get("role")
        holder = assignment.get("principal_id")
        scope = assignment.get("scope")
        if role in HIGH_PRIVILEGE_ROLES and _is_subscription_scope(scope):
            findings.append(_finding(
                "broad_standing_role_review", "medium", holder, [assignment["id"]],
                {"role": role, "scope": scope, "source": "active_rbac"},
                "Confirm business need and consider narrower scope or eligible/time-bound access; do not revoke automatically.",
            ))
        if holder in service_principals and role in HIGH_PRIVILEGE_ROLES and _is_subscription_scope(scope):
            findings.append(_finding(
                "broad_service_principal_access", "high", holder, [assignment["id"]],
                {"role": role, "scope": scope, "source": "active_rbac"},
                "Review automation dependency and reduce the service principal's standing scope if feasible.",
            ))

    for user in users:
        if not user.get("enabled", True):
            continue
        last_signin = user.get("last_signin_at")
        if not last_signin:
            continue  # Missing activity evidence is not proof that the account is stale.
        try:
            days_since = (snapshot - _utc(last_signin, "last_signin_at")).total_seconds() / 86400
        except ValueError:
            continue  # Data-quality validation is a separate phase.
        if days_since < stale_days:
            continue
        paths = _membership_paths(user["id"], memberships)
        shortest_path_by_holder = {}
        for chain in paths:
            holder = chain[-1]
            if holder not in shortest_path_by_holder or len(chain) < len(shortest_path_by_holder[holder]):
                shortest_path_by_holder[holder] = chain
        for a in active_roles:
            if a.get("role") not in HIGH_PRIVILEGE_ROLES:
                continue
            chain = shortest_path_by_holder.get(a["principal_id"])
            if chain is None:
                continue
            findings.append(_finding(
                "stale_user_powerful_standing_role", "high", user["id"], [a["id"]],
                {"last_signin_at": last_signin, "days_since_signin": int(days_since),
                 "role": a["role"], "scope": a["scope"], "membership_chain": chain},
                "Verify account activity and business need before removing the active RBAC assignment or group membership.",
            ))

    for credential in credentials:
        end_str = credential.get("expires_at")
        if not end_str:
            continue  # Federated credentials need a different review, not an invented expiry.
        try:
            end = _utc(end_str, "expires_at")
        except ValueError:
            continue
        days_left = (end - snapshot).total_seconds() / 86400
        if days_left > expiring_days:
            continue
        expired = days_left <= 0
        findings.append(_finding(
            "credential_expired" if expired else "credential_expiring",
            "high" if expired else "medium",
            credential["principal_id"], [],
            {"credential_id": credential.get("credential_id"),
             "credential_type": credential.get("credential_type"),
             "expires_at": end_str, "days_until_expiry": round(days_left, 2)},
            "Confirm whether the credential is still needed; rotate or retire through a controlled process.",
        ))

    status_counts = {name: 0 for name in ("active", "eligible", "expired", "scheduled", "invalid")}
    for item in pim_records:
        status_counts[item["evaluated_state"]] += 1
    findings.sort(key=lambda f: (f["type"], f["principal_id"], f["assignment_ids"]))
    return {
        "snapshot_time_utc": _iso(snapshot),
        "pim_status_counts": status_counts,
        "pim_assignments": pim_records,
        "standing_rbac_assignments_reviewed": len(active_roles),
        "finding_count": len(findings),
        "findings": findings,
        "model_limitations": MODEL_LIMITATIONS,
    }
