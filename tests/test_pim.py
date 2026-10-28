"""Phase 3 independent tests with synthetic data, not NovaTech hardcoded IDs."""
import json
from datetime import datetime, timezone

import pytest

from ztlab.pim import analyze_privileges, pim_status


SNAP = "2026-01-20T12:00:00Z"


def _save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _base(tmp_path):
    _save(tmp_path / "identity/pim_assignments.json", {
        "snapshot_time_utc": SNAP,
        "pim_assignments": [
            {"id": "p-1", "principal_id": "alice", "role": "Owner", "scope": "sub-a",
             "state": "eligible", "activation_start": None, "activation_end": None,
             "requires_mfa": True, "requires_justification": True},
            {"id": "p-2", "principal_id": "bob", "role": "Contributor", "scope": "sub-a",
             "state": "active", "activation_start": "2026-01-20T10:00:00Z",
             "activation_end": "2026-01-20T14:00:00Z",
             "requires_mfa": True, "requires_justification": True},
            {"id": "p-3", "principal_id": "alice", "role": "Owner", "scope": "sub-a",
             "state": "active", "activation_start": "2026-01-18T10:00:00Z",
             "activation_end": "2026-01-18T14:00:00Z",
             "requires_mfa": True, "requires_justification": True},
        ],
    })
    _save(tmp_path / "identity/users.json", {"users": [
        {"id": "alice", "enabled": True, "last_signin_at": "2025-11-01T12:00:00Z"},
        {"id": "bob", "enabled": True, "last_signin_at": "2026-01-19T12:00:00Z"},
        {"id": "disabled", "enabled": False, "last_signin_at": "2025-01-01T12:00:00Z"},
    ]})
    _save(tmp_path / "identity/group_memberships.json", {"memberships": [
        {"member_id": "alice", "member_type": "user", "group_id": "child"},
        {"member_id": "child", "member_type": "group", "group_id": "parent"},
    ]})
    _save(tmp_path / "azure/rbac_assignments.json", {"assignments": [
        {"id": "ra-standing-1", "principal_id": "parent", "role": "Owner",
         "scope": "sub-a", "assignment_type": "active"},
        {"id": "ra-standing-2", "principal_id": "pipeline", "role": "Contributor",
         "scope": "sub-a", "assignment_type": "active"},
        {"id": "ra-eligible", "principal_id": "disabled", "role": "Owner",
         "scope": "sub-a", "assignment_type": "eligible"},
    ]})
    _save(tmp_path / "identity/workload_identities.json", {
        "service_principals": [{"id": "pipeline", "name": "pipeline"}],
        "managed_identities": [],
    })
    _save(tmp_path / "identity/workload_credentials.json", {"credentials": [
        {"principal_id": "pipeline", "credential_id": "c-1", "credential_type": "client_secret",
         "expires_at": "2026-01-01T12:00:00Z"},
        {"principal_id": "pipeline", "credential_id": "c-2", "credential_type": "client_secret",
         "expires_at": "2026-02-01T12:00:00Z"},
        {"principal_id": "pipeline", "credential_id": "c-3", "credential_type": "federated",
         "expires_at": None},
        {"principal_id": "pipeline", "credential_id": "c-4", "credential_type": "certificate",
         "expires_at": "2027-01-01T12:00:00Z"},
    ]})
    return tmp_path


def test_pim_snapshot_states_and_non_effective_eligibility(tmp_path):
    result = analyze_privileges(_base(tmp_path))
    assert result["pim_status_counts"] == {
        "active": 1, "eligible": 1, "expired": 1, "scheduled": 0, "invalid": 0,
    }
    assert [r["assignment_id"] for r in result["pim_assignments"] if r["effective_at_snapshot"]] == ["p-2"]


def test_expiry_boundary_and_activation_start_inclusive():
    record = {"state": "active", "activation_start": "2026-01-20T10:00:00Z",
              "activation_end": "2026-01-20T14:00:00Z"}
    assert pim_status(record, "2026-01-20T10:00:00Z") == "active"
    assert pim_status(record, "2026-01-20T14:00:00Z") == "expired"
    assert pim_status(record, "2026-01-20T09:59:59Z") == "scheduled"


def test_declared_expired_cannot_become_active():
    record = {"state": "expired", "activation_start": "2026-01-19T10:00:00Z",
              "activation_end": "2026-01-19T14:00:00Z"}
    assert pim_status(record, SNAP) == "expired"
    record["activation_end"] = "2026-01-21T14:00:00Z"
    assert pim_status(record, SNAP) == "invalid"


def test_broken_and_naive_dates_never_grant():
    record = {"state": "active", "activation_start": "2026-01-20T10:00:00",
              "activation_end": "2026-01-20T14:00:00Z"}
    assert pim_status(record, SNAP) == "invalid"
    record["activation_start"] = "2026-01-20T15:00:00Z"
    assert pim_status(record, SNAP) == "invalid"
    record["activation_start"] = "garbage"
    assert pim_status(record, SNAP) == "invalid"
    with pytest.raises(ValueError, match="Timezone required"):
        pim_status(record, datetime(2026, 1, 20))


def test_eligible_with_activation_window_is_inconsistent():
    assert pim_status({"state": "eligible", "activation_start": "2026-01-20T10:00:00Z",
                       "activation_end": "2026-01-20T14:00:00Z"}, SNAP) == "invalid"


def test_stale_user_nested_group_evidence(tmp_path):
    result = analyze_privileges(_base(tmp_path))
    stale = [f for f in result["findings"] if f["type"] == "stale_user_powerful_standing_role"]
    assert len(stale) == 1
    assert stale[0]["principal_id"] == "alice"
    assert stale[0]["assignment_ids"] == ["ra-standing-1"]
    assert stale[0]["evidence"]["membership_chain"] == ["alice", "child", "parent"]


def test_broad_service_principal_and_evidence(tmp_path):
    result = analyze_privileges(_base(tmp_path))
    broad = [f for f in result["findings"] if f["type"] == "broad_service_principal_access"]
    assert len(broad) == 1
    assert broad[0]["principal_id"] == "pipeline"
    assert broad[0]["assignment_ids"] == ["ra-standing-2"]


def test_expiring_and_expired_credentials_but_not_federated(tmp_path):
    result = analyze_privileges(_base(tmp_path))
    alerts = [f for f in result["findings"] if f["type"].startswith("credential_")]
    assert {(a["type"], a["evidence"]["credential_id"]) for a in alerts} == {
        ("credential_expired", "c-1"), ("credential_expiring", "c-2"),
    }


def test_as_of_override_changes_pim(tmp_path):
    result = analyze_privileges(_base(tmp_path), as_of="2026-01-21T12:00:00+00:00")
    assert result["snapshot_time_utc"] == "2026-01-21T12:00:00Z"
    assert result["pim_status_counts"]["active"] == 0
    assert result["pim_status_counts"]["expired"] == 2


def test_future_activity_not_stale_and_disabled_skipped(tmp_path):
    base = _base(tmp_path)
    path = base / "identity/users.json"
    data = json.loads(path.read_text())
    data["users"][0]["last_signin_at"] = "2026-02-20T12:00:00Z"
    _save(path, data)
    result = analyze_privileges(base)
    assert not [f for f in result["findings"] if f["type"] == "stale_user_powerful_standing_role"]


def test_standing_rbac_eligible_is_not_standing_access(tmp_path):
    result = analyze_privileges(_base(tmp_path))
    assert result["standing_rbac_assignments_reviewed"] == 2
    assert all("ra-eligible" not in f["assignment_ids"] for f in result["findings"])


def test_active_pim_missing_control_detected(tmp_path):
    base = _base(tmp_path)
    path = base / "identity/pim_assignments.json"
    data = json.loads(path.read_text())
    data["pim_assignments"][1]["requires_mfa"] = False
    _save(path, data)
    result = analyze_privileges(base)
    alerts = [f for f in result["findings"] if f["type"] == "active_pim_control_review"]
    assert len(alerts) == 1 and alerts[0]["assignment_ids"] == ["p-2"]


def test_invalid_pim_window_is_flagged(tmp_path):
    base = _base(tmp_path)
    path = base / "identity/pim_assignments.json"
    data = json.loads(path.read_text())
    data["pim_assignments"][1]["activation_end"] = "2026-01-20T09:00:00Z"
    _save(path, data)
    result = analyze_privileges(base)
    assert result["pim_status_counts"]["invalid"] == 1
    assert any(f["type"] == "pim_record_inconsistent" for f in result["findings"])


def test_timezone_offsets_and_valid_thresholds(tmp_path):
    base = _base(tmp_path)
    report = analyze_privileges(base, as_of="2026-01-20T07:00:00-05:00", expiring_days=5)
    assert report["snapshot_time_utc"] == SNAP
    assert not any(f["type"] == "credential_expiring" for f in report["findings"])
    with pytest.raises(ValueError, match="non-negative"):
        analyze_privileges(base, stale_days=-1)
