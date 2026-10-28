"""Independent Phase 2 RBAC tests; no hardcoded NovaTech answers."""
import json

import pytest

from ztlab.permissions import principal_access, resource_access, _scope_includes


def _json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _fixture(tmp_path):
    _json(tmp_path / "identity/users.json", {"users": [
        {"id": "alice"}, {"id": "bob"}
    ]})
    _json(tmp_path / "identity/groups.json", {"groups": [
        {"id": "parent"}, {"id": "child"}
    ]})
    _json(tmp_path / "identity/workload_identities.json", {
        "service_principals": [{"id": "pipeline"}],
        "managed_identities": [{"id": "managed"}],
    })
    _json(tmp_path / "identity/group_memberships.json", {"memberships": [
        {"group_id": "child", "member_id": "alice", "member_type": "user"},
        {"group_id": "parent", "member_id": "child", "member_type": "group"},
    ]})
    _json(tmp_path / "azure/resources.json", {"resources": [
        {"id": "sub-a/resourceGroups/rg-one/providers/Microsoft.Compute/virtualMachines/vm1",
         "name": "vm1", "type": "vm"},
        {"id": "sub-a/resourceGroups/rg-two/providers/Microsoft.Compute/virtualMachines/vm2",
         "name": "vm2", "type": "vm"},
        {"id": "sub-a/resourceGroups/rg-two/providers/Microsoft.Storage/storageAccounts/store",
         "name": "store", "type": "storage"},
        {"id": "sub-b/resourceGroups/rg-one/providers/Microsoft.Compute/virtualMachines/vm3",
         "name": "vm3", "type": "vm"},
    ]})
    _json(tmp_path / "azure/role_capability_map.json", {"role_capabilities": {
        "Reader": ["resource.read"],
        "Contributor": ["resource.read", "resource.write"],
        "Virtual Machine Contributor": ["vm.read", "vm.write"],
    }})
    _json(tmp_path / "azure/rbac_assignments.json", {"assignments": [
        {"id": "ra-1", "principal_id": "parent", "role": "Reader",
         "scope": "sub-a", "assignment_type": "active"},
        {"id": "ra-2", "principal_id": "alice", "role": "Virtual Machine Contributor",
         "scope": "sub-a/resourceGroups/rg-one", "assignment_type": "active"},
        {"id": "ra-3", "principal_id": "bob", "role": "Contributor",
         "scope": "sub-a/resourceGroups/rg-two", "assignment_type": "active"},
        {"id": "ra-4", "principal_id": "pipeline", "role": "Reader",
         "scope": "sub-b", "assignment_type": "active"},
        {"id": "ra-5", "principal_id": "managed", "role": "Reader",
         "scope": "sub-a", "assignment_type": "eligible"},
    ]})
    return tmp_path


def test_scope_boundary():
    assert _scope_includes("sub-a/resourceGroups/rg", "sub-a/resourceGroups/rg/providers/X/Y")
    assert not _scope_includes("sub-a/resourceGroups/rg", "sub-a/resourceGroups/rg-two/providers/X/Y")
    assert not _scope_includes("sub-a", "sub-ab/resourceGroups/rg")


def test_nested_group_inheritance_with_evidence(tmp_path):
    base = _fixture(tmp_path)
    response = principal_access("alice", base)
    result = next(item for item in response["resources"] if item["resource_name"] == "vm2")
    assert "resource.read" in result["capabilities"]
    assert any(
        grant["membership_chain"] == ["alice", "child", "parent"]
        and grant["assignment_id"] == "ra-1"
        for grant in result["grant_evidence"]
    )


def test_direct_scope_does_not_leak(tmp_path):
    base = _fixture(tmp_path)
    response = principal_access("alice", base)
    vm1 = next(item for item in response["resources"] if item["resource_name"] == "vm1")
    vm2 = next(item for item in response["resources"] if item["resource_name"] == "vm2")
    assert "vm.write" in vm1["capabilities"]
    assert "vm.write" not in vm2["capabilities"]
    assert all(item["resource_name"] != "vm3" for item in response["resources"])


def test_resource_type_capability_filter(tmp_path):
    base = _fixture(tmp_path)
    result = principal_access("alice", base)
    storage = next(item for item in result["resources"] if item["resource_name"] == "store")
    assert "vm.write" not in storage["capabilities"]
    assert "resource.read" in storage["capabilities"]


def test_inactive_assignment_not_effective(tmp_path):
    base = _fixture(tmp_path)
    assert principal_access("managed", base)["resource_count"] == 0


def test_service_principal(tmp_path):
    base = _fixture(tmp_path)
    assert [r["resource_name"] for r in principal_access("pipeline", base)["resources"]] == ["vm3"]


def test_resource_query_and_unknowns(tmp_path):
    base = _fixture(tmp_path)
    result = resource_access("vm2", base)
    assert {p["principal_id"] for p in result["principals"]} == {"alice", "bob", "child", "parent"}
    with pytest.raises(ValueError, match="Unknown principal"):
        principal_access("missing", base)
    with pytest.raises(ValueError, match="Unknown resource"):
        resource_access("missing", base)


def test_nested_group_cycle_is_safe(tmp_path):
    base = _fixture(tmp_path)
    path = base / "identity/group_memberships.json"
    data = json.loads(path.read_text())
    data["memberships"].append({
        "group_id": "child", "member_id": "parent", "member_type": "group",
    })
    _json(path, data)
    result = principal_access("alice", base)
    assert any(r["resource_name"] == "vm1" for r in result["resources"])
    assert len(result["resources"]) == 3
