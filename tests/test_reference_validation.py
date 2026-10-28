from ztlab.reference_validation import validate_access_references


def test_existing_access_references():
    results = validate_access_references()

    assert results["invalid_rbac_principals"] == []
    assert results["invalid_pim_principals"] == []
    assert results["invalid_credential_principals"] == []


def test_invalid_access_references(monkeypatch):
    fake_data = {
        "users.json": {
            "users": [{"id": "u-001"}]
        },
        "groups.json": {
            "groups": [{"id": "g-001"}]
        },
        "workload_identities.json": {
            "service_principals": [{"id": "sp-001"}],
            "managed_identities": [{"id": "mi-001"}],
        },
        "rbac_assignments.json": {
            "assignments": [
                {"principal_id": "u-001"},
                {"principal_id": "u-999"},
            ]
        },
        "pim_assignments.json": {
            "pim_assignments": [
                {"principal_id": "u-888"}
            ]
        },
        "workload_credentials.json": {
            "credentials": [
                {"principal_id": "sp-999"}
            ]
        },
    }

    def fake_read_json(path):
        return fake_data[path.name]

    monkeypatch.setattr(
        "ztlab.reference_validation.read_json",
        fake_read_json,
    )

    results = validate_access_references()

    assert results["invalid_rbac_principals"] == ["u-999"]
    assert results["invalid_pim_principals"] == ["u-888"]
    assert results["invalid_credential_principals"] == ["sp-999"]
    