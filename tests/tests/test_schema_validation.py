from ztlab.schema_validation import validate_schemas
from ztlab.data_loader import find_missing_required_fields


def test_missing_required_fields():
    records = [
        {"id": "u-001", "upn": "user1@example.com"},
        {"upn": "user2@example.com"},
        {"id": "u-003", "upn": ""},
    ]

    result = find_missing_required_fields(
        records, ["id", "upn"]
    )

    assert result == [
        {"row": 1, "missing_fields": ["id"]},
        {"row": 2, "missing_fields": ["upn"]},
    ]


def test_valid_required_fields():
    records = [
        {"id": "u-001", "enabled": False},
        {"id": "u-002", "enabled": True},
    ]

    result = find_missing_required_fields(
        records, ["id", "enabled"]
    )

    assert result == []
    from ztlab.schema_validation import validate_schemas


def test_schema_validation_clean_data():
    results = validate_schemas()

    assert all(issues == [] for issues in results.values())


def test_schema_validation_detects_missing_field(monkeypatch):
    fake_data = {
        "users.json": {
            "users": [
                {
                    "id": "u-001",
                    "enabled": True,
                    "account_type": "member",
                }
            ]
        },
        "groups.json": {
            "groups": [
                {"id": "g-001", "name": "Admins"}
            ]
        },
        "rbac_assignments.json": {
            "assignments": [
                {
                    "id": "ra-001",
                    "principal_id": "u-001",
                    "role": "Reader",
                    "scope": "sub-001",
                    "assignment_type": "active",
                }
            ]
        },
    }

    def fake_read_json(path):
        return fake_data[path.name]

    monkeypatch.setattr(
        "ztlab.schema_validation.read_json",
        fake_read_json,
    )

    results = validate_schemas()

    assert results["identity/users.json"] == [
        {"row": 0, "missing_fields": ["upn"]}
    ]