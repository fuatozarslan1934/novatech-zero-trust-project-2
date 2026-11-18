from ztlab.access_review import review_write_access


def test_direct_users():
    result = review_write_access("vm-portal-edge-01", "data")

    assert result["direct_users"] == ["u-003", "u-039"]


def test_group_users():
    result = review_write_access("vm-portal-edge-01", "data")

    assert result["group_users"] == [
        "u-001",
        "u-005",
        "u-008",
        "u-009",
        "u-017",
        "u-031",
    ]