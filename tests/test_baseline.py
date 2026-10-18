"""Starter smoke tests only: students must build a broader suite."""
from ztlab.data_loader import DEFAULT_DATA_DIR, read_json, validate_data

def test_dataset_files_are_readable():
    results = validate_data(DEFAULT_DATA_DIR)
    assert results["json"] >= 10
    assert results["csv"] >= 3

def test_users_have_ids():
    users = read_json(DEFAULT_DATA_DIR / "identity" / "users.json")["users"]
    assert len(users) >= 30
    assert all("id" in user for user in users)
