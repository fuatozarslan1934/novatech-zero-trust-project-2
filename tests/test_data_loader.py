from ztlab.data_loader import find_duplicate_ids, find_missing_ids
from ztlab.data_loader import find_duplicate_ids


def test_duplicate_ids():
    records = [
        {"id": "u-001"},
        {"id": "u-002"},
        {"id": "u-001"},
    ]

    result = find_duplicate_ids(records)

    assert result == ["u-001"]


def test_no_duplicate_ids():
    records = [
        {"id": "u-001"},
        {"id": "u-002"},
    ]

    result = find_duplicate_ids(records)

    assert result == []

    

def test_missing_ids():
    records = [
        {"id": "u-001"},
        {"name": "Alex"},
        {"id": "u-003"},
    ]

    assert find_missing_ids(records) == [1]


def test_all_ids_present():
    records = [
        {"id": "u-001"},
        {"id": "u-002"},
    ]

    assert find_missing_ids(records) == []