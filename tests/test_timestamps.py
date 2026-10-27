from ztlab.data_loader import is_valid_timestamp


def test_valid_timestamp():
    assert is_valid_timestamp("2026-10-14T12:00:00Z") is True


def test_invalid_timestamp():
    assert is_valid_timestamp("2026-15-45T12:00:00Z") is False


def test_timestamp_without_timezone():
    assert is_valid_timestamp("2026-10-14T12:00:00") is False
    