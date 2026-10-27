"""Small working example for dataset reading. Extend with validation."""
from pathlib import Path
import csv
import json
from datetime import datetime

DEFAULT_DATA_DIR = Path(__file__).resolve().parents[2] / "data"

def read_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def read_csv(path: Path):
    with Path(path).open(encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))

def discover_files(data_dir: Path = DEFAULT_DATA_DIR):
    root = Path(data_dir)
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in {".json", ".csv", ".log"})

def validate_data(data_dir: Path = DEFAULT_DATA_DIR):
    files = discover_files(data_dir)
    if not files:
        raise ValueError(f"No dataset files under {data_dir}")
    counts = {"json":0,"csv":0,"log":0}
    for path in files:
        fmt = path.suffix.lower()[1:]
        if fmt == "json":
            read_json(path)
        elif fmt == "csv":
            read_csv(path)
        counts[fmt] += 1
    return counts
def find_duplicate_ids(records: list[dict]) -> list[str]:
    seen = set()
    duplicates = set()

    for record in records:
        record_id = record.get("id")

        if record_id is None:
            continue

        if record_id in seen:
            duplicates.add(record_id)
        else:
            seen.add(record_id)

    return sorted(duplicates)

def find_missing_ids(records: list[dict]) -> list[int]:
    missing = []

    for index, record in enumerate(records):
        if not record.get("id"):
            missing.append(index)

    return missing
def find_invalid_references(
    records: list[dict],
    reference_field: str,
    valid_ids: set,
) -> list[str]:
    invalid = []

    for record in records:
        reference_id = record.get(reference_field)

        if reference_id is not None and reference_id not in valid_ids:
            invalid.append(reference_id)

    return sorted(set(invalid))
def is_valid_timestamp(value: str) -> bool:
    if not isinstance(value, str):
        return False

    try:
        timestamp = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
        return timestamp.tzinfo is not None

    except ValueError:
        return False

def validate_identity_data(data_dir: Path = DEFAULT_DATA_DIR) -> dict:
    base = Path(data_dir) / "identity"

    users = read_json(base / "users.json")["users"]
    groups = read_json(base / "groups.json")["groups"]
    memberships = read_json(
        base / "group_memberships.json"
    )["memberships"]

    user_ids = {user["id"] for user in users if user.get("id")}
    group_ids = {group["id"] for group in groups if group.get("id")}

    user_memberships = [
        m for m in memberships if m.get("member_type") == "user"
    ]

    nested_memberships = [
        m for m in memberships if m.get("member_type") == "group"
    ]

    return {
        "duplicate_users": find_duplicate_ids(users),
        "missing_user_ids": find_missing_ids(users),
        "invalid_user_references": find_invalid_references(
            user_memberships, "member_id", user_ids
        ),
        "invalid_group_references": find_invalid_references(
            memberships, "group_id", group_ids
        ),
        "invalid_nested_group_references": find_invalid_references(
            nested_memberships, "member_id", group_ids
        ),
        "invalid_user_timestamps": [
            user.get("id", f"index-{index}")
            for index, user in enumerate(users)
            if user.get("last_signin_at") is not None
            and not is_valid_timestamp(user["last_signin_at"])
        ],
    }
