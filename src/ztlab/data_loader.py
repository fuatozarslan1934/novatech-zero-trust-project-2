"""Small working example for dataset reading. Extend with validation."""
from pathlib import Path
import csv
import json

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