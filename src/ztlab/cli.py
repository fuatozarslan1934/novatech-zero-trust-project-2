"""NovaTech Zero Trust Security Analyzer CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .data_loader import (
    validate_data,
    validate_identity_data,
    DEFAULT_DATA_DIR,
)
from .inventory import build_inventory


COMMANDS = [
    "validate-data",
    "inventory",
    "access",
    "privileged",
    "policy-check",
    "attack-paths",
    "explain-path",
    "compare-controls",
    "report",
]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NovaTech Zero Trust Security Analyzer"
    )

    parser.add_argument(
        "--data-dir",
        default=str(DEFAULT_DATA_DIR),
    )

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    for cmd in COMMANDS:
        p = sub.add_parser(cmd)

        if cmd == "access":
            p.add_argument("--principal")
            p.add_argument("--resource")

        elif cmd == "policy-check":
            p.add_argument("--user", required=True)
            p.add_argument("--app", required=True)
            p.add_argument("--source-ip", required=True)
            p.add_argument("--mfa", required=True)
            p.add_argument("--compliant", required=True)

        elif cmd == "explain-path":
            p.add_argument("--path-id", required=True)

        elif cmd == "compare-controls":
            p.add_argument("--baseline", required=True)
            p.add_argument("--proposed", required=True)

        elif cmd == "report":
            p.add_argument("--format", default="md")

    args = parser.parse_args()
    data_dir = Path(args.data_dir)

    if args.command == "validate-data":
        counts = validate_data(data_dir)
        results = validate_identity_data(data_dir)

        print("Dataset readable:", counts)
        print("Identity validation:", results)
        return 0

    if args.command == "inventory":
        results = build_inventory(data_dir)
        print(json.dumps(results, indent=2))
        return 0

    print(f"NOT IMPLEMENTED: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())