"""NovaTech Zero Trust Security Analyzer CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from .pim import analyze_privileges
from .permissions import principal_access, resource_access
from .reference_validation import validate_access_references
from .data_loader import (
    validate_data,
    validate_identity_data,
    DEFAULT_DATA_DIR,
)
from .inventory import build_inventory
from .schema_validation import validate_schemas
from .schema_validation import validate_all_schemas
from .csv_validation import validate_csv_data


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
        identity_results = validate_identity_data(data_dir)
        access_results = validate_access_references(data_dir)
        schema_results = validate_all_schemas(data_dir)
        csv_results = validate_csv_data(data_dir)

        print("Dataset readable:", counts)
        print("Identity validation:", identity_results)
        print("Access reference validation:", access_results)

        print("JSON files checked:", len(schema_results))
        print(
            "JSON schema issues:",
            sum(len(v) for v in schema_results.values())
        )

        for filename, result in csv_results.items():
            print(
                filename,
                "Records:", result["records"],
                "Issues:", len(result["issues"])
            )

        return 0
    # PHASE2_ACCESS_HANDLER
    # PHASE3_PRIVILEGED_HANDLER
    if args.command == "privileged":
        report = analyze_privileges(Path(args.data_dir))
        import json as _json
        print(_json.dumps(report, indent=2))
        return 0

    if args.command == "access":
        if bool(args.principal) == bool(args.resource):
            parser.error("Specify exactly one: --principal or --resource")
        try:
            if args.principal:
                result = principal_access(args.principal, Path(args.data_dir))
            else:
                result = resource_access(args.resource, Path(args.data_dir))
        except ValueError as exc:
            parser.error(str(exc))
        import json as _json
        print(_json.dumps(result, indent=2))
        return 0

    if args.command == "inventory":
        results = build_inventory(data_dir)
        print(json.dumps(results, indent=2))
        return 0

    print(f"NOT IMPLEMENTED: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
