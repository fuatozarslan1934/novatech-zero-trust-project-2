"""CLI starter — students implement each investigation command."""
from __future__ import annotations
import argparse
from pathlib import Path
from .data_loader import validate_data, DEFAULT_DATA_DIR

COMMANDS = ["validate-data","inventory","access","privileged","policy-check","attack-paths","explain-path","compare-controls","report"]

def main() -> int:
    parser = argparse.ArgumentParser(description="NovaTech Project 2: Offline Zero Trust Security Analyzer")
    parser.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR), help="Directory containing simulation data")
    sub = parser.add_subparsers(dest="command", required=True)
    for cmd in COMMANDS:
        p=sub.add_parser(cmd)
        if cmd=="access":
            p.add_argument("--principal")
            p.add_argument("--resource")
        elif cmd=="policy-check":
            p.add_argument("--user",required=True);p.add_argument("--app",required=True);p.add_argument("--source-ip",required=True)
            p.add_argument("--mfa",choices=["true","false"],required=True)
            p.add_argument("--compliant",choices=["true","false"],required=True)
        elif cmd=="explain-path":p.add_argument("--path-id",required=True)
        elif cmd=="compare-controls":p.add_argument("--baseline",required=True);p.add_argument("--proposed",required=True)
        elif cmd=="report":p.add_argument("--format",choices=["json","html","md"],default="md")
    args=parser.parse_args()
    if args.command=="validate-data":
        counts=validate_data(Path(args.data_dir))
        print("Dataset readable:", counts)
        return 0
    print(f"NOT IMPLEMENTED: {args.command}. This is your assignment; read README.md.")
    return 2

if __name__=="__main__":
    raise SystemExit(main())
