#!/usr/bin/env python3
"""Simple offline launcher; no packaging installation required."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
from ztlab.cli import main
if __name__ == '__main__':
    raise SystemExit(main())
