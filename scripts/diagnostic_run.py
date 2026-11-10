"""Diagnostic run: all seven metrics as text or JSON.

Every metric is present even when its honest value is zero — a missing field
reads as "not measured", which is exactly the confusion the run exists to
prevent. Where a number cannot be measured portably (syscall counts), the
report says `null` rather than inventing one.

USAGE
    uv run python scripts/diagnostic_run.py
    uv run python scripts/diagnostic_run.py --json
    uv run python scripts/diagnostic_run.py --json --out diagnostic.json
"""

from __future__ import annotations

import argparse
import json
import sys

from effect_broker.metrics import diagnostic_report, print_diagnostic_report


def main() -> int:
    parser = argparse.ArgumentParser(description="ECAC seven-metric diagnostic run.")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--out", help="write the report to this path")
    args = parser.parse_args()

    report = diagnostic_report()

    if args.json:
        payload = json.dumps(report, indent=2, sort_keys=True)
    else:
        print_diagnostic_report()
        payload = json.dumps(report, indent=2, sort_keys=True)

    if args.out:
        from pathlib import Path

        Path(args.out).write_text(payload + "\n")
        print(f"wrote {args.out}", file=sys.stderr)
    elif args.json:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
