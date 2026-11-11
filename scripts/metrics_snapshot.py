"""Baseline snapshot of the regression metrics, taken before the executor rewrite.

WHAT THIS IS NOT
────────────────
This is not the full diagnostic run described in the evidence plan. That run
reports unauthorized effects, UNKNOWN outcomes and the trusted boundary --
numbers that are meaningless until commit ordering and confinement are
trustworthy, which is why it is sequenced after that work. Building it now
would produce a confident-looking table resting on the very inferences it
exists to eliminate.

This script is narrower and honest: it snapshots the metrics that ARE
currently meaningful (defense rate, false positives, false negatives,
per-mechanism contribution, latency) so the executor rewrite can be checked
for regressions. It writes JSON to a file and can diff two snapshots.

USAGE
─────
    uv run python scripts/metrics_snapshot.py --out baseline.json
    uv run python scripts/metrics_snapshot.py --out after.json
    uv run python scripts/metrics_snapshot.py --compare baseline.json after.json

EXIT CODES
──────────
    0  metrics equal, or only improvements
    1  a regression was detected (defense rate down, false positives up)
    2  snapshots are from different scenario sets -- comparison is invalid
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from effect_broker.metrics import build_report

# Metrics where LOWER is better. Everything else is "lower is worse".
#
# `tcb_lines` is deliberately NOT here. It is the size of the trusted core, a
# reviewed figure with a known target, not a quantity to minimise: it grows when
# a fix is added and shrinks when logic is deleted, and either can be correct.
# Listing it as lower-is-better made every legitimate fix fail this gate — a
# fix that adds a check is "a regression" and one that removes a module is an
# improvement, which is the wrong incentive to encode in CI.
#
# It is still diffed and still reported; it just does not decide the exit code.
# A real change in TCB size should be argued in review, not gated on a number.
_ADVISORY = frozenset({"tcb_lines"})

_LOWER_IS_BETTER = frozenset(
    {
        "false_negatives",
        "false_positives",
        "false_positive_rate",
        "latency_p50_ms",
        "latency_p95_ms",
        "latency_p99_ms",
        "annotations",
    }
)

# Annotation burden: fewer explicit grants per allowed operation is better
# usability, so a DECREASE is an improvement. Listed above with the other
# lower-is-better metrics; kept explicit here because the name does not
# suggest its direction.

# Metrics that identify WHICH scenario set produced the numbers. If these
# differ, the snapshots are not comparable and we must refuse to diff them.
_IDENTITY_KEYS = ("total", "attacks", "legitimate")


def _flatten(report: dict[str, Any]) -> dict[str, float | int]:
    """Flatten a nested report into dotted scalar keys for diffing."""
    flat: dict[str, float | int] = {}

    def walk(prefix: str, node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(f"{prefix}.{k}" if prefix else str(k), v)
        elif isinstance(node, bool):
            flat[prefix] = int(node)
        elif isinstance(node, (int, float)):
            flat[prefix] = node
        # strings/lists are intentionally skipped: they are not metrics

    walk("", report)
    return flat


def snapshot() -> dict[str, Any]:
    """Capture the current report as a JSON-serialisable dict."""
    return dict(build_report())


def _is_regression(key: str, before: float, after: float) -> bool:
    """Decide whether a change is a regression.

    Latency is compared with a tolerance: sub-millisecond timing noise on a
    shared machine must not fail a build. Advisory metrics never fail a build.
    All other metrics must not move in the wrong direction at all.
    """
    if before == after:
        return False
    if key in _ADVISORY:
        return False
    if key.endswith("_ms"):
        # 25% plus 0.05 ms of slack for measurement noise.
        tolerance = max(before * 0.25, 0.05)
        return (after - before) > tolerance
    if key in _LOWER_IS_BETTER:
        return after > before
    return after < before


def compare(before_path: Path, after_path: Path) -> int:
    """Diff two snapshots. Returns a process exit code."""
    try:
        before_raw = json.loads(before_path.read_text())
        after_raw = json.loads(after_path.read_text())
    except FileNotFoundError as exc:
        print(f"ERROR: snapshot not found: {exc.filename}", file=sys.stderr)
        print("       Record it first with --out <path>.", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"ERROR: malformed snapshot JSON: {exc}", file=sys.stderr)
        return 2

    # Guard: the scenario sets must match, else the diff is meaningless.
    for key in _IDENTITY_KEYS:
        if before_raw.get(key) != after_raw.get(key):
            print(
                f"ERROR: scenario set differs on {key!r}: "
                f"{before_raw.get(key)!r} -> {after_raw.get(key)!r}",
                file=sys.stderr,
            )
            print(
                "       The snapshots are not comparable. Re-record the baseline "
                "on the current scenario set before diffing.",
                file=sys.stderr,
            )
            return 2

    before = _flatten(before_raw)
    after = _flatten(after_raw)

    changed: list[tuple[str, float, float, bool]] = []
    for key in sorted(set(before) | set(after)):
        b = before.get(key)
        a = after.get(key)
        if b is None or a is None:
            print(f"WARN: metric {key} present in only one snapshot", file=sys.stderr)
            continue
        if b != a:
            changed.append((key, b, a, _is_regression(key, b, a)))

    print("=" * 68)
    print(f"BASELINE {before_path.name}  ->  CURRENT {after_path.name}")
    print("=" * 68)
    if not changed:
        print("No metric changed.")
        print("=" * 68)
        return 0

    regressions = [c for c in changed if c[3]]
    for key, b, a, is_reg in changed:
        if key in _ADVISORY:
            marker = "advisory"
        elif is_reg:
            marker = "REGRESSION"
        else:
            marker = "ok"
        arrow = "↑" if a > b else "↓"
        print(f"  [{marker:<10}] {key:<34} {b:>10.4g} {arrow} {a:>10.4g}")

    print("=" * 68)
    if _ADVISORY & {c[0] for c in changed}:
        print("'advisory' metrics are reported but do not fail the gate:")
        print("  TCB size moves in both directions on correct changes, so it is")
        print("  argued in review rather than gated on a number.")
    if regressions:
        print(f"REGRESSIONS DETECTED: {len(regressions)}")
        for key, b, a, _ in regressions:
            print(f"  - {key}: {b:.4g} -> {a:.4g}")
        return 1
    print(f"No regressions ({len(changed)} metric(s) improved or unchanged in kind).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", type=Path, help="write a snapshot JSON to this path")
    group.add_argument(
        "--compare",
        nargs=2,
        metavar=("BEFORE", "AFTER"),
        type=Path,
        help="diff two snapshot files",
    )
    args = parser.parse_args(argv)

    if args.compare:
        return compare(args.compare[0], args.compare[1])

    report = snapshot()
    out: Path = args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    print("=" * 64)
    print(f"SNAPSHOT written to {out}")
    print("=" * 64)
    print(
        f"Scenarios:        {report['total']} "
        f"(attacks={report['attacks']}, legit={report['legitimate']})"
    )
    print(f"Defense rate:     {report['defense_rate'] * 100:.1f}%")
    print(f"False negatives:  {report['false_negatives']}")
    print(f"False positives:  {report['false_positives']}")
    print(f"TCB size:         {report['tcb_lines']} lines")
    print("=" * 64)
    print("NOTE: regression metrics on supplied scenarios only.")
    print("This is not the full diagnostic run: UNKNOWN and")
    print("unauthorized-effect counts are absent by design and stay")
    print("absent until commit ordering and confinement are trustworthy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
