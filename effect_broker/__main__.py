"""CLI entry point for the effect-broker conformance experiment.

Run the mandatory experiments to verify all five kill criteria:

    $ python -m effect_broker
    $ uv run python -m effect_broker

Or call the experiment module directly:

    $ python -m effect_broker.experiment
"""

from __future__ import annotations

import argparse
import sys

from .experiment import print_results, run_all_experiments


def main() -> None:
    """Run all conformance experiments and print results.

    Exit code:
        0 = all experiments passed (all five kill criteria verified)
        1 = one or more experiments failed (mediation incomplete or kill criterion not met)
    """
    parser = argparse.ArgumentParser(
        prog="effect-broker",
        description="Effect broker conformance experiment — verify all five kill criteria.",
    )
    parser.add_argument(
        "--warn-same-process",
        action="store_true",
        help="Show the same-process assumption warning",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show per-experiment details (not just pass/fail summary)",
    )
    args = parser.parse_args()

    # Suppress same-process warning unless explicitly requested
    import warnings

    if not args.warn_same_process:
        warnings.filterwarnings("ignore", message="SAME-PROCESS", category=UserWarning)

    results = run_all_experiments()
    print_results(results)
    sys.stdout.flush()

    if args.verbose:
        print()
        for name, result in results.items():
            print(f"  {name}:")
            print(f"    mediation_complete={result.mediation_complete}")
            print(f"    actual_allow={result.actual_allow}")
            print(f"    expected_blocker={result.expected_blocker}")
            if result.replay_blocked:
                print(f"    replay_blocked={result.replay_blocked}")

    # Exit code: 0 if all passed, 1 if any failed
    all_passed = all(r.mediation_complete for r in results.values())
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    # For `python -m effect_broker` use the full main() with argparse
    main()
