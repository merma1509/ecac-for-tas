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

from .experiment import (
    collect_outcome_counts,
    print_outcome_counts,
    print_results,
)


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

    results, counts = collect_outcome_counts()
    print_results(results)
    print_outcome_counts(counts)
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

    # Exit code: 0 only if every result was EVALUATED and passed.
    #
    # The old form was `all(r.mediation_complete ...)`, which treated an
    # unevaluated result as a pass the moment the field was defaulted to True,
    # and would treat None as failure-by-accident otherwise. "Did not check" is
    # neither pass nor fail; making it a separate condition forces the missing
    # check to be visible instead of silently green.
    unevaluated = [n for n, r in results.items() if not r.mediation_evaluated]
    failed = [
        n
        for n, r in results.items()
        if r.mediation_evaluated and r.mediation_complete is False
    ]
    all_passed = not unevaluated and not failed
    if unevaluated:
        print(f"NOT EVALUATED ({len(unevaluated)}): mediation was never checked")
        for n in unevaluated:
            print(f"  - {n}")
    if failed:
        print(f"MEDIATION INCOMPLETE ({len(failed)}):")
        for n in failed:
            result = results[n]
            print(f"  - {n}")
            for failure in result.mediation_failures:
                print(f"      {failure}")
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    # For `python -m effect_broker` use the full main() with argparse
    main()
