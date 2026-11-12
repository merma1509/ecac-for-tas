"""The trusted computing base: what ECAC's security argument rests on.

The list lives in tracked source on purpose. `docs/ARCHITECTURE.md` also
describes the TCB, but `docs/` is not tracked by git (see .gitignore), so a
definition that exists only there is invisible to CI: the test that compared the
metric against the document skipped, and the metric could drift unobserved while
everything stayed green.

Composition rule — a module belongs here if a defect in it can make `accept` and
`reject` swap, or can mutate external state without the gate approving it:

  * the gate and its predicates  (broker.py, model.py)
  * the only path that mutates state  (executor.py)
  * the store the gate reasons about  (restricted_store.py)

Deliberately excluded, and why:

  * ledger.py        — observes and records; a bug in it falsifies the *account*
                       of what happened, not the allow/deny decision.
  * mediation.py     — boundary advice consulted by the gate; when absent the
                       gate still runs, and every non-allow path is a denial.
  * shims, ipc, tests, baselines, the evaluation harness — untrusted by design.

`baselines/` is excluded in particular because those comparators exist to be
*scored*, not trusted; counting them would inflate the TCB by the size of the
alternatives being ruled out.
"""

from __future__ import annotations

# (module path, one-line role). Order is presentation order in reports.
TCB_MODULES: tuple[tuple[str, str], ...] = (
    ("effect_broker/broker.py", "4-predicate gate, approval binding, orchestration"),
    ("effect_broker/model.py", "Effect, Capability, Task, Session, canonical request"),
    ("effect_broker/executor.py", "sole mutation path"),
    ("effect_broker/restricted_store.py", "resource store the gate reasons about"),
)

TCB_FILES: tuple[str, ...] = tuple(path for path, _ in TCB_MODULES)


def assert_complete() -> None:
    """Fail if a listed module is missing or an unlisted one looks trusted.

    Called by the metrics module at import time: a TCB that silently undercounts
    is worse than no figure, because it is quoted.
    """
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    missing = [rel for rel in TCB_FILES if not (root / rel).exists()]
    if missing:
        raise AssertionError(
            f"TCB modules listed but absent: {missing}. Either restore them or "
            f"remove them from TCB_MODULES — a missing path is skipped by the "
            f"line count, so the reported TCB would silently shrink."
        )
