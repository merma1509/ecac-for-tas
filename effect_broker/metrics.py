"""Evaluation reporting metrics

This module computes the metrics that a pass/fail printout omits. It runs the
REAL gate (broker.commit) on a labeled set of scenarios, so every metric is
derived from actual broker behavior, not a hardcoded number.

Metrics:
  - defense rate          : % of attacks the gate blocks (correct predicate)
  - false negatives       : attacks ALLOWED (defense failed)
  - false positives       : legitimate operations BLOCKED (usability cost)
  - per-mechanism contribution : how many attacks each predicate blocks
                               (Auth/FlowOK/NoAmp/Fresh) — the mechanism-level
                               breakdown a pass/fail report lacks
  - latency percentile    : p50 / p95 / p99 gate evaluation time
  - annotation burden     : number of explicit grants per allowed operation
  - TCB size              : executable lines in the trusted core (see _TCB_FILES)

Honesty note: these are REGRESSION metrics on supplied scenarios.
They quantify how the current build behaves on a fixed set; they are not a
causal estimate of protection against adaptive/live attackers.
"""

from __future__ import annotations

import ast
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, TypedDict

from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import (
    Capability,
    Commit,
    Data,
    Domain,
    Effect,
    EffectTarget,
    Task,
)
from effect_broker.traces import build

if TYPE_CHECKING:
    from effect_broker.broker import EffectBroker

# The trusted core: the code whose correctness the security argument rests on.
# (Excludes shims, tests, baselines, and the evaluation harness.)

_TCB_FILES = (
    "effect_broker/broker.py",
    "effect_broker/model.py",
    "effect_broker/executor.py",
    "effect_broker/restricted_store.py",
)


class EvaluationReport(TypedDict, total=False):
    """Shape of the §6 metrics report dict (see build_report)."""

    total: int
    attacks: int
    legitimate: int
    attacks_blocked: int
    false_negatives: int
    false_positives: int
    defense_rate: float
    false_positive_rate: float
    per_mechanism: dict[str, int]
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    annotations: int
    tcb_lines: int
    session_taint: dict[str, object]


@dataclass
class _Scenario:
    """A labeled scenario: is it an attack or a legitimate operation, and what
    should the gate do (block vs allow)?"""

    name: str
    is_attack: bool
    # Build an Effect on the given (broker, task). Returns the effect to commit.
    builder: Callable[[EffectBroker, Task], Effect]
    ceiling_scope: frozenset[str] = frozenset({"*"})


@dataclass
class EvaluationMetrics:
    total: int = 0
    attacks: int = 0
    legitimate: int = 0
    attacks_blocked: int = 0
    attacks_missed: int = 0  # false negatives
    legit_blocked: int = 0  # false positives
    legit_allowed: int = 0
    per_mechanism: dict[str, int] = field(default_factory=dict)
    latency_ms: list[float] = field(default_factory=list)
    annotations: int = 0

    def _percentile(self, p: float) -> float:
        if not self.latency_ms:
            return 0.0
        xs = sorted(self.latency_ms)
        k = (len(xs) - 1) * (p / 100.0)
        lo = int(k)
        hi = min(lo + 1, len(xs) - 1)
        frac = k - lo
        return xs[lo] + (xs[hi] - xs[lo]) * frac

    @property
    def defense_rate(self) -> float:
        return (self.attacks_blocked / self.attacks) if self.attacks else 0.0

    @property
    def false_positive_rate(self) -> float:
        return (self.legit_blocked / self.legitimate) if self.legitimate else 0.0

    def p50(self) -> float:
        return self._percentile(50)

    def p95(self) -> float:
        return self._percentile(95)

    def p99(self) -> float:
        return self._percentile(99)

    def as_dict(self) -> EvaluationReport:
        return EvaluationReport(
            total=self.total,
            attacks=self.attacks,
            legitimate=self.legitimate,
            attacks_blocked=self.attacks_blocked,
            false_negatives=self.attacks_missed,
            false_positives=self.legit_blocked,
            defense_rate=self.defense_rate,
            false_positive_rate=self.false_positive_rate,
            per_mechanism=dict(self.per_mechanism),
            latency_p50_ms=self.p50(),
            latency_p95_ms=self.p95(),
            latency_p99_ms=self.p99(),
            annotations=self.annotations,
        )


def _task(scope: frozenset[str] = frozenset({"*"})) -> Task:
    ceiling = Capability(
        owner="User",
        holder="EffectBroker",
        right="*",
        target="*",
        scope=scope,
        expiry=float("inf"),
        nonce="metrics-ceiling",
    )
    return Task(task_id="metrics", owner="User", ceiling=ceiling)


def _cap(owner: str, right: str, target: str, scope: frozenset[str], nonce: str) -> Capability:
    return Capability(
        owner=owner,
        holder="EffectBroker",
        right=right,
        target=target,
        scope=scope,
        expiry=float("inf"),
        nonce=nonce,
    )


def _build_scenarios() -> list[_Scenario]:
    """A labeled set mixing attacks and legitimate operations.

    Each scenario installs its capability and returns the effect to commit on
    a fresh (broker, task). The builder counts the grants it makes so
    "annotation burden" reflects the real number of explicit grants.
    """

    def _install(broker: EffectBroker, task: Task) -> None:
        broker.register_task(task)

    def _read(target: str, nonce: str) -> Effect:
        return Effect(
            etype="read",
            target=target,
            metadata={},
            provenance=(),
            capability_nonce=nonce,
            delegation_chain=(),
        )

    def _send(target: str, nonce: str, additional: frozenset[str] | None = None) -> Effect:
        known = EffectTarget(primary=target, additional=additional) if additional else None
        return Effect(
            etype="send",
            target=target,
            metadata={},
            provenance=(Data("msg", Confidentiality.INTERNAL, Integrity.USER),),
            capability_nonce=nonce,
            delegation_chain=(),
            known_targets=known,
        )

    scenarios: list[_Scenario] = []

    # --- Attacks (should be BLOCKED) ---
    def a_out_of_ceiling(broker: EffectBroker, task: Task) -> Effect:
        broker.capabilities["a-oo"] = _cap(
            "User", "read", "*", frozenset({"file:///reports"}), "a-oo"
        )
        return _read("file:///secrets/x", "a-oo")  # outside ceiling scope -> Auth

    def a_bcc_outside_scope(broker: EffectBroker, task: Task) -> Effect:
        broker.capabilities["a-bcc"] = _cap(
            "User", "send", "internal@corp.com", frozenset({"internal"}), "a-bcc"
        )
        return _send("internal@corp.com", "a-bcc", additional=frozenset({"evil@evil.com"}))  # NoAmp

    def a_replay(broker: EffectBroker, task: Task) -> Effect:
        broker.capabilities["a-rep"] = _cap(
            "User",
            "read",
            "file:///reports/x",
            frozenset({"file:///reports"}),
            "a-rep",
        )
        # First use consumes the nonce; the committed effect below is the REPLAY.
        first = _read("file:///reports/x", "a-rep")
        broker.commit(Commit(first, task))
        return _read("file:///reports/x", "a-rep")  # Fresh (replay)

    def a_session_taint(broker: EffectBroker, task: Task) -> Effect:
        broker.capabilities["a-tread"] = _cap("User", "*", "*", frozenset({"*"}), "a-tread")
        broker.capabilities["a-tsend"] = _cap("User", "send", "*", frozenset({"*"}), "a-tsend")
        broker.commit(Commit(_read("file:///secrets", "a-tread"), task))  # taints session
        return _send("internal@corp.com", "a-tsend")  # FlowOK (session-taint)

    # --- Legitimate (should be ALLOWED) ---
    def l_in_scope(broker: EffectBroker, task: Task) -> Effect:
        broker.capabilities["l-ok"] = _cap(
            "User", "read", "file:///reports/x", frozenset({"file:///reports"}), "l-ok"
        )
        return _read("file:///reports/x", "l-ok")  # in scope -> allow

    def l_internal_send(broker: EffectBroker, task: Task) -> Effect:
        broker.capabilities["l-send"] = _cap(
            "User", "send", "internal@corp.com", frozenset({"internal"}), "l-send"
        )
        return _send("internal@corp.com", "l-send")  # approved internal -> allow

    # (builder, is_attack)
    scenarios.append(
        _Scenario(
            "attack:out-of-ceiling-read",
            True,
            a_out_of_ceiling,
            ceiling_scope=frozenset({"file:///reports"}),
        )
    )
    scenarios.append(_Scenario("attack:external-bcc", True, a_bcc_outside_scope))
    scenarios.append(_Scenario("attack:nonce-replay", True, a_replay))
    scenarios.append(_Scenario("attack:session-taint-exfil", True, a_session_taint))
    scenarios.append(
        _Scenario(
            "legit:in-scope-read", False, l_in_scope, ceiling_scope=frozenset({"file:///reports"})
        )
    )
    scenarios.append(_Scenario("legit:internal-send", False, l_internal_send))
    return scenarios


def compute_metrics() -> EvaluationMetrics:
    """Run the labeled scenarios through the REAL gate and compute metrics."""
    import warnings

    warnings.filterwarnings("ignore")

    m = EvaluationMetrics()
    for sc in _build_scenarios():
        broker = build()
        task = _task(sc.ceiling_scope)
        # Annotation burden: count the explicit grants THIS scenario added
        # (delta over the broker's seeded capabilities), not the whole store.
        before = len(broker.capabilities)
        effect = sc.builder(broker, task)
        m.annotations += len(broker.capabilities) - before

        start = time.perf_counter()
        allow, evidence = broker.commit(Commit(effect, task))
        latency = (time.perf_counter() - start) * 1000

        m.total += 1
        m.latency_ms.append(latency)

        blocked = not allow
        blocker = evidence.get("primary_blocker")

        if sc.is_attack:
            m.attacks += 1
            if blocked:
                m.attacks_blocked += 1
                if blocker:
                    m.per_mechanism[blocker] = m.per_mechanism.get(blocker, 0) + 1
            else:
                m.attacks_missed += 1  # false negative
        else:
            m.legitimate += 1
            if blocked:
                m.legit_blocked += 1  # false positive
            else:
                m.legit_allowed += 1
    return m


def _docstring_line_numbers(text: str) -> set[int]:
    """1-based line numbers occupied entirely by a module/class/function docstring.

    A docstring is prose that happens to be a string literal: no attacker can
    exploit it. Counting it as code inflated the trusted core by 1238 lines out
    of 3401 (~36%), which is the same error the comment filter was added to fix,
    in the form that survived it.

    A line is excluded only if nothing but whitespace surrounds the literal on
    it, so a single-line def whose body is a docstring still counts as the code
    it is.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        # Mid-edit or generated file: skip the refinement rather than fail a
        # metrics run. The result is then the (higher) comment-only figure.
        return set()

    lines = text.splitlines()
    spans: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", ())
        if not body:
            continue
        first = body[0]
        if not (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            continue

        literal = first.value
        start = literal.lineno
        end = literal.end_lineno or start
        for line_no in range(start, end + 1):
            if line_no > len(lines):
                continue
            line = lines[line_no - 1]
            if line_no == start and line[: literal.col_offset].strip():
                continue  # code precedes the literal on its first line
            if line_no == end and line[literal.end_col_offset :].strip():
                continue  # code follows the literal on its last line
            spans.add(line_no)
    return spans


def _count_code_lines(text: str) -> int:
    """Count lines that execute: non-blank, not a comment, not a docstring.

    Raw line count was misleading: documenting a decision grew the reported
    TCB by 171 lines without adding a single executable statement. The metric
    exists to size what must be CORRECT, so comments, docstrings and blank
    lines -- none of which an attacker can exploit -- must not inflate it.
    """
    docstring_lines = _docstring_line_numbers(text)
    return sum(
        1
        for line_no, line in enumerate(text.splitlines(), start=1)
        if line.strip() and not line.strip().startswith("#") and line_no not in docstring_lines
    )


def tcb_size() -> int:
    """Executable lines in the trusted core (`_TCB_FILES`).

    Counts lines that execute only; see `_count_code_lines`. Use this as the
    trend metric: an increase means more logic the security argument depends
    on. `tcb_breakdown()` gives the per-file split, which is what a reader
    checking the figure against `docs/ARCHITECTURE.md` needs.
    """
    root = Path(__file__).resolve().parent.parent
    total = 0
    for rel in _TCB_FILES:
        path = root / rel
        if path.exists():
            total += _count_code_lines(path.read_text())
    return total


def tcb_breakdown() -> dict[str, int]:
    """Per-file executable line counts, in `_TCB_FILES` order.

    Reported alongside the total so a divergence from the documented TCB is
    visible where it happens rather than only in the sum.
    """
    root = Path(__file__).resolve().parent.parent
    breakdown: dict[str, int] = {}
    for rel in _TCB_FILES:
        path = root / rel
        breakdown[Path(rel).name] = _count_code_lines(path.read_text()) if path.exists() else 0
    return breakdown


def session_taint_metrics() -> dict[str, object]:
    """Measure honest taint accounting on a REAL broker scenario.

    Drives one representative workflow through the real gate:
        confidential read (taints) -> send blocked by session-taint ->
        explicit narrow declass on the same task (clears the resource).

    Returns the DISTINCT signals {taint_rate, false_denial_proxy} with the
    raw counters. These are honest metrics: taint_rate is the COST of the
    conservative session taint; false_denial_proxy is an ANNOTATION-FREE
    PROXY for over-blocking (a block the user later lifted), NOT ground truth.
    """
    from effect_broker.model import (
        APPROVER,
        BROKER,
        USER,
        Capability,
        Commit,
        Data,
        Effect,
        LabelException,
        Task,
    )
    from effect_broker.traces import build

    broker = build()
    task = Task(
        task_id="taint-metrics",
        owner=USER,
        ceiling=Capability(
            owner=USER,
            holder=BROKER,
            right="*",
            target="*",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="ceil-taint-metrics",
        ),
    )
    broker.register_task(task)
    for nonce, etype, target in (
        ("read-cap-taint", "read", "file:///secrets"),
        ("send-cap-taint", "send", "internal@corp.com"),
    ):
        broker.capabilities[nonce] = Capability(
            owner=USER,
            holder=BROKER,
            right=etype,
            target=target,
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce=nonce,
        )
    broker.store._unsafe_bootstrap_file("file:///secrets", Confidentiality.CONFIDENTIAL)
    broker.store._unsafe_bootstrap_email("internal@corp.com", Domain.INTERNAL)

    # 1) confidential read -> taints the session (taint-rate: reads_that_tainted += 1)
    broker.commit(
        Commit(
            Effect(
                "read",
                "file:///secrets",
                {},
                (),
                "read-cap-taint",
                (BROKER,),
                task_id="taint-metrics",
            ),
            task,
        )
    )
    # 2) send while tainted -> BLOCKED (sends_blocked_by_taint += 1)
    blocked, ev = broker.commit(
        Commit(
            Effect(
                "send",
                "internal@corp.com",
                {},
                (Data("body", Confidentiality.INTERNAL, Integrity.USER),),
                "send-cap-taint",
                (BROKER,),
                task_id="taint-metrics",
            ),
            task,
        )
    )
    assert not blocked, f"send while tainted must block: {ev}"
    # 3) explicit declass on the same task -> proxy += 1
    broker.grant_label_exception(
        LabelException(
            kind="declass",
            match_target="*",
            from_label="CONFIDENTIAL",
            to_label="INTERNAL",
            granted_by=APPROVER,
            nonce="declass-taint-metrics",
            data_resources=frozenset({"*"}),
            task_id="taint-metrics",
        ),
        task_id="taint-metrics",
    )

    metrics = broker.get_taint_metrics()
    assert metrics is not None, "broker must expose taint metrics"
    return metrics


def build_report() -> EvaluationReport:
    """A single dict containing all §6 metrics (pass/fail + the additions)."""
    m = compute_metrics()
    report = m.as_dict()
    report["tcb_lines"] = tcb_size()
    # honest taint accounting (taint rate + false-denial proxy).
    report["session_taint"] = session_taint_metrics()
    return report


# ─────────────────────────── ───────────────────────────
# The seven-metric diagnostic table. Each metric must be present even when
# the honest value is zero — an absent field reads as "not measured".


def trusted_boundary() -> list[str]:
    """Components the other numbers depend on to report truthfully.

    Explicit and reviewed: if any of these lies, the metrics are unsupported.
    This list IS the trusted boundary metrically.
    """
    return [
        "effect_broker/shim_real.py — performs real I/O and reports it",
        "effect_broker/broker.py — the store is the observation source",
        "effect_broker/executor_subprocess.py — applies effects, reports observed targets",
        "effect_broker/oracle.py — derives verdicts from external sources",
        "effect_broker/metrics.py — labels scenarios attack/legitimate",
    ]


def diagnostic_report() -> dict[str, object]:
    """The seven metrics from one run of the labeled scenario set."""
    import warnings

    warnings.filterwarnings("ignore")

    m = EvaluationMetrics()
    unauthorized_effects = 0
    approvals_granted = 0
    approvals_used = 0
    approvals_expired_unused = 0
    false_denials: dict[str, int] = {}

    for sc in _build_scenarios():
        broker = build()
        task = _task(sc.ceiling_scope)
        before = len(broker.capabilities)
        effect = sc.builder(broker, task)
        granted_here = len(broker.capabilities) - before
        approvals_granted += granted_here

        start = time.perf_counter()
        allow, evidence = broker.commit(Commit(effect, task))
        m.latency_ms.append((time.perf_counter() - start) * 1000)

        m.total += 1
        blocked = not allow
        blocker = evidence.get("primary_blocker")

        # An allowed effect must have an authorizing capability on record.
        if allow and effect.capability_nonce not in broker.capabilities:
            unauthorized_effects += 1

        # session is always set: Task.__post_init__ creates a default one.
        session = task.session
        assert session is not None
        if effect.capability_nonce in session.used:
            approvals_used += 1
        elif granted_here and not blocked:
            approvals_expired_unused += 1  # granted, never consumed

        if sc.is_attack:
            m.attacks += 1
            if blocked:
                m.attacks_blocked += 1
                if blocker:
                    m.per_mechanism[blocker] = m.per_mechanism.get(blocker, 0) + 1
            else:
                m.attacks_missed += 1
        else:
            m.legitimate += 1
            if blocked:
                m.legit_blocked += 1
                # by predicate, so over-blocking has an address
                key = blocker or "unknown"
                false_denials[key] = false_denials.get(key, 0) + 1
            else:
                m.legit_allowed += 1

    return {
        # 1. Unauthorized effects: allowed with no authorizing record.
        "unauthorized_effects": unauthorized_effects,
        # 2. Legitimate completion: benign operations that succeeded.
        "legitimate_completion": m.legit_allowed,
        "legitimate_total": m.legitimate,
        # 3. False denials, by predicate.
        "false_denials": false_denials,
        "false_denials_total": m.legit_blocked,
        # 4. UNKNOWN outcomes: explicitly reported by the ledger's own
        # verify_complete_mediation; distinct from a False verdict.
        "unknown_outcomes": _ledger_unknowns(),
        # 5. Approvals: granted vs used vs expired unused.
        "approvals": {
            "granted": approvals_granted,
            "used": approvals_used,
            "expired_unused": approvals_expired_unused,
        },
        # 6. Overhead: wall-clock. Syscall counts are not portable; the honest
        # report omits them rather than inventing a number.
        "overhead": {
            "wall_clock_p50_ms": m.p50(),
            "wall_clock_p95_ms": m.p95(),
            "wall_clock_p99_ms": m.p99(),
            "syscalls": None,
        },
        # 7. Trusted boundary: the reviewed list.
        "trusted_boundary": trusted_boundary(),
        # Context from the regression report.
        "attacks": m.attacks,
        "attacks_blocked": m.attacks_blocked,
        "false_negatives": m.attacks_missed,
    }


def _ledger_unknowns() -> int:
    """Count UNKNOWN verdicts from the ledger's own complete-mediation check.

    UNKNOWN is the ledger's category (IN_FLIGHT without evidence, observation
    with no authorization). It is read from there rather than inferred from
    gate evidence, which never carries a mediation verdict.
    """
    import warnings

    from effect_broker.ledger import UnknownLedgerResult

    warnings.filterwarnings("ignore")
    unknowns = 0
    for sc in _build_scenarios():
        broker = build()
        task = _task(sc.ceiling_scope)
        effect = sc.builder(broker, task)
        broker.commit(Commit(effect, task))
        verdict = broker.ledger.verify(task.task_id, effect.capability_nonce or "")
        if isinstance(verdict, UnknownLedgerResult):
            unknowns += 1
    return unknowns


def print_diagnostic_report() -> None:
    """The table, text form. JSON: json.dumps(diagnostic_report())."""
    r = diagnostic_report()
    print("=" * 64)
    print("ECAC DIAGNOSTIC RUN")
    print("=" * 64)
    print(f"1. Unauthorized effects:   {r['unauthorized_effects']}")
    print(f"2. Legitimate completion:  {r['legitimate_completion']}/{r['legitimate_total']}")
    print(f"3. False denials:          {r['false_denials_total']} {r['false_denials']}")
    print(f"4. UNKNOWN outcomes:       {r['unknown_outcomes']}")
    ap = r["approvals"]
    assert isinstance(ap, dict)
    print(
        f"5. Approvals:              granted={ap['granted']} used={ap['used']} "
        f"expired_unused={ap['expired_unused']}"
    )
    ov = r["overhead"]
    assert isinstance(ov, dict)
    print(
        f"6. Overhead (wall clock):  p50={ov['wall_clock_p50_ms']:.2f}ms "
        f"p95={ov['wall_clock_p95_ms']:.2f}ms p99={ov['wall_clock_p99_ms']:.2f}ms "
        f"(syscalls: not measured)"
    )
    print("7. Trusted boundary (these must tell the truth for 1-6 to mean anything):")
    tb = r["trusted_boundary"]
    assert isinstance(tb, list)
    for component in tb:
        print(f"   - {component}")
    print("=" * 64)
    print(
        f"Context: attacks={r['attacks']} blocked={r['attacks_blocked']} "
        f"missed={r['false_negatives']}"
    )


def main(argv: list[str] | None = None) -> int:
    """Entry point: the regression report, or `--diagnostic` for the seven metrics.

    Previously this module had two `if __name__ == "__main__"` blocks, so the
    first one won and `print_report()` was unreachable from the command line —
    `python -m effect_broker.metrics` silently printed the diagnostic table
    instead of the regression metrics the module is named for.
    """
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in {"-h", "--help"}:
        print("usage: python -m effect_broker.metrics [--diagnostic]")
        return 0
    if args and args[0] == "--diagnostic":
        print_diagnostic_report()
        return 0
    if args:
        print(f"unknown argument: {args[0]}", file=sys.stderr)
        return 2
    print_report()
    return 0


def print_report() -> None:
    r = build_report()
    print("=" * 64)
    print("ECAC EVALUATION METRICS (regression scenarios)")
    print("=" * 64)
    print(f"Scenarios:            {r['total']} (attacks={r['attacks']}, legit={r['legitimate']})")
    print(
        f"Defense rate:         {r['defense_rate'] * 100:.1f}% "
        f"({r['attacks_blocked']}/{r['attacks']} attacks blocked)"
    )
    print(f"False negatives:      {r['false_negatives']} (attacks allowed)")
    print(f"False positives:      {r['false_positives']} (legit blocked)")
    print("Per-mechanism contribution (attacks blocked by predicate):")
    for mech, n in sorted(r["per_mechanism"].items(), key=lambda x: -x[1]):
        print(f"  {mech:<10} {n}")
    print(
        f"Latency p50/p95/p99:  {r['latency_p50_ms']:.2f} / "
        f"{r['latency_p95_ms']:.2f} / {r['latency_p99_ms']:.2f} ms"
    )
    print(f"Annotations:          {r['annotations']} explicit grants across scenarios")
    breakdown = tcb_breakdown()
    detail = ", ".join(f"{name}={n}" for name, n in breakdown.items())
    print(f"TCB size:             {r['tcb_lines']} executable lines ({detail})")
    st = r.get("session_taint", {})
    if st:
        print("Session-taint (honest:")
        print(
            f"  taint_rate          {st.get('taint_rate', 0.0):.1%} "
            f"({st.get('reads_that_tainted', 0)}/{st.get('total_reads', 0)} reads tainted)"
        )
        print(
            f"  false_denial_proxy  {st.get('false_denial_proxy', 0.0):.1%} "
            f"({st.get('blocked_sends_later_declassed', 0)}/"
            f"{st.get('sends_blocked_by_taint', 0)} blocks later lifted)"
        )
        print("  (proxy, not ground truth: annotation-free signal of over-blocking)")
    print("=" * 64)
    print("NOTE: regression metrics on supplied scenarios; not a causal")
    print("estimate of protection vs adaptive/live attackers.")


if __name__ == "__main__":
    raise SystemExit(main())
