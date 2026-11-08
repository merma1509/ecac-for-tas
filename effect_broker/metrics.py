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
  - TCB size              : lines of code in the trusted core (broker+model)

Honesty note: these are REGRESSION metrics on supplied scenarios.
They quantify how the current build behaves on a fixed set; they are not a
causal estimate of protection against adaptive/live attackers.
"""

from __future__ import annotations

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
_TCB_FILES = ("effect_broker/broker.py", "effect_broker/model.py")


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


def tcb_size() -> int:
    """Lines of code in the trusted core (broker + model)."""
    root = Path(__file__).resolve().parent.parent
    total = 0
    for rel in _TCB_FILES:
        path = root / rel
        if path.exists():
            total += len(path.read_text().splitlines())
    return total


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
    print(f"TCB size:             {r['tcb_lines']} lines (broker.py + model.py)")
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
    print_report()
