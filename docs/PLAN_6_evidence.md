# PLAN 6 — Evidence: Occurrence, Provenance Fidelity, Concurrency & Comparators

**Status:** Proposed
**Priority:** HIGH (until this lands, no claim about effectiveness is supported)
**Supersedes:** PLAN 3 (marked COMPLETE; the comparisons still omit the central
mechanisms of the systems they name)

---

## Why this plan exists

The system can currently report "17/18 blocked" and "mediation complete" without
being able to establish:

- whether a blocked effect was blocked _by the intended mechanism_;
- whether an effect happened once, twice, or transiently;
- whether a `LabelException` survived the process boundary intact;
- whether two concurrent attempts got two tickets or one;
- whether the named baselines actually implement the named mechanisms.

Trigger: external review, items 4, 5 and 6.

This plan is the measurement layer. **Do not expand features until it lands** —
every additional feature enlarges the surface that cannot yet be measured.

---

## Part A — Occurrence identity and observation windows

### Evidence

`effect_broker/oracle.py`:

```
:36   observed: bool                             # boolean, no count
:67   exists = os.path.exists(target_path)       # existence, not recurrence
:107  delivered = {rcpt for rcpt, _data in ...}  # set collapses duplicates
:114  verify_hidden_recipients(declared)         # checks SUPPLIED addresses only
```

Concrete blind spots:

- `write(x); write(x)` → one `exists=True`. One occurrence vs. two: identical.
- `write(x); delete(x)` → `file-absent` → reported as "effect did not happen",
  indistinguishable from `delete(x)` alone or from nothing at all.
- `send(a); send(a)` → `delivered == {a}`. Repeats collapse.
- No observation window, so an effect that lands after the check is invisible;
  an effect from a previous run is indistinguishable from this one.
- `verify_hidden_recipients` can only flag recipients present in `smtp_log` but
  absent from `declared`. A recipient hidden from _both_ is not detectable by
  this method at all — which is what the reviewer means by "the SMTP probe
  checks supplied addresses; it does not discover arbitrary hidden recipients".

### Design

**Occurrence record, not a verdict.** The observer emits events; verdicts are
derived.

```python
@dataclass(frozen=True)
class Occurrence:
    effect_id: str            # unique per occurrence (from PLAN 4)
    payload_id: str           # digest of what was actually transmitted/written
    etype: str
    target: str
    targets: frozenset[str]   # full observed target set for this occurrence
    observed_at: float
    source: str               # "fs-diff" | "smtp-envelope" | "imap-uid"
    window: tuple[float, float]
```

Counting then becomes `len([o for o in occurrences if o.effect_id == eid])`:

| Scenario                     | Today              | After                                    |
| ---------------------------- | ------------------ | ---------------------------------------- |
| two identical writes         | `True`             | 2 occurrences, same `payload_id`         |
| write then delete            | `False` ("absent") | 2 occurrences, both recorded             |
| repeat send to one recipient | 1 (set)            | 2 occurrences                            |
| late delivery                | invisible          | outside window ⇒ flagged `out_of_window` |

**Envelope-level SMTP observation.** Instead of probing supplied addresses, read
the transport's own transaction record after acceptance: for a local MTA that is
the mail log / queue; the observation must be of the _envelope_ (`RCPT TO`
records actually accepted during `DATA`), not of the request. Hidden recipients
then surface because the MTA recorded them, not because we guessed them. Where
no such source exists, the honest answer is `UNKNOWN` — not "no hidden
recipients".

### Tasks

- [ ] Define `Occurrence` in `oracle.py`; replace `OracleVerdict.observed: bool`.
- [ ] Filesystem observer: diff-based, records every occurrence, keeps history.
- [ ] SMTP observer: read envelope transactions from the MTA log/queue.
- [ ] Add `window` to every observation; flag effects outside it.
- [ ] Report occurrences with zero broker claims (the "absent from claims" case).
- [ ] Rewrite `verify_hidden_recipients` against envelope records, not the request.
- [ ] Tests: double write, write-then-delete, repeated send, late delivery.
- [ ] Tests: an effect with no broker claim at all is reported, not dropped.

---

## Part B — Provenance fidelity across the boundary

### Evidence

Verified by round-trip:

```
original task_id        : task-42
roundtrip task_id       : None
original data_resources : frozenset({'file:///secrets'})
roundtrip data_resources: frozenset()
covers_taint_resource('file:///secrets') after IPC: False
```

`effect_broker/executor_ipc.py:96-106` serializes 7 of `LabelException`'s 11
fields. `task_id` and `data_resources` are dropped and default to
`None`/`frozenset()` on deserialize (`:138`).

Both defaults are the _unsafe-safe_ choice in one direction and the _unsafe_
choice in the other:

- `data_resources=frozenset()` ⇒ clears no taint ⇒ a granted declass silently
  stops working across the process boundary;
- `task_id=None` ⇒ valid in any task ⇒ the exception widens beyond its intended
  scope.

So the same dropped field can cause either a false denial or a privilege
widening, depending on which field it is. Neither is detected, because no test
asserts survival.

Related inconsistency in the plan history: the retired `docs/PLANS.md` marked
"Verify `task_id` unchanged through IPC roundtrip" as completed in PLAN 1 §4,
while the superseded draft of the same plan left it unchecked. The completed
item verified `Effect.task_id` (which _is_ serialized) — not
`LabelException.task_id` (which is not).

### Design

**Round-trip is a property, tested exhaustively.** No field may be silently
defaulted.

```python
def assert_serializable(cls) -> None:
    """Fail at import if a security-relevant field is not in the codec."""
```

- Codec declared as explicit field lists; adding a dataclass field without
  updating the codec raises at import time.
- Missing field on decode ⇒ `ValueError`, never a default.
- Version tag in the payload so an old peer is rejected rather than silently
  misinterpreted.

### Tasks

- [x] Serialize all 11 `LabelException` fields.
- [x] Deserialize with no silent defaults; missing field ⇒ `ValueError`.
      (`_require_field()` distinguishes an absent key from an explicit `null`.)
- [ ] Add an import-time guard that fails when a field is unaccounted for.
- [ ] Add a payload version tag; reject mismatched versions.
- [x] Round-trip test per security-relevant field (`task_id`, `data_resources`,
      `additional_targets`, `etype`, `nonce`, `granted_by`, provenance
      `provenance_id`/`scope_hash`).
- [ ] Record in this plan which fields were previously claimed as verified, so
      the correction is auditable rather than silent.

**Scope boundary:** this part covers the `LabelException` codec only. The
_session_ codec has the same class of defect (a cleared record comes back
active, see PLAN 5 Part C / C2) and is fixed there. Both must land before
Part E can report false-denial counts that mean anything.

---

## Part C — Concurrency: reserve before executing

### Evidence

`broker.py:1263`, verbatim:

```
# Note: send_count is incremented AFTER successful apply_effect (in executor),
# not during gate. This ensures failed sends (SMTP server down) do
# not consume the budget. Gate only checks if count < max_sends (allow check).
```

The window between check and increment is the defect: N concurrent sends can all
observe `count < max` and all proceed.

`_task_locks: dict[TaskId, threading.Lock]` (`:363`) protects the nonce but is
thread-scoped. Across processes it provides nothing.

### Design

**Reserve atomically, release on failure.** Two-phase budget:

```
reserve_send(task) -> ticket | RateLimited     # atomic, before execution
commit(ticket)                                 # on success: ticket → consumed
release(ticket)                                # on failure: ticket → available
```

The reservation is a durable counter (file lock or the ledger), not an in-memory
int, so it holds across processes. A crashed holder's ticket is reclaimed by
lease expiry — creating `UNKNOWN` budget state rather than silently leaking or
silently refunding.

### Tasks

- [ ] Replace `session.send_count` int with an atomic ticket store.
- [ ] Reserve before `execute()`; release on `failed`/`denied`.
- [ ] Lease expiry for tickets from crashed processes.
- [ ] Make the store cross-process (file lock or ledger-backed).
- [ ] Tests: distinct concurrent nonces → both allowed (not collapsed).
- [ ] Tests: identical concurrent nonce → exactly one allowed.
- [ ] Tests: failed execution → budget not consumed.
- [ ] Tests: lost acknowledgement → `UNKNOWN`, not double-spend.
- [ ] Multiprocess variant of every test above.

---

## Part D — Faithful comparators

### Evidence

`baselines/mode_conventional_sandbox.py` is ~50 lines of string checks:
`_WRITABLE_ROOTS`, `_ALLOWED_HOSTS`, `_host_of()`. There is no seccomp, no
Landlock, no syscall. It cannot represent a conventional sandbox, so a comparison
against it measures nothing.

`baselines/mode_pact.py` states in its own docstring what it omits ("No content
hash binding", "No session taint") without implementing what PACT actually does —
so the ECAC advantage is asserted against a stub designed to lose.

### Design

**A comparator must implement the mechanism or be renamed.** Two acceptable
outcomes per baseline, no third:

1. **Implement it.** For the conventional sandbox: real `landlock` rules +
   real write-path confinement, measured on the same traces.
2. **Rename it.** `mode_conventional_sandbox.py` → `mode_path_allowlist.py`,
   documented as "path/host allowlist only; not a sandbox comparator".

Silently keeping the current name is the one option that must not survive,
because it makes every comparative number unsupported.

### Tasks

- [ ] Decide per baseline: implement or rename — record the decision per file.
- [ ] Implement a real broker+sandbox comparator (Landlock + path mediation).
- [ ] Rename stubs that cannot be made faithful.
- [ ] Re-run the comparative suite; publish numbers only for faithful comparators.
- [ ] Update `README.md`: remove "20/20"/superiority claims that rest on stubs.
- [ ] Document each comparator's mechanisms in a table, with source references.

---

## Part E — The diagnostic run

The measurement that must precede any feature work.

### Reported metrics

| Metric                    | Definition                                                    |
| ------------------------- | ------------------------------------------------------------- |
| **Unauthorized effects**  | occurrences with no authorizing record (from Part A)          |
| **Legitimate completion** | required benign operations that succeeded (e.g. M4)           |
| **False denials**         | legitimate operations blocked, by predicate                   |
| **UNKNOWN outcomes**      | `IN_FLIGHT` with no evidence, or ambiguous transport          |
| **Approvals**             | approval granted vs. used vs. expired unused                  |
| **Overhead**              | wall-clock and syscall count, ECAC vs. comparator             |
| **Trusted boundary**      | explicit list of every component trusted to report truthfully |

The **trusted boundary** section matters most: it states which code must be
correct for the other numbers to mean anything. Today that list would include the
shim (performs I/O and reports it), the broker store (observation source), and
the `__main__` aggregate (mediation inference) — which is exactly why the numbers
are currently unsupported.

### Tasks

- [x] Write `scripts/diagnostic_run.py` emitting the table above as JSON + text.
- [x] Report `mediation_evaluated=false` distinctly from `false`.
      (`diagnostic_report()["mediation"]` is a four-field block — `evaluated`,
      `complete`, `failures`, `note`. When the ledger check could not run,
      `complete` is `None` and the text form prints `NOT EVALUATED` with the
      reason that this is not the same as `False`. Pinned by
      `TestMediationIsThreeValued`, including the case where the check raises.)
- [x] Report the trusted boundary as an explicit, reviewed list.
      (`metrics.trusted_boundary()`, printed as section 7.)
- [x] Run on the fake-SMTP harness for CI reproducibility **and** once against a
      real MTA, recording both. The real half is now recorded:
      `tests/data/postfix-maillog.txt` is a log captured from a real Postfix
      3.7.11 instance (`scripts/capture_mta_log.sh` regenerates it), containing
      one honest single-recipient send and one with an undeclared BCC. Both are
      parsed by `effect_broker/mta_log.py` and pinned by `tests/test_mta_log.py`.
      **What this does not establish:** the oracle had no way to read an MTA log
      at all before this — `smtp_log` was filled in by hand from the handler that
      had just been written, so the "independent" observer was listening to the
      sender's own account of itself. That gap is closed, but the log is still
      not a trust boundary: a process that can write to `maillog` can forge
      entries. The claim it supports is narrower and real — the observations come
      from the MTA's own accounting rather than from the code being observed.
- [ ] Freeze feature work until this run is green and reviewed. **Not done** —
      and cannot be ticked from inside the repository: this is a process
      commitment, not a code change.

### Why only Part E is ticked here

Parts A–D have their own task lists above and most remain open. This plan is
unusual in that its _measurement_ arrived long before its _remediation_: the
scenario snapshot and diagnostic run exist and are honest about what they do not
measure, while occurrence identity (Part A), the boundary codec (Part B) and the
comparators (Part D) are only partly done. Reporting "Part E complete" must not
be read as "the evidence story is complete" — the diagnostic run is a tripwire
over six scenarios, and its own trusted-boundary section names what has to be
correct for the numbers to mean anything.

---

## Exit criteria

> IDs are the register keys in [REVIEW_REMEDIATION.md](REVIEW_REMEDIATION.md).

1. **P6-1** — Occurrence counts are distinguishable for all four scenarios in
   Part A.
2. **P6-2** — Every `LabelException` field survives round-trip, asserted per
   field.
3. **P6-3** — Concurrent-ticket tests pass in both thread and multiprocess
   modes.
4. **P6-4** — Every comparator either implements the named mechanism or is
   renamed.
5. **P6-5** — The diagnostic run reports all seven metrics, including the
   trusted boundary.
6. **P6-6** — No comparative claim in `README.md` references a stub comparator.

## Sequencing

```
PLAN 4 (trusted executor) ──┐
                            ├──> PLAN 6 Part E (diagnostic run) ──> contribution choice
PLAN 5 (enforced boundary) ─┘
```

Parts A–D of PLAN 6 can proceed in parallel with PLAN 4/5, but **Part E must run
after both**, because its UNKNOWN and unauthorized-effect counts are meaningless
until commit ordering and confinement are trustworthy.

## Risks

- **This plan says "we cannot yet show our claims hold".** That is the point: it
  converts an unsupported claim into a measurement. Expect the first diagnostic
  run to be unflattering.
- **Real-MTA observation** may be unavailable in some environments; the fallback
  must be `UNKNOWN`, not a weaker inference.
- **Comparator work is open-ended.** Bound it: implement only what the traces
  exercise, and rename the rest.
