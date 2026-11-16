# PLAN 4 — Trusted Executor: Commit Ordering & Outcome Evidence

**Status:** Proposed
**Priority:** HIGH (blocks any claim of "execution integrity")
**Supersedes:** PLAN 1 §1 (marked COMPLETE, but the gap it describes is still present)

---

## Why this plan exists

PLAN 1 §1 declared the ledger fix complete. The ledger itself is fine. The
problem is one layer below it: **the shim performs real I/O after the broker has
already committed**, so the ledger records authorization for effects that never
happened, and cannot distinguish "committed" from "attempted".

Trigger for this plan: external review, items 1, 5 and 6.

---

## Evidence (verified in code, not inferred)

### E1 — Commit precedes the real operation

`effect_broker/shim_email.py`:

```
:437   allow, evidence = self.broker.executor.execute(commit)   # ledger write
:466   if not allow: raise ...
:470   delivered = self._smtp_send(...)                        # real I/O AFTER
:478   raise EmailSecurityError("SMTP delivery failed after ALLOW")
```

`effect_broker/shim_real.py` has the same shape twice — the IPC branch
(`:690`) and the same-process branch (`:717`).

Consequences:

- The real operation can fail _after_ the broker recorded authorization.
  The ledger then has `auth > 0, obs = 0` → `UNKNOWN`. Correct per the
  ledger's own invariant, but the shim raised it as a _"security event"_,
  which mislabels an ordinary SMTP failure.
- There is no point in the code where "this effect definitely happened"
  is established from evidence. `COMMITTED` is never recorded from
  observation of the protected operation — only from the broker's own
  decision.

### E2 — The observer cannot distinguish occurrence counts

`effect_broker/oracle.py`:

```
:36   observed: bool      # in OracleVerdict — boolean, no count
:67   exists = os.path.exists(target_path)   # write: existence only
:107  delivered = {rcpt for rcpt, _data in self.smtp_log}  # set, collapses repeats
```

- one write vs. two identical writes → indistinguishable;
- transient write (`write` → `delete`) → `file-absent` → reads as "never happened";
- repeated send to the same recipient → collapsed by set semantics;
- no observation window, so a late effect cannot be attributed.

### E3 — "Denied ⇒ complete mediation" is inferred, not verified

`effect_broker/experiment.py`, 12+ sites:

```
:1016  mediation_complete=not actual_allow
:1046  mediation_complete=not actual_allow_h2
:1075  mediation_complete=not actual_allow_h3
:1104  mediation_complete=not actual_allow_t9    # comment: "blocked = safe"
:986   mediation_complete=m5_replay_blocked
:953   mediation_complete=m4_passed and len(...) == 0   # only site that calls it
```

`verify_complete_mediation()` returns a list of violations (empty = complete).
Most sites never call it and substitute "the effect was blocked" as proof that
mediation is complete. Those are different propositions: a blocked effect says
nothing about whether some _other_ effect escaped unmediated.

`effect_broker/__main__.py:66` then aggregates:

```
all_passed = all(r.mediation_complete for r in results.values())
```

so the false inference propagates to the top-level exit status.

---

## Design

### 1. Explicit effect lifecycle

Replace the implicit two-step (gate → apply) with a recorded state machine:

```
PREPARED ──gate──> AUTHORIZED ──dispatch──> IN_FLIGHT ──evidence──> COMMITTED
   │                    │                        │
   └──blocked──> DENIED └──expired──> ABANDONED  └──ambiguous──> UNKNOWN
```

Rules:

- `COMMITTED` may be recorded **only** from evidence produced by the executor
  that performed the protected operation — never from the gate decision.
- `IN_FLIGHT` persisted _before_ the syscall/network call, so a crash between
  I/O and bookkeeping yields `UNKNOWN`, never a silent `COMMITTED`.
- `UNKNOWN` is a first-class, reportable outcome, not an error path.

### 2. One trusted executor for authorize + execute + record

Today authorization is split across `broker.gate()`, `executor.execute()`, the
shim, and the subprocess. Consolidate:

| Responsibility             | Today                     | After                   |
| -------------------------- | ------------------------- | ----------------------- |
| Decide allow/deny          | `broker.gate()`           | unchanged               |
| Perform the real operation | shim (`smtp`, `open`)     | executor only           |
| Produce outcome evidence   | shim `op_log` (in-memory) | executor, signed record |
| Record verdict             | shim / caller             | executor, single writer |

The shim keeps building the _request_; it loses the ability to perform I/O and
to append its own claims.

### 3. Evidence, not assertion

Each terminal record carries:

```python
@dataclass(frozen=True)
class EffectEvidence:
    effect_id: str          # occurrence identity (see PLAN 6)
    outcome: Literal["committed", "failed", "unknown", "denied"]
    observed_bytes: int | None      # how much actually left/landed
    observed_targets: frozenset[str] | None  # from the transport, not the request
    transport_response: str | None  # SMTP 250 / errno / fsync result
    source: str             # "smtp-envelope" | "fs-stat" | ...
    window: tuple[float, float]     # observation window
```

`outcome="committed"` requires a non-`None` transport response and at least one
observed target. Absent both → `unknown`.

### 4. Fix the "denied = safe" inference

Every `mediation_complete=` site must be the result of an actual
`verify_complete_mediation()` call. Where the suite merely asserts a block, the
field is set to `None` and the aggregate in `__main__.py` treats `None` as
"not evaluated" rather than "passed".

```python
# after
failures = shim.verify_complete_mediation()
results[name] = ExperimentResult(
    ...,
    mediation_complete=True if not failures else False,
    mediation_evaluated=True,
    mediation_failures=tuple(failures),
)
```

`__main__.py`:

```
all_passed = all(
    r.mediation_evaluated and r.mediation_complete for r in results.values()
)
```

---

## Tasks

- [x] Define `EffectEvidence` and `EffectState` in `model.py`; add to `ledger.py`.
      (model.py: `EffectState`, `ALLOWED_TRANSITIONS`, `EffectEvidence`,
      `state_from_evidence()`. The ledger hookup is still pending.)
- [x] Persist `IN_FLIGHT` before any syscall/network call.
      (ledger.record_dispatched(); called at all three I/O sites —
      shim_email SMTP DATA, shim_real IPC branch, shim_real same-process branch.)
- [ ] Move `_smtp_send` / `open()` out of the shims into the executor.
      (Examined 2026-08: NOT a free refactor, so not done. The shim's post-ALLOW
      `open()` is redundant with `commit()` in multi-process mode — `APPLY_COMMIT`
      already performs the write in B — but in same-process mode it is the only
      write. Moving it changes where a crash lands relative to the dispatch
      marker, which is the ordering `test_commit_ordering.py` pins. Deferred
      rather than attempted blind.)
- [ ] Shims emit a `Request`; executor performs and records.
      (Blocked on the above; the same same-process/multi-process split decides
      whether a `Request` has an executor to reach.)
- [x] Outcome counting must not contradict the verdict.
      (`outcome_of()` bucketed an `executor.apply` observation as `committed`
      while `verify()` called the same effect `committed_without_evidence` —
      `executor.apply` is recorded BEFORE a real write reaches the filesystem, so
      a crash in between scored as a commit in the metrics and unknown in the
      audit. `outcome_of()` now defers to `verify()`. Caught by
      `test_outcome_counts.py::test_outcome_of_never_disagrees_with_verify`.)
- [x] Settle a crash-torn write from outside the writer.
      (`oracle.reconcile_unknowns()`: a write that landed and then lost its
      process stays `UNKNOWN` forever because nothing in the write path returns
      to fill the gap. The oracle now checks the filesystem and records evidence
      with `source="oracle.reconcile"`, leaving `authorized_not_observed` and
      absent/non-file targets untouched. `ledger.target_for()` returns None on
      ambiguity instead of picking a directory — the first version of it settled
      an unknown against the parent dir, which always exists.)
- [x] Add `verdict_from_evidence()` in `ledger.py`: no evidence ⇒ `UNKNOWN`.
      (Landed as `verify()` distinguishing `DISPOSITION_UNKNOWN` from
      `authorized_not_observed`, plus `state_from_evidence()` in model.py.)
- [x] Replace all 12+ `mediation_complete=` inferences with real calls.
      (18 sites; `_mediation_verdict()` helper. Includes the `mediation_complete=True`
      at the T18 rate-limit site, which was the purest assertion of the lot.)
- [x] Add `mediation_evaluated` to `ExperimentResult`; update `__main__.py`.
      (`mediation_complete: bool | None`, `mediation_evaluated`, `mediation_failures`;
      `__post_init__` rejects either field without the other. Aggregate requires
      evaluated AND complete, and reports unevaluated separately. Same treatment
      in held_out_evaluation.py.)
- [x] Stop labelling post-`ALLOW` transport failures as "security event";
      classify as `failed` outcome with the transport error.
      (`PostAuthorizationFailure` in shim_email.py, used at all three sites
      including the two in shim_real.py.)
- [x] Tests: crash between I/O and record ⇒ `UNKNOWN`
      (`test_commit_ordering.py::TestCrashBetweenDispatchAndRecord`, 7 tests,
      plus `test_shim_email.py::TestDispatchMarker` pinning the ORDERING).
- [x] Tests: transport failure ⇒ `failed`, ledger shows `UNKNOWN`, not `COMMITTED`.
      (`test_shim_email.py::TestEmailEvidence`, 3 tests. Classification is
      `PostAuthorizationFailure`, not a security event.)
- [ ] Tests: `mediation_complete` is `None` when unrelated to a block.

## Exit criteria

> IDs are the register keys in [REVIEW_REMEDIATION.md](REVIEW_REMEDIATION.md).

1. **P4-1** — No code path records `COMMITTED` without executor-produced
   evidence.
2. **P4-2** — A forced `SIGKILL` between `IN_FLIGHT` and the record produces
   `UNKNOWN`.
3. **P4-3** — Grep proves zero `mediation_complete=not actual_allow` style
   inferences, and `mediation_evaluated` is reported separately.
4. **P4-4** — The diagnostic run reports counts for all five outcomes
   (`committed`, `failed`, `unknown`, `denied`, `abandoned`).

   _Status:_ met. `ledger.outcome_counts()` + `experiment.collect_outcome_counts()`;
   printed by both entry points. Two caveats are printed beside the numbers
   rather than left implicit: `abandoned` has no producer yet (capability expiry
   is denied at the gate, before authorization), and `unknown` is zero because
   the suite has no mid-operation crashes. A bare zero for either would read as
   "we checked and found none".

## Non-goals

- Concurrency/ticket reservation → **PLAN 6**.
- Occurrence identity and observation windows → **PLAN 6** (this plan defines
  the fields, PLAN 6 makes the observer able to fill them).
- OS-level confinement → **PLAN 5**.
- Label semantics and codec fidelity → **PLAN 5 Part C / PLAN 6 Part B**.

## Dependencies

False-denial accounting (exit criterion 4) is only meaningful once PLAN 5 Part C
lands: a declass that is dropped by the session codec currently reappears as an
active taint in the executor subprocess, so a legitimate operation is denied for
a reason that has nothing to do with policy. Until then, the `denied` count
mixes policy denials with codec-induced ones. Run Part E after PLAN 5 Part C.

## Risks

- **Behaviour change:** effects that previously reported "blocked" on transport
  failure now report `failed` + `UNKNOWN`. Some existing tests encode the old
  behaviour and will need updating, not merely fixing.
- **Consolidating I/O into the executor** touches every shim; expect the diff to
  be wide even though each change is mechanical.
