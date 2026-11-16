# Review Remediation — Traceability Index

**Status:** Proposed
**Source:** external review, "1. Current issues and how to solve them"
**Plans:** [PLAN_4](PLAN_4_trusted_executor.md) · [PLAN_5](PLAN_5_enforced_boundary.md) · [PLAN_6](PLAN_6_evidence.md)

---

## Purpose

This file exists so that no review item can be quietly dropped. Every bullet of
the review maps to a plan, a part and at least one exit criterion. If a row is
added to the review later, it must get a row here before any code is written.

The earlier `docs/PLANS.md` was retired because it marked items COMPLETE that
the code did not implement. This index is the mechanism that prevents a repeat:
completion is claimed per exit criterion, and each criterion is a test or a grep,
not a checkbox.

---

## Item-by-item mapping

### Item 1 — Actual execution and authorization must be connected

| Review requirement                                             | Where                   | Exit criterion |
| -------------------------------------------------------------- | ----------------------- | -------------- |
| Shims perform real I/O after the model commit                  | PLAN 4, E1              | — (evidence)   |
| Define precisely when an effect commits                        | PLAN 4 §1 state machine | P4-1           |
| One trusted executor for authorize + execute + record          | PLAN 4 §2               | P4-2           |
| Record COMMITTED only from evidence of the protected operation | PLAN 4 §3               | P4-1           |
| Preserve UNKNOWN when the outcome is ambiguous                 | PLAN 4 §3               | P4-2, P4-3     |

### Item 2 — The access boundary remains incomplete

| Review requirement                                                      | Where                             | Exit criterion |
| ----------------------------------------------------------------------- | --------------------------------- | -------------- |
| Patching `os.open` does not confine arbitrary tool code                 | PLAN 5, A1–A2                     | P5-1           |
| Replace with an OS-enforced boundary (files, credentials, signing keys) | PLAN 5 Part A                     | P5-1, P5-2     |
| Correct the Landlock integration                                        | PLAN 5, A1                        | P5-1           |
| Verify that restrictions are active                                     | PLAN 5, `_selftest_confinement()` | P5-1           |
| Align documentation with mechanisms actually installed                  | PLAN 5, A5                        | P5-5           |

### Item 3 — Approvals must bind the complete operation

| Review requirement                                          | Where                             | Exit criterion |
| ----------------------------------------------------------- | --------------------------------- | -------------- |
| One unambiguous canonical request in `model.py`             | PLAN 5 Part B, `CanonicalRequest` | P5-3           |
| Contains task, operation, acting account, sender            | PLAN 5, B1 table                  | P5-9           |
| Complete recipients, exact content, attachment digests      | PLAN 5, B1/B4                     | P5-10          |
| Hash raw bytes consistently across processes                | PLAN 5, B3                        | P5-3           |
| `subject`/`body` concatenation permits encoding ambiguities | PLAN 5, B2                        | P5-4           |
| `shim_email.py` omits the actual body bytes                 | PLAN 5, B4                        | P5-10          |
| Executor transmits exactly the approved operation           | PLAN 5, Part B design             | P5-3           |

### Item 4 — Provenance and exceptions need stronger semantics

| Review requirement                                                       | Where                                  | Exit criterion |
| ------------------------------------------------------------------------ | -------------------------------------- | -------------- |
| Labels from trusted records                                              | PLAN 5, C1 + design                    | P5-6           |
| A valid provenance ID must not permit changing labels                    | PLAN 5, C1                             | P5-6           |
| …or substituting unrelated content                                       | PLAN 5 design (`content_hash`, `name`) | P5-6           |
| Explicitly define provenance-preserving transformations                  | PLAN 5, C3 + table                     | P5-8           |
| A confidentiality release must leave integrity active                    | PLAN 5, C4 (already true; pin it)      | P5-11          |
| `executor_ipc.py` preserve `LabelException.task_id` and `data_resources` | PLAN 6 Part B                          | P6-2           |
| Correct inconsistent taint-resource field names                          | PLAN 5, C2 (`cleared_by`)              | P5-7           |
| Round-trip tests for every security-relevant field                       | PLAN 6 Part B                          | P6-2           |

### Item 5 — The observer must distinguish actual occurrences

| Review requirement                                       | Where                           | Exit criterion |
| -------------------------------------------------------- | ------------------------------- | -------------- |
| Final file state cannot establish once/twice/transiently | PLAN 6, A                       | P6-1           |
| Recipient sets cannot establish recurrence               | PLAN 6, A                       | P6-1           |
| Record occurrence identity                               | PLAN 6, `Occurrence.effect_id`  | P6-1           |
| Record payload identity                                  | PLAN 6, `Occurrence.payload_id` | P6-1           |
| Bounded observation window                               | PLAN 6, `Occurrence.window`     | P6-1           |
| Include effects absent from the broker's claims          | PLAN 6, A tasks                 | P6-1           |
| SMTP probe checks supplied addresses only                | PLAN 6, A evidence              | P6-1           |
| Observe actual envelope transactions on acceptance       | PLAN 6, A design                | P6-1           |

### Item 6 — Concurrency and evaluation need repair

| Review requirement                                           | Where                | Exit criterion |
| ------------------------------------------------------------ | -------------------- | -------------- |
| Reserve tickets and send budgets atomically before execution | PLAN 6 Part C        | P6-3           |
| …including the multiprocess path                             | PLAN 6 Part C design | P6-3           |
| Test different concurrent nonces                             | PLAN 6 Part C tasks  | P6-3           |
| Test failed execution                                        | PLAN 6 Part C tasks  | P6-3           |
| Test acknowledgement loss                                    | PLAN 6 Part C tasks  | P6-3           |
| Replace named baseline stubs with faithful implementations   | PLAN 6 Part D        | P6-4           |
| Implement a real conventional broker-plus-sandbox comparator | PLAN 6 Part D        | P6-4           |
| Remove "denied ⇒ complete mediation" inference               | PLAN 4, E3           | P4-3           |

### Item 7 — Freeze features, run a diagnostic comparison

| Review requirement                                      | Where                    | Exit criterion   |
| ------------------------------------------------------- | ------------------------ | ---------------- |
| Keep feature expansion frozen                           | PLAN 6, A intro + Part E | P6-6             |
| Report actual unauthorized effects                      | PLAN 6, Part E table     | P6-5             |
| Report legitimate completion                            | PLAN 6, Part E table     | P6-5             |
| Report false denials                                    | PLAN 6, Part E table     | P6-5             |
| Report UNKNOWN outcomes                                 | PLAN 6, Part E table     | P6-5             |
| Report approvals                                        | PLAN 6, Part E table     | P6-5             |
| Report overhead                                         | PLAN 6, Part E table     | P6-5             |
| Report the complete trusted boundary                    | PLAN 6, Part E table     | P6-5             |
| Then choose the research contribution from the evidence | PLAN 6, Sequencing       | — (follows P6-5) |

---

## Exit criteria register

| ID    | Criterion                                                                             | Checked by       | Plan | Status                             |
| ----- | ------------------------------------------------------------------------------------- | ---------------- | ---- | ---------------------------------- |
| P4-1  | No path records `COMMITTED` without executor-produced evidence                        | grep + test      | 4    | **DONE**                           |
| P4-2  | `SIGKILL` between `IN_FLIGHT` and record ⇒ `UNKNOWN`                                  | test             | 4    | **DONE**                           |
| P4-3  | Zero `mediation_complete=not actual_allow` inferences; `mediation_evaluated` reported | grep             | 4    | DONE                               |
| P4-4  | Diagnostic reports all five outcomes                                                  | script output    | 4    | DONE                               |
| P5-1  | `_selftest_confinement()` proves denied paths fail with `EACCES`                      | test on Linux    | 5    | **DONE** on Linux (writes + reads) |
| P5-2  | `ECAC_REQUIRE_CONFINEMENT=1` + no Landlock ⇒ refuse to run                            | test             | 5    | **DONE**                           |
| P5-3  | `CanonicalRequest` round-trips byte-identically (non-UTF-8 attachment)                | test             | 5    | **DONE**                           |
| P5-4  | Zero ambiguous concatenations in the approval path                                    | grep + test      | 5    | **DONE**                           |
| P5-5  | README/SECURITY match installed mechanism, per platform                               | review           | 5    | **DONE**                           |
| P5-6  | Forged labels under a valid `prov_id` ⇒ untrusted                                     | test             | 5    | **DONE**                           |
| P5-7  | Declass survives `session_state_to_dict → dict_to_session`                            | test             | 5    | **DONE**                           |
| P5-8  | Transformation table exists; every row has a test                                     | review + test    | 5    | **DONE**                           |
| P5-9  | Approval for sender/acting-account A does not authorize B                             | test             | 5    | **DONE** (was falsely marked DONE) |
| P5-10 | Changed attachment blob changes `request_hash`                                        | test             | 5    | **DONE** (was falsely marked DONE) |
| P5-12 | The email approval binds the body actually transmitted                                | test             | 5    | **DONE** (was OPEN — see below)    |
| P5-11 | Declass leaves integrity active; empty `data_resources` clears nothing                | regression test  | 5    | **DONE**                           |
| P6-1  | Occurrence counts distinguishable in all four scenarios                               | test             | 6    | **DONE**                           |
| P6-2  | Every `LabelException` field survives round-trip                                      | test (per field) | 6    | **DONE**                           |
| P6-3  | Concurrent-ticket tests pass in thread and multiprocess modes                         | test             | 6    | **PARTIAL** — thread only          |
| P6-4  | Every comparator implements the named mechanism or is renamed                         | review           | 6    | **DONE**                           |
| P6-5  | Diagnostic reports all seven metrics incl. trusted boundary                           | script output    | 6    | **DONE**                           |
| P6-6  | No comparative claim in README references a stub comparator                           | grep             | 6    | **DONE**                           |

### Third audit: a criterion that had no row at all

P5-10 said a changed _attachment_ changes `request_hash`, and it is DONE. But
the same review item (PLAN 5 B4) also recorded that `shim_email.py` omits the
actual body bytes, and for that there was **no row**. So the register could be
fully green while every email approval bound `sha256("")`:

- `RealEmailShim.send()` put `subject` and `body_size` on the effect and no
  `body`; `_smtp_send()` transmitted a separately built `raw_msg`. With no body,
  `compute_content_hash()` returned the hash of the empty string for every send,
  so `content-hash-mismatch` in `gate()` was dead code for email. An approval
  granted for one message authorized any other — demonstrated end-to-end
  through the live shim before the fix.
- `body_size` is not a substitute: two bodies of equal length share it, so a
  check resting on it would pass the very case it was meant to catch.
- The existing tests did not see this because they build their `Effect` by hand
  _with_ `body` in the metadata. Only an effect taken from the shim shows the
  gap, so P5-12 is pinned by `tests/test_email_body_binding.py`, which runs the
  shim's own construction path.

Found alongside it, in the same path: the shim's metadata held a `frozenset`,
so every email commit in multi-process mode raised `TypeError` inside
`_sign_payload` — after the gate had authorized, and as a crash rather than a
denial, leaving no verdict in the journal. `effect_to_dict()` now normalizes
non-encodable values at the serialization boundary instead of relying on each
shim to remember.

### Baseline recorded before the executor rewrite

`docs/metrics_baseline_pre_executor_rewrite.json` is a snapshot of the
regression metrics taken with `scripts/metrics_snapshot.py`. It exists so the
executor rewrite can be checked for regressions:

```
uv run python scripts/metrics_snapshot.py --out after.json
uv run python scripts/metrics_snapshot.py --compare \
    docs/metrics_baseline_pre_executor_rewrite.json after.json
```

Exit 0 = no regression, 1 = regression, 2 = scenario set changed (the diff
would be meaningless, so it refuses).

Baseline at time of recording: 6 scenarios, defense rate 100%, 0 false
positives, 0 false negatives, TCB 2351 executable lines.

> **Correction.** This paragraph said "TCB 2163" while the artifact it
> describes (`docs/metrics_baseline_pre_executor_rewrite.json`) records
> `tcb_lines: 2351`. The recorded figure is the one the compare command reads,
> so the prose was the wrong number. Current tree measures 2175.

**TCB size is advisory, not a gate.** It was listed as lower-is-better, which
made every security fix read as a regression and deleting a module read as an
improvement — the wrong incentive to encode in CI. It is still printed in the
diff and labelled `advisory`; it just does not decide the exit code.

**The TCB figure changed definition, not just value.** It used to sum two files
while this repository's own architecture defined the trusted core as four, so
`executor.py` — the sole mutation path — was uncounted, and it counted
docstrings as code. The honest figure for that commit was 2351 executable
lines across `broker.py`, `model.py`, `executor.py` and `restricted_store.py`.
The current tree measures 2175.

**This is not Part E.** It deliberately omits unauthorized-effect counts,
UNKNOWN outcomes and the trusted boundary, because those are exactly the
numbers Part E exists to make trustworthy and cannot be measured before the
commit ordering and confinement work lands. The snapshot is a regression
tripwire, not a claim of protection.

### Landed so far

| Criterion           | Change                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Tests                                                                                                                                                          |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **P5-6**            | `model.py`: `is_trusted_provenance` now compares `confidentiality`/`integrity`; new `provenance_mismatch_reason()` names the diverging field                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `tests/test_review_remediation.py::TestProvenanceLabelBinding` (5)                                                                                             |
| **P5-7**            | `model.py`: `Session.restore_taint()`; `executor_ipc.py`: `dict_to_session` preserves `cleared_by`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `...::TestDeclassSurvivesIpc` (3)                                                                                                                              |
| **P6-2**            | `executor_ipc.py`: `label_exception_to_dict` / `dict_to_label_exception` / `_require_field`; full field set on the wire                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | `...::TestLabelExceptionCodec` (6)                                                                                                                             |
| **P5-11**           | Pinned only — behaviour was already correct (no code change)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `...::TestDeclassDoesNotClearIntegrity` (3)                                                                                                                    |
| **P5-8**            | New `effect_broker/provenance_transforms.py`: `PROVENANCE_TRANSFORMS` table + `propagated_labels()` join; documented in `ARCHITECTURE.md`, linked from `Data`'s docstring                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | `tests/test_provenance_transforms.py` (22)                                                                                                                     |
| _(baseline)_        | `scripts/metrics_snapshot.py` — regression tripwire with diff + scenario-set guard. Prerequisite for measuring the executor rewrite, **not** Part E                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `tests/test_metrics_snapshot.py` (15)                                                                                                                          |
| **P4-1 (partial)**  | `model.py`: `EffectState`, `ALLOWED_TRANSITIONS`, `EffectEvidence` (unbacked `committed` is unconstructible), `state_from_evidence()`; `PostAuthorizationFailure` replaces the "security event" mislabel at 3 shim sites                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | `tests/test_commit_ordering.py` (24)                                                                                                                           |
| **P4-2 (partial)**  | `ledger.py`: `record_dispatched()` / `was_dispatched()` / `DISPOSITION_UNKNOWN`; `verify()` now separates "dispatched, never observed" from "never dispatched". Markers written before I/O at all 3 sites                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | `test_commit_ordering.py::TestCrashBetweenDispatchAndRecord` (7), `test_shim_email.py::TestDispatchMarker` (1)                                                 |
| **P4-1 (complete)** | `ledger.py`: `verify()` returns `UnknownLedgerResult("committed_without_evidence")` when no evidence backs the claim, so an observation alone no longer reads as a commit. `model.py`: `Commit.store_is_external_state` distinguishes a store that _is_ the external state (simulated `FileShim`, plain `broker.commit()`) from one that only mirrors it (`shim_real`, `shim_email`). `executor.py`: `_record_store_evidence()` for the former, evidence from the IPC reply for the subprocess path. `ipc.py`: `record_evidence`/`evidence_for` on `LedgerBackend`, `LocalLedgerBackend`, `ProcessLedgerClient`, plus `RECORD_EVIDENCE`/`EVIDENCE_FOR` wire requests and `EffectEvidence` serialization | `tests/test_commit_ordering.py`, `test_ipc.py`, `test_ipc_executor_isolation.py`, `test_observer_*`, `test_periodic_audit.py`, `test_same_process_observer.py` |
| **P4-2 (complete)** | `tests/test_crash_harness.py`: a child process is really `SIGKILL`ed while parked between the IN_FLIGHT marker and the record; the recovered ledger reports `UNKNOWN`, not safe, and still distinguishes "dispatched" from "never started"                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `tests/test_crash_harness.py` (9)                                                                                                                              |
| **P4-3**            | `experiment.py`: `_mediation_verdict()` replaces 18 inferences; `mediation_complete` is now nullable with `mediation_evaluated` + `mediation_failures`, invariants enforced in `__post_init__`; `__main__.py` aggregate requires evaluated AND complete; same in `held_out_evaluation.py`                                                                                                                                                                                                                                                                                                                                                                                                               | `tests/test_mediation_evaluated.py` (14)                                                                                                                       |
| **P4-4**            | `ledger.py`: `OutcomeCounts`, `outcome_of()`, `outcome_counts()`, closed allow-lists for committing/failed/denying sources; `experiment.py`: `collect_outcome_counts()` (single execution, scoped registry) + `print_outcome_counts()`; both entry points print the tally and their caveats                                                                                                                                                                                                                                                                                                                                                                                                             | `tests/test_outcome_counts.py` (26)                                                                                                                            |

**Why P5-6 is safe for legitimate labelling.** Confidentiality is derived in
exactly one place from trusted OS state (`statx.derive_provenance`: statx bits →
permission bits → keyword → deny-most) and its integrity is always `USER` for
OS-derived content. The label recorded at read-commit time is therefore
authoritative; a caller that wants a different label must obtain a new committed
read under a different capability, not edit the field.

**What P4-1 bought.** The type is the load-bearing part:
`EffectEvidence(outcome="committed")` raises unless a transport response and at
least one _observed_ target are present, so an unbacked commit claim cannot be
constructed anywhere in the codebase. The second half is now wired as well:
`verify()` refuses `CONFIRMED_COMMITTED` when no evidence exists, and every path
that applies an effect records evidence — the executor for stores that _are_ the
external state, the IPC reply for the subprocess path, and the shims themselves
for real filesystem/SMTP I/O.

**Why `store_is_external_state` had to be a flag, not an assumption.** The two
shim families are opposites. In the simulated `FileShim`, `_do_write`/`_do_send`
are documented NO-OPs — `apply_effect()` _is_ the mutation, so the store's own
log entry is a genuine measurement. In `RealFileShim` the store only bookkeeps
and the bytes land later, after `commit()` returns. Writing store evidence for
the real shims produced this journal, caught by
`test_dispatch_precedes_evidence_in_the_file`:

```
['authorized', 'observed', 'evidence', 'dispatched', 'evidence']
```

`evidence` preceded `dispatched` — proof recorded before the operation it
proves, which is the exact defect this plan exists to remove. The flag defaults
to `True` (a plain `broker.commit()` mutates only the store) and the real shims
set it `False`.

**Why outcome classification uses an allow-list.** The first version of
`outcome_of()` classified by exclusion: anything that was not obviously a block
counted as a commit. That is the optimistic default, and it meant adding a new
observation source anywhere in the codebase would silently inflate the commit
count. Rewritten as three closed sets (`_COMMITTING_SOURCES`,
`_FAILED_SOURCES`, `_DENYING_SOURCES`) with `unknown` as the fallthrough, so an
unrecognised source is reported as unexplained instead of being promoted to
success. A mutation test confirms the sets are load-bearing.

The `total` check is the one that matters: the five buckets must account for
every effect the ledger heard of, including effects observed but never
authorized. An accounting that drops the unexplained ones would report a clean
suite by losing track of the failures.

**What the zeros mean.** `abandoned` is zero and cannot currently be otherwise:
capability expiry is caught by the gate as a denial, before authorization is
recorded, so nothing reaches AUTHORIZED-then-given-up. `unknown` is zero because
no scenario crashes mid-operation. Both are printed with their explanation
beside the number, because a bare 0 reads as "we looked and found none" when it
means "this cannot happen yet". A test pins the first claim so that adding such
a path forces the note to be revisited.

**Why "denied implies complete" was the worst inference in the suite.** It is
not merely wrong, it is _inverted_ in its effect: the more successfully the suite
blocked things, the more confidently it declared mediation complete, and the
scenario that would have exposed a hole — one where an effect escaped while
another was blocked — was exactly the one nobody checked for. At the T18
rate-limit site the field was hardcoded `True` with the comment "rate limiting
worked correctly", which is an assertion about a different mechanism entirely.

The fix makes the two claims separate fields. `mediation_complete` is `None`
until something asks the ledger, and `__post_init__` refuses to hold a verdict
without `mediation_evaluated` — so the old code now raises
`ValueError: ... this is the 'blocked implies complete' inference in disguise`
rather than quietly returning True. The aggregate in `__main__.py` counts
unevaluated results as neither pass nor fail and prints them by name.

The grep criterion from the plan is enforced as a test
(`test_no_mediation_complete_inferred_from_allow`), and it was verified by
reintroducing the inference and watching both that test and the `__post_init__`
invariant fire.

**What P4-2 bought.** The marker is written before the network/syscall at all
three I/O sites, and `verify()` distinguishes "dispatched, never observed"
(`DISPOSITION_UNKNOWN`) from "never dispatched" (`authorized_not_observed`). The
ordering is pinned by a test that fails if the marker is moved after the send
call — verified by mutating the shim and watching it go red.

The remaining half was the real thing P4-2 asks for: an actual `SIGKILL` between
the I/O and the record. `tests/test_crash_harness.py` now does this — it starts
a child, waits until it is parked past the in-flight marker, kills it, and
asserts the recovered ledger reports `UNKNOWN` rather than safe, still
distinguishing "dispatched" from "never started". In-process pytest could not
demonstrate this (a real kill takes the runner with it), so the crash lives in a
subprocess. This required the journal: the in-flight marker is journaled before
the I/O, so it survives the kill. Constructing the post-crash state is not the
same as surviving the crash, and only the harness does the latter.

**Why a dispatch marker cannot substitute for evidence.** The marker records
intent, and intent is free — any compromised shim can write one. It is therefore
never sufficient for `CONFIRMED_COMMITTED` (a test pins this); it only upgrades
an otherwise silent gap into a named, reportable UNKNOWN. Evidence of a commit
still requires a transport response and observed targets.

**Why a transport failure is not a security event.** An MTA timeout was raising
`EmailSecurityError`, the same class as a policy block. That conflated "you were
denied" with "the network was down", which taught operators to ignore the
category that should never be ignored, and left `auth > 0 / obs = 0` unreadable.
`PostAuthorizationFailure` is deliberately NOT a subclass of
`EmailSecurityError` (a test pins this), and its outcome is `failed` → `UNKNOWN`,
because a timed-out SMTP delivery may still have landed.

**Why P6-2 rejects absence rather than defaulting.** An absent key means the
producer did not consider the field; an explicit `null` means it deliberately
chose `None`. Conflating the two is precisely how `task_id` became "valid in any
task" and `data_resources` silently stopped clearing taint.

**Why the P5-8 table is derived, not asserted.** Every row follows from one
rule: a transformation preserves provenance iff its output is a deterministic
function of its inputs AND every output byte is attributable to an input byte.
`summarise`, `translate` and `model_generate` fail the second clause — their
output is _new content_, so a summary of CONFIDENTIAL data is CONFIDENTIAL
**and** UNTRUSTED. `concat` passes but needs the lattice join (confidentiality
MAX, integrity MIN) across all inputs, not the primary input's labels.
`encrypt`/`hash` pass: the datum is opaque but the label still travels, so
encryption is not declassification. `decode_lossy` (`errors="replace"`) fails —
this is the concrete defect at `model.py` vs `executor_subprocess.py` (PLAN 5,
B3). An unclassified transformation raises `KeyError` rather than defaulting to
`PRESERVED`.

---

## Contract change: an observation alone no longer means COMMITTED

**This changes test expectations, not just code.** Recording it here so the
change is auditable rather than silent — the same discipline the plan asks for
regarding the retired `PLANS.md`.

Sixteen tests wrote `record_authorization` + `record_observation` straight into
the ledger and asserted `CONFIRMED_COMMITTED`. That was the old contract:
"observed implies committed". P4-1 makes it wrong by construction — the point of
evidence is that the observation is not the commit. Those tests now record
evidence too, via a `commit_evidence()` helper in `tests/conftest.py`.

Two expectations were not merely updated but **inverted**, because their
premises contradicted the invariant:

| Test                                              | Old expectation                                        | Why it cannot stand                                                                                                                                                            |
| ------------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `test_verify_requires_correct_source_for_blocked` | non-BLOCKED source + empty obs ⇒ `CONFIRMED_COMMITTED` | `EffectEvidence(outcome="committed")` cannot be constructed without observed targets, so no evidence can back this claim. Now asserts "not `CONFIRMED_BLOCKED`, and `UNKNOWN`" |
| `test_observation_after_dispatch_still_commits`   | dispatch + observation ⇒ `CONFIRMED_COMMITTED`         | Dispatch marks intent, and intent is free; it never was sufficient for a commit. Now also requires evidence                                                                    |

**The honest caveat:** these two now pass for a weaker reason than their names
suggest, and a reviewer should treat them as "the path refuses to over-claim"
rather than "the happy path is proven". The stronger assertion — that a real I/O
commit produces evidence — lives in `test_io_evidence.py` and
`test_crash_harness.py`.

---

## Second audit: the register was wrong

Re-checking every "DONE" row against the running code (not against the
document) found three criteria that were marked **DONE** without the property
holding, and one row whose stated reason was narrower than the actual hole. This is the same failure mode that retired `PLANS.md`, so it is
recorded here rather than quietly corrected.

| Criterion | Register said | Reality                                                                                                                                                                                                                                                                                 |
| --------- | ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P5-1      | OPEN (honest) | The row was correctly OPEN, but the reason was understated. `_landlock_handled_access()` omitted `READ_FILE`, so **no read was confined**: `~/.ssh/id_rsa` and `~/.aws/credentials` opened fine under the real syscall even with Landlock active. Writes were confined; reads were not. |
| P5-9      | DONE          | `request_hash` was defined on `ApprovedRequest` but **never populated** by `grant_approval()` and **never checked** by the gate. An approval granted for `alice@corp.com` authorized a send as `attacker@evil.com`.                                                                     |
| P5-10     | DONE          | Same cause: a swapped attachment blob with identical subject/body was allowed.                                                                                                                                                                                                          |
| P6-3      | DONE          | `send_count` was still a plain int incremented _after_ a successful apply, and the gate only read it. Five concurrent sends with `max_sends=1` were **all allowed**.                                                                                                                    |

All four are now fixed and pinned by tests that were **mutation-verified** —
each was run against the pre-fix code and observed to fail:

- `tests/test_approval_request_binding.py` (6 tests) — with the `request_hash`
  check disabled, 3 tests fail. The remaining 3 pin the legitimate paths, so the
  fix cannot be "deny everything".
- `tests/test_send_budget_tickets.py` (5 tests) — with the reservation disabled,
  the concurrency test reports `budget of 1 admitted 5 sends`.
- `tests/test_confinement_honesty.py::TestReadConfinement` (3 tests, Linux) —
  removing the `READ_FILE` bit makes all three read tests and both write tests
  fail.

**What the send fix is and is not.** `Session` now exposes
`reserve_send/commit_send/release_send` over a lock, and the gate reserves a
ticket atomically (in the same locked section as the nonce). The ticket counts
against the budget, so a second concurrent sender sees it in flight. A blocked
gate releases the ticket; a failed apply does too, so a transport failure still
does not spend budget. **This is cross-thread, not cross-process:** `_send_tickets`
and the lock live in `Session`, which is per-process, so two executor processes
sharing a session are not yet covered. That is the remaining half of P6-3, and
it is why the row says PARTIAL.

---

## What is still open, and why part of it cannot close on macOS

PLAN 4 is complete. PLAN 5 and PLAN 6 are **not**, and one blocker is
environmental rather than effort.

**P5-1 / P5-2 (Landlock): reads are now confined too.**
`_selftest_confinement()` and `ECAC_REQUIRE_CONFINEMENT` are implemented
(`executor_subprocess.py:473`, `:599`). This audit re-ran them on Linux
(Debian slim, kernel 6.x) rather than trusting the comments:

- **Proven, on Linux:** the ruleset installs, `restrict_self` succeeds, the
  status string reports `landlock`, and `ECAC_REQUIRE_CONFINEMENT=1` makes the
  executor refuse to run with no kernel confinement.
- **The hole this audit found and closed:** `_landlock_handled_access()` did not
  include `READ_FILE`, so the kernel confined writes but **not reads**.
  `~/.ssh/id_rsa`, `~/.aws/credentials` and a signing key under `/tmp` all
  opened fine through the real syscall. So did `open("/etc/passwd")` via
  `builtins.open`, which the `os.open` patch never sees. `READ_FILE` is now in
  the handled mask, with `_LANDLOCK_READ_DIRS` re-opening `/usr`, `/lib`,
  `/etc`, `/dev`, `/proc`, `/sys` for read+execute only — deliberately **not**
  `~`. `ECAC_LANDLOCK_READ_ROOTS` adds deployment-specific data roots.
- **Two narrow exceptions, both required and both auditable:** the _working
  directory_ (a workload must read its own inputs) and `ECAC_IPC_KEY_DIR` (the
  executor must read the HMAC key it verifies IPC messages with; that directory
  holds one file). Neither of them opens `~`.
- **The trap this exposed:** `/etc/shadow` returns `EACCES` — but because the
  non-root test user cannot read it _by ordinary permissions_, not because
  Landlock blocked it. Treating that as proof of confinement is exactly the
  false positive `_selftest_confinement()` must avoid. The selftest now probes
  **both** directions for reads too: a legitimate read under a permitted root
  must succeed, and a canary under `$HOME` must fail with `EACCES`. The canary is
  planted _before_ the ruleset applies, because afterwards `$HOME` is unwritable
  — without that, the probe had nothing to test and reported "unconfined" on
  every legitimate deployment.
- **Mutation-verified on Linux:** removing the `READ_FILE` bit makes
  `test_read_file_is_in_the_handled_mask` and both write tests fail (26 pass
  with it, 3 fail without).

**Caveat, stated because it matters:** any path under a _write_ root is
readable by design, so a credential file that a deployment keeps inside
`/tmp/ecac-sandbox` remains readable. Keep secrets outside the sandbox root.
Unlike the write roots, `~` stays unreadable on purpose: a workload whose real
inputs live under a home directory must name them in `ECAC_LANDLOCK_READ_ROOTS`.

**P5-3 / P5-4 / P5-9 / P5-10 (canonical request).** `CanonicalRequest` exists
(`model.py:703`) with length-prefixed `canonical_bytes()`, a single `sha256_raw()`
helper, and a non-UTF-8 round-trip test. P5-9/P5-10 were the gap: the object was
built and tested but the gate never consulted it. That is fixed above and pinned
by gate-level tests.

**P6-1 (occurrence identity) — type exists, no producer.** `Occurrence` and
`count_occurrences()` exist (`oracle.py:46`), but `Occurrence(` is constructed
**only in `tests/test_occurrences.py`**. `IndependentOracle.verify_write()` still
returns a boolean from `os.path.exists`, and `verify_send()` still collapses the
log into a set. So the observer cannot yet tell one write from two, and the
diagnostic run does not count occurrences. This remains the largest item.

**P6-3 (ticket reservation).** Thread-scoped reservation now exists (see above):
the gate reserves a ticket that counts against the budget. Still missing: a
cross-process store and a lease for a dead holder's ticket. `send_count` is no
longer the whole story but remains a plain int.

**P6-4 (comparators).** Resolved by renaming, not by implementing:
`mode_conventional_sandbox.py` is now `mode_path_allowlist.py` and states it is a
path/host allowlist, not a sandbox. `COMPARATOR_MECHANISMS` declares each
comparator's enforced and omitted mechanisms. There is still **no faithful
conventional-sandbox comparator** — that needs a real Landlock/seatbelt profile.
The row is DONE because the false name is gone, not because the comparator exists.
