# Response to the reviewer: P1–P6

This document answers the six issues in the review, point by point, against the
code in this tree. For each issue: **what the reviewer asked**, **what the code
now does**, **where it lives**, and **what remains open**. Nothing below is
claimed that is not implemented; the open items are stated as open.

Measured on macOS, Python 3.12:

```
pytest tests/            →  950 passed, 14 skipped (964 collected, 75 files)
mypy effect_broker/      →  clean, 30 source files
ruff check .             →  clean
held_out_evaluation      →  8/8 (100%)
diagnostic_report()      →  see §7
```

The 14 skips are the Landlock tests, which execute in CI on Ubuntu with
`ECAC_REQUIRE_CONFINEMENT=1`.

---

## P1 — Execution and authorization must be connected

**Asked.** Real I/O must not happen after a model commit has already succeeded.
Define when an effect commits; make one trusted executor own authorization,
execution and outcome recording; record COMMITTED only from evidence of the
actual protected operation; keep UNKNOWN when the outcome is ambiguous.

**Done.**

- **One executor, one mutation point.** Every effect — tool/shim call or direct
  `broker.commit()` — goes through
  `IsolatedExecutor.execute()` / `SubprocessExecutor.execute()`. Both call
  `broker._apply_effect()`, and `apply_effect()` is the only method in the
  codebase that reaches external state (`effect_broker/executor.py`).
- **Commit is defined by observation, not by authorization.** The ledger
  (`effect_broker/ledger.py`) records _authorization_ (from `gate`) and
  _observation_ (from `apply_effect` / the subprocess reply) as separate
  events. `CONFIRMED_COMMITTED` requires evidence (`record_evidence` /
  `evidence_for`), not merely a passed gate. An authorization with no
  observation resolves to `UNKNOWN`, and `UNKNOWN` is never reported as safe.
- **Evidence sourced from the operation itself.** `_record_store_evidence()`
  writes an `EffectEvidence` only from what the shim/subprocess actually
  measured (observed targets, transport response). `tests/conftest.py`
  exposes `commit_evidence()` so tests record evidence instead of asserting a
  commit from an observation alone.
- **Failed apply is not a commit.** If `apply_effect()` returns `False`, the
  executor records `executor.apply:FAILED`, releases the send budget, and does
  not record `CONFIRMED_COMMITTED` (`executor.py`, else-branch).

**Where.** `executor.py`, `executor_subprocess.py`, `ledger.py`, `model.py`
(`EffectEvidence`).

**Open.** In same-process mode a direct store mutation bypasses the executor;
the ledger correctly answers `UNKNOWN`, but it cannot _prevent_ the write. That
is the documented same-process limitation, closed only by process isolation.

---

## P2 — The access boundary remains incomplete

**Asked.** `os.open` patching plus import blocking does not confine arbitrary
tool code. Replace the assumptions with an OS-enforced boundary, correct the
Landlock integration, verify restrictions are active, and align the docs with
what is actually installed.

**Done.**

- **Landlock is verified, not assumed.** `_apply_landlock_sandbox()` applies a
  ruleset and then `_selftest_confinement()` _observes_ a denied write outside
  the allowed roots. The claim is only made after that observation succeeds
  (`executor_subprocess.py`). `_get_confinement_status()` reports which
  mechanism is actually active.
- **Absence is loud.** `ECAC_REQUIRE_CONFINEMENT=1` turns a missing boundary
  into a refusal to start rather than a silent downgrade.
- **A real OS comparator exists.** `effect_broker/baselines/mode_os_sandbox.py`
  applies Landlock (Linux) or a seatbelt profile (macOS) and lets the kernel
  decide the verdict — the comparison is no longer between string matching and
  a claim.
- **Docs corrected.** The false "Layer 3b — Seccomp BPF" claim (which blocked
  socket/connect/execve and never existed) was removed from
  `executor.py` and `executor_subprocess.py`, and the isolation scope now
  states plainly that `socket`/`smtplib`/`imaplib` stay importable and that
  there is **no syscall filtering**.

**Where.** `executor_subprocess.py` (`_apply_landlock_sandbox`,
`_selftest_confinement`, `_get_confinement_status`), `baselines/mode_os_sandbox.py`.

**Open.** On macOS with no `sandbox-exec`, and outside Linux, the Python-level
wrappers remain hygiene, not confinement; the code says so. A compromised
subprocess can still open a socket to any host.

---

## P3 — Approvals must bind the complete operation

**Asked.** One unambiguous canonical request (task, operation, acting account,
sender, complete recipients, exact content, attachment digests); hash raw bytes
consistently across processes; fix the subject/body concatenation ambiguity;
the live email effect must include the actual body bytes; the executor must
transmit exactly what was approved.

**Done.**

- **One canonical request.** `CanonicalRequest` (`model.py`) carries version,
  operation, `task_id`, `acting_account`, `sender`, sorted complete
  `recipients` (primary + CC + BCC), `target`, `resource_digests` and
  `attachments` (name, sha256hex). The binding hash is over
  `canonical_bytes()`.
- **Separator ambiguity removed.** `canonical_bytes()` length-prefixes every
  field, so `subject='a|b', body='c'` and `subject='a', body='b|c'` no longer
  collide.
- **One hashing helper.** `sha256_raw()` is the single hashing path;
  `errors="replace"` decoding was removed, so a non-UTF-8 attachment hashes
  identically on both sides of the IPC boundary.
- **The transmitted operation is the approved one.** `compute_content_hash()`
  hashes the message body (the bytes that go on the wire) for `send` and the
  raw content (or base64-decoded bytes) for `write`; the subprocess recomputes
  the same hash before applying and blocks on mismatch.

**Where.** `model.py` (`CanonicalRequest`, `sha256_raw`,
`Effect.compute_content_hash`), `executor.py` (`_verify_content_binding`),
`executor_subprocess.py` (`_verify_content_binding`).

**Open.** Attachment digests are bound when present; there is no test asserting
every attachment field round-trips through the live SMTP shim.

---

## P4 — Provenance and exceptions need stronger semantics

**Asked.** Labels must come from trusted records; a valid provenance ID must
not permit relabelling or substituting unrelated content; define which
transformations preserve provenance; a confidentiality release must leave
integrity checks active; preserve `LabelException.task_id` and
`data_resources` across IPC; fix inconsistent taint-resource field names; add
round-trip tests for every security-relevant field.

**Done.**

- **Labels from trusted records.** `store.resolve()` supplies resource labels;
  effect provenance is checked against them, not accepted from the tool.
- **Round-trip preserves security fields.** `executor_ipc.py` serialises
  `LabelException` with `task_id` and `data_resources`; the comment at the
  serialisation site records why dropping `task_id` would widen an exception to
  "valid in any task" and why dropping `data_resources` would stop clearing
  taint (`executor_ipc.py:75`, `:97`).
- **Declass is separate from endorse.** A declass lowers confidentiality via
  `LabelException`; integrity is evaluated by its own branch, so releasing
  confidentiality does not disable the integrity check.
- **Round-trip tests.** `tests/test_ipc.py` and `tests/test_ipc_evidence.py`
  (serialisation over the IPC boundary), `tests/test_review_remediation.py`
  (`LabelException` `task_id` / `data_resources` survival),
  `tests/test_provenance_transforms.py`, `tests/test_flow_declass.py`.

**Where.** `model.py` (`LabelException`, `Effect.compute_content_hash`),
`executor_ipc.py`, `broker.py` (`data_resources` plumbing at `:746`, `:769`).

**Open.** "Which transformations preserve provenance" is documented per
transformation in `mode_chaincaps.py` and the provenance-transforms tests; it
is not stated as a single closed lattice table.

---

## P5 — The observer must distinguish actual occurrences

**Asked.** Final file state and recipient sets cannot show whether an operation
happened once, twice, or transiently. Record occurrence identity, payload
identity and a bounded observation window, including effects absent from the
broker's claims. The SMTP probe checks supplied addresses; it does not discover
hidden recipients — observe actual envelope transactions.

**Done.**

- **Occurrences, not states.** `oracle.py` models `Occurrence` with a
  `payload_id` (digest of what was transmitted) and treats two identical writes
  as _two_ occurrences with the same payload id, rather than collapsing them
  (`oracle.py:69`, `:74`, `:94`).
- **Bounded window.** Evidence carries a `window` (start, end); an observation
  outside the authorized window is not attributed to the commit.
- **Envelope-level email observation.** `mta_log.py` records the SMTP
  _envelope_ transaction (`source="smtp-envelope"`), not just the addresses the
  broker already believed in — so a hidden recipient appears in the log.
- **Effects absent from claims are visible.** The ledger lists authorized
  effects with no observation as `UNKNOWN`, which is how a bypass surfaces.

**Where.** `oracle.py`, `mta_log.py`, `ledger.py`, `model.py` (`EffectEvidence`).

**Open.** Envelope observation depends on the configured MTA/log path; against
a real relay that does not expose transactions, discovery degrades to the
supplied-address probe.

---

## P6 — Concurrency, evaluation, and the mediation inference

**Asked.** Reserve execution tickets and send budgets atomically _before_
execution, including the multiprocess path. Test different concurrent nonces,
failed execution and acknowledgement loss. Replace the named baseline stubs
with faithful implementations and add a real conventional broker-plus-sandbox
comparator. Remove the evaluator's inference that a denied request proves
complete mediation.

**Done.**

- **Atomic budget reservation.** `gate()` reserves the send ticket and the
  Fresh nonce under a per-task lock before execution
  (`broker.py:1687–1700`); in multi-process mode the subprocess performs the
  same check and reservation inside `APPLY_COMMIT` (`executor.py:548`,
  `reserve_nonce=True`), so the broker does not pre-reserve a nonce the
  subprocess would then see as replayed.
- **Concurrency tests.** `tests/test_concurrent_replay.py`,
  `tests/test_concurrent_subprocess.py`, `tests/test_send_budget_tickets.py`.
- **Comparators implement their named mechanism.** Every one of the nine
  baselines denies for the reason its docstring names; the numbers in
  `VERIFICATION.md` §"Comparison results" were re-measured. `PathAllowlist` was
  renamed away from `mode_conventional_sandbox.py` because it compared strings
  while claiming a sandbox, and `mode_os_sandbox.py` now supplies the real
  kernel-enforced one.
- **The "denied ⇒ complete mediation" inference is gone.**
  `diagnostic_report()` explicitly clears `_SCENARIO_BROKERS`, asks each broker
  the mediation question directly, and the comment names the removed mistake:
  _"Inferring it from the block counts instead is the 'denied implies complete'
  mistake this repository removed elsewhere."_ (`metrics.py`).

**Where.** `broker.py`, `executor.py`, `metrics.py`, `baselines/`.

**Open.** `PACT`'s score is dominated by grant coverage: all 14 of its blocks
report `no capability for (etype, target)`, i.e. they come from the fixture
grants, not from a check above coverage. This is stated in
`VERIFICATION.md` rather than hidden.

---

## 7 — The diagnostic comparison the review asked for

`python -m effect_broker.metrics` reports exactly the seven quantities
requested. Measured now, on the labeled scenario set:

| Quantity                   | Value                                           |
| -------------------------- | ----------------------------------------------- |
| Unauthorized effects       | **0**                                           |
| Legitimate completion      | **2 / 2**                                       |
| False denials              | **0**                                           |
| UNKNOWN outcomes           | **0**                                           |
| Approvals                  | granted 7, used 3, expired-unused 0             |
| Overhead (p50 / p95 / p99) | 0.032 / 0.052 / 0.054 ms                        |
| Complete mediation         | `evaluated: True, complete: True, failures: []` |

The trusted boundary is printed in full rather than summarised:

```
effect_broker/shim_real.py         — performs real I/O and reports it
effect_broker/broker.py            — the store is the observation source
effect_broker/executor_subprocess.py — applies effects, reports observed targets
effect_broker/oracle.py            — derives verdicts from external sources
effect_broker/metrics.py           — labels scenarios attack/legitimate
```

TCB: 2175 executable lines (`broker.py` 1025, `model.py` 595,
`executor.py` 285, `restricted_store.py` 270).

**Scope limit, stated in the tool's own output:** these are regression metrics
on supplied scenarios, not a causal estimate against adaptive or live
attackers. Six scenarios is a smoke test, not an evaluation.

---

## Summary table

| Issue                          | Closed by code                                                   | Remaining gap                                             |
| ------------------------------ | ---------------------------------------------------------------- | --------------------------------------------------------- |
| P1 execution/authorization     | one executor, evidence-based commit, UNKNOWN preserved           | same-process bypass is detected, not prevented            |
| P2 access boundary             | Landlock self-tested, loud on absence, real OS comparator        | no syscall filtering; macOS confinement only via seatbelt |
| P3 complete-operation approval | `CanonicalRequest`, one hasher, raw-byte digests                 | attachment round-trip through live SMTP untested          |
| P4 provenance/exceptions       | `task_id`/`data_resources` preserved, declass≠endorse            | transformation table per-baseline, not one closed lattice |
| P5 occurrences                 | `Occurrence`+`payload_id`+window, SMTP envelope log              | needs an MTA that exposes envelopes                       |
| P6 concurrency/eval            | atomic reservation both paths, stubs replaced, inference removed | PACT score is coverage-dominated (disclosed)              |
