# Response to Review — Diagnostic Report

**Answers:** external review, "1. Current issues and how to solve them"
**Issue-by-issue (P1–P6):** [REVIEW_RESPONSE_P1_P6.md](REVIEW_RESPONSE_P1_P6.md)
**Index of the original mapping:** [REVIEW_REMEDIATION.md](REVIEW_REMEDIATION.md)
**Machine:** macOS (darwin/arm64), Python 3.12.13; Linux evidence from Ubuntu CI
**Commit:** `develop` @ `eb12edb`

---

## How to read this

The previous report was criticised for marking items COMPLETE that the code did
not implement, and `docs/PLANS.md` was retired for exactly that. So this
document does not have a "status" column that asserts progress. Every claim below
is either a number produced by running something, or a test name that fails if
the claim stops being true. Where an item is not finished, the report says what
is missing and what evidence would close it.

Two verdicts are used, and they are not a scale:

| Verdict     | Means                                                                                |
| ----------- | ------------------------------------------------------------------------------------ |
| **Closed**  | A test fails if the property stops holding, and I verified that by breaking the code |
| **Partial** | Part of the requirement holds; the rest is named and unimplemented                   |

No item is marked **Open** in the sense of "nothing done", because none is in that
state — but no item is closed on the strength of a plan either. Where the central
requirement of an item is unmet (item 1's single executor, item 6's cross-process
budget), the verdict is Partial and the missing half is named explicitly rather
than averaged into the verdict.

## Headline

The frozen-feature request (item 7) was followed: no new capability was added
while this was measured. The work in this cycle was the diagnostic instrument
itself and the defects it exposed.

Of the six substantive items, **two are closed and four are partial**:

| Item | Subject                            | Verdict     | The blocker, stated plainly                                                                                                                |
| ---- | ---------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| 1    | Execution↔authorization coupling   | **Partial** | Shims still perform I/O after `commit()`. Evidence gating is real; the ordering is not unified.                                            |
| 2    | OS-enforced boundary               | **Partial** | Landlock is real and verified on Linux; on macOS it does not exist and the flag makes it refuse rather than pretend.                       |
| 3    | Approval binds complete operation  | **Closed**  | Body binding and request-hash binding both have gate-level tests.                                                                          |
| 4    | Provenance and exception semantics | **Closed**  | Label binding, the transformation table and the codec round-trip are tested per field.                                                     |
| 5    | Observer distinguishes occurrences | **Partial** | `Occurrence` now has a real producer (MTA log), but the diagnostic does not consume it and file verification still collapses to a boolean. |
| 6    | Concurrency and evaluation         | **Partial** | Thread-scoped reservation is real; cross-process is not. Comparators are honest but the sandbox comparator is absent.                      |

The one-line summary: **the measuring instrument is now trustworthy in the parts
that are green, and the parts that are not green are named.** That sentence is
the deliverable, not a claim of protection.

---

## Item 1 — Execution and authorization must be connected

**Verdict: Partial.**

### What the review asked

> Current file and email shims perform real I/O after the model commit.
> Define precisely when an effect commits, and make one trusted executor
> responsible for authorization, execution and outcome recording. Record
> COMMITTED only from evidence of the actual protected operation.

### What is now true

**Commit is defined by a type, not by convention.** `EffectEvidence(outcome="committed")`
raises in its constructor unless a transport response and at least one observed
target are present. An unbacked commit claim is therefore not constructible
anywhere in the codebase — this is enforced at construction, so it cannot be
bypassed by a new caller that forgets.

**An observation alone no longer reads as a commit.** `verify()` returns
`UnknownLedgerResult("committed_without_evidence")` when no evidence backs the
claim. This changed a contract: sixteen tests that recorded
`record_authorization` + `record_observation` and asserted `CONFIRMED_COMMITTED`
now record evidence too. Two of them were _inverted_ rather than updated,
because their premise contradicted the invariant.

**A real crash is survived, not simulated.** `tests/test_crash_harness.py` (9
tests) starts a child process, waits until it is parked past the IN_FLIGHT
marker, `SIGKILL`s it, and asserts the recovered ledger reports `UNKNOWN` while
still distinguishing "dispatched" from "never started". This required journaling
the marker before the I/O. Constructing the post-crash state in-process would not
have demonstrated survivability; only the harness does.

**Outcome counting agrees with the verdict.** This was found by this cycle's
audit, not reported by the review but a direct instance of the same requirement.
`outcome_of()` filed an `executor.apply` observation under `committed` while
`verify()` called the same effect `committed_without_evidence`. Since
`executor.apply` is recorded _before_ the effect reaches external state, a
process killed in between left an observation for a write that never happened —
and the metrics, which read `outcome_of()`, reported it as a commit. The audit
path and the reporting path now call the same function.

```
tests/test_commit_ordering.py          31 passed
tests/test_crash_harness.py             9 passed
tests/test_outcome_counts.py           27 passed
```

`test_outcome_of_never_disagrees_with_verify` is the pin: reintroducing the old
classification makes it and three others fail.

### What is still not true

**The I/O still happens in the shim, after `commit()`.** This is the item's
central requirement and it is not met. `shim_real.py:697` calls
`broker.commit()`; the write is dispatched at line ~728 via
`ipc_client.real_file_write`. The same shape holds in `shim_email.py:559`, where
`_smtp_send` follows the ALLOW branch.

The dispatch marker is written _before_ the IPC call, so a crash between them is
reported as `dispatched, unobserved` rather than silently lost. That is honest
reporting of an ordering that should not exist. It is not the fix the review
asks for.

**Why this was not simply refactored.** I examined the change and deferred it
rather than attempt it blind, for a reason that is specific and checkable: in
multi-process mode `APPLY_COMMIT` already performs the write in process B, so the
shim's post-ALLOW `open()` is redundant; in same-process mode it is the only
write. Moving it relocates where a crash lands relative to the dispatch marker,
which is the exact ordering `tests/test_commit_ordering.py` pins. Doing that
correctly means designing one commit point for both modes, which is a
PLAN 4 deliverable (`Move _smtp_send / open() out of the shims into the
executor`), not a refactor to be squeezed in.

**What would close it.** A `Request` value that the executor performs, with the
shim holding no file or socket handle at all. The exit criterion is a test that
fails if the shim's own process performs a syscall on the target — measurable by
running the shim under a seccomp filter that traps `open`/`connect`.

---

## Item 2 — The access boundary remains incomplete

**Verdict: Partial** — real where the kernel exists, refused where it does not.

### What the review asked

> Patching `os.open` and blocking selected imports does not confine arbitrary
> tool code. Replace the current assumptions with an OS-enforced boundary.
> Correct the Landlock integration, verify that restrictions are active, and
> align the documentation with the mechanisms actually installed.

### What the audit found, which is worse than the review stated

The review said patching `os.open` is insufficient. The audit found the patch was
also _wrong in a way that looked right_: `_landlock_handled_access()` omitted
`READ_FILE`, so the kernel confined **writes but not reads**. `~/.ssh/id_rsa`,
`~/.aws/credentials` and a signing key under `/tmp` all opened through the real
syscall while the status string reported `restricted-open`. The status advertised
a layer whose most-asked-about property was absent.

Two further defects were found alongside it:

- `_apply_landlock_sandbox()` called `restrict_self` with the ruleset FD where
  the flags argument belongs, added no rules, and ignored the result — then
  reported the sandbox active.
- `/etc` was granted as a _subtree_, so `/etc/shadow` was readable through a
  read root the code believed was narrow.

### What is now true

`READ_FILE` is in the handled mask. `/etc` is no longer a root; individual files
are granted (`hosts`, `resolv.conf`, `passwd`, the CA bundle), so a file missing
from the list is unreadable — it fails closed.

`_selftest_confinement()` probes **both directions**: a legitimate read under a
permitted root must succeed, and a canary under `$HOME` must fail with `EACCES`.
The canary is planted _before_ the ruleset applies, because afterwards `$HOME` is
unwritable and the probe would have nothing to test.

The selftest also had to avoid a false positive that already in the suite:
`/etc/shadow` returns `EACCES` for a non-root test user _by ordinary
permissions_, not because Landlock blocked it. Treating that as proof would have
passed with Landlock entirely absent.

### Evidence, and its limit

```
macOS:  17 passed, 13 skipped   ← every kernel-level test skipped
Linux:  Ubuntu CI, ECAC_REQUIRE_CONFINEMENT=1, green
```

The 13 skips are the Landlock tests and they skip with the reason
`Landlock is Linux-only`. **I cannot claim the boundary holds on macOS** because
the mechanism does not exist there, and the code does not pretend it does:
`ECAC_REQUIRE_CONFINEMENT=1` makes the executor refuse to start rather than run
unconfined. CI sets it, so the Linux path is genuinely exercised on every push.

**Mutation-verified on Linux:** removing the `READ_FILE` bit makes
`test_read_file_is_in_the_handled_mask` and both write tests fail (26 pass with
it, 3 fail without).

### What is still not true

The boundary confines **file reads and writes**. It does not yet confine
credentials reached by other means: an inherited file descriptor, a process
environment variable holding a token, or a network call to a metadata endpoint
are outside what Landlock rules on. `PathAllowlist` blocks
`169.254.169.254` at the policy layer, which is a different mechanism and a
weaker one.

**The caveat that matters operationally:** any path under a _write_ root is
readable by design, so a credential file kept inside `/tmp/ecac-sandbox` stays
readable. Secrets must live outside the sandbox root.

---

## Item 3 — Approvals must bind the complete operation

**Verdict: Closed.**

### What the review asked

> Define one unambiguous canonical request containing the task, operation,
> acting account, sender, complete recipients, exact content and attachment
> digests. Hash raw bytes consistently across processes. The current
> subject/body concatenation permits encoding ambiguities, and the live email
> effect in `shim_email.py` omits the actual body bytes.

### What is now true

`CanonicalRequest` binds operation, acting account, sender, complete recipients
and attachment digests, and `canonical_bytes()` is length-prefixed, so
`subject='a|b', body='c'` and `subject='a', body='b|c'` no longer collide. Both
processes call one `sha256_raw()` helper; the subprocess's mirrored hashing copy
is gone.

### The defect that was hidden behind a green row

P5-10 was marked DONE for "changed attachment changes `request_hash`", and it
was. But the same review item also recorded that `shim_email.py` omits the body,
and for that there was **no row at all** — so the register could be fully green
while every email approval bound `sha256("")`.

- `RealEmailShim.send()` put `subject` and `body_size` on the effect and no
  `body`. `compute_content_hash()` therefore returned the hash of the empty
  string for every send, making `content-hash-mismatch` in `gate()` dead code
  for email. An approval granted for one message authorized any other —
  demonstrated end-to-end through the live shim.
- `body_size` is not a substitute: two bodies of equal length share it, so a
  check resting on it passes the very case it was meant to catch.
- Existing tests missed it because they build their `Effect` by hand _with_
  `body` in metadata. Only an effect taken from the shim shows the gap.

`tests/test_email_body_binding.py` (14 tests) now runs the shim's own
construction path, which is why it catches this and the hand-built tests did not.

### Also found in the same path

The shim's metadata held a `frozenset`, so every email commit in multi-process
mode raised `TypeError` inside `_sign_payload` — _after_ the gate authorized, and
as a crash rather than a denial, leaving no verdict in the journal.
`effect_to_dict()` now normalizes non-encodable values at the serialization
boundary instead of relying on each shim to remember.

```
tests/test_approval_request_binding.py  5 passed
tests/test_email_body_binding.py       14 passed
tests/test_canonical_request.py       (passing; non-UTF-8 round-trip)
```

Request-hash binding was **mutation-verified**: with the `request_hash` check
disabled, 3 of the 5 approval tests fail. The other 2 pin the legitimate paths,
so the fix cannot be satisfied by denying everything.

### Honest limit

The approval binds _what is transmitted_ by hashing it at both ends. It does not
bind the transport's own transformation — an MTA that rewrites a header (or a
transport that re-encodes) is not detected. The BCC case is handled separately by
the envelope probe, not by the request hash.

---

## Item 4 — Provenance and exceptions need stronger semantics

**Verdict: Closed.**

### What the review asked

> A valid provenance ID must not permit changing the associated labels or
> substituting unrelated content. Explicitly define which transformations
> preserve provenance. A confidentiality release must leave integrity checks
> active. In `executor_ipc.py`, preserve `LabelException.task_id` and
> `data_resources`, and correct the inconsistent taint-resource field names.

### What is now true

**Label substitution under a valid `prov_id` is caught.** `is_trusted_provenance`
compares `confidentiality` and `integrity`;
`provenance_mismatch_reason()` names the diverging field. A caller cannot edit a
label and keep the ID.

**This is safe for legitimate labelling for a specific reason.**
Confidentiality is derived in exactly one place from trusted OS state
(`statx.derive_provenance`: statx bits → permission bits → keyword →
deny-most), and its integrity is always `USER` for OS-derived content. The label
recorded at read-commit time is therefore authoritative; a caller wanting a
different label must obtain a new committed read under a different capability,
not edit the field.

**The transformation table is derived from a rule, not asserted.** A
transformation preserves provenance iff its output is a deterministic function of
its inputs **and** every output byte is attributable to an input byte. That single
rule yields, non-obviously:

| Transformation                             | Preserves              | Why                                                                                         |
| ------------------------------------------ | ---------------------- | ------------------------------------------------------------------------------------------- |
| `summarise`, `translate`, `model_generate` | **No**                 | output is _new content_; a summary of CONFIDENTIAL data is CONFIDENTIAL **and** UNTRUSTED   |
| `concat`                                   | Yes, with lattice join | needs confidentiality MAX / integrity MIN across all inputs, not the primary input's labels |
| `encrypt`, `hash`                          | Yes                    | datum is opaque but the label still travels — **encryption is not declassification**        |
| `decode_lossy` (`errors="replace"`)        | **No**                 | the concrete defect at `model.py` vs `executor_subprocess.py`                               |

An unclassified transformation raises `KeyError` rather than defaulting to
`PRESERVED`. 22 tests in `tests/test_provenance_transforms.py` cover every row.

**The codec now rejects absence rather than defaulting.** An absent key means
the producer did not consider the field; an explicit `null` means it deliberately
chose `None`. Conflating them is exactly how `task_id` became "valid in any task"
and `data_resources` silently stopped clearing taint. Every security-relevant
field has its own round-trip test:

```
tests/test_review_remediation.py        17 passed
  TestProvenanceLabelBinding             5
  TestDeclassSurvivesIpc                 3
  TestLabelExceptionCodec                6
  TestDeclassDoesNotClearIntegrity       3
tests/test_provenance_transforms.py     22 passed
```

**A confidentiality release leaves integrity active** — this was already correct
and is now pinned rather than assumed (P5-11 needed no code change; a test
prevents it drifting).

---

## Item 5 — The observer must distinguish actual occurrences

**Verdict: Partial** — the type has a real producer now; the diagnostic does not
use it.

### What the review asked

> Final file state and recipient sets cannot establish whether an operation
> occurred once, twice, or transiently. Record occurrence identity, payload
> identity and a bounded observation window, including effects absent from the
> broker's claims. The SMTP probe checks supplied addresses; it does not discover
> arbitrary hidden recipients. Observe actual envelope transactions associated
> with message acceptance.

### The criticism was correct on both counts

**The probe was circular.** `smtp_log` carried the comment "in a real deployment
this is the MTA's mail log, read out-of-band", but nothing read one. Every caller
filled the list by hand from the handler it had just written — the independent
observer was listening to the sender's own account of itself. That is the exact
failure mode an out-of-band observer exists to rule out.

**Recipient sets cannot establish recurrence.** Two sends to the same address
collapse into one set; a send followed by a failure collapses into one entry; a
transient effect leaves no trace at all.

### What is now true

`effect_broker/mta_log.py` parses the MTA's own accounting.
`read_postfix_log()` / `parse_postfix_log()` produce `EnvelopeTransaction`
values; `occurrences_from_transactions()` turns each accepted recipient into an
`Occurrence` with `effect_id` (`smtp:<queue_id>:<index>`), `payload_id`,
`source="smtp-envelope"` and a bounded `window`.
`IndependentOracle.from_mta_log()` builds the oracle from a log rather than from
a list.

`effect_id` is stable within a transaction and distinct across them, so two sends
to the same address do not collide — which is the property the review asked for
and a set cannot express.

**The fixture is a real log, not a synthetic one.**
`tests/data/postfix-maillog.txt` was captured from Postfix 3.7.11 in a container
(`scripts/capture_mta_log.sh`) and contains one honest single-recipient send
(`nrcpt=1`) and one whose client declared one recipient and gave the MTA two
(`nrcpt=2`, with `to=<attacker@evil.com>`). `hidden_recipients()` surfaces the
undeclared address. Because the fixture asserts on Postfix's own vocabulary, a
hand-written replacement would fail the suite rather than quietly weaken it.

```
tests/test_mta_log.py          21 passed
tests/test_occurrences.py      13 passed
```

### What is still not true

**The diagnostic does not count occurrences.** `metrics.diagnostic_report()` has
no occurrence section; grep for `Occurrence` in `metrics.py` and
`diagnostic_run.py` returns nothing. So the report below cannot tell you whether
an effect happened once or twice — the tooling to answer it exists and is unused.

**File verification still collapses to a boolean.**
`IndependentOracle.verify_write()` returns `os.path.exists`. A file written twice
and then deleted is indistinguishable from one never written.

**`reconcile_unknowns()` fixes the duration, not the count.** It settles a
crash-torn write from the filesystem, attributed to `oracle.reconcile`, and
leaves `authorized_not_observed` and non-file targets alone. It answers "did this
land", not "how many times did it land" — those are different questions and only
the first is now answered.

---

## Item 6 — Concurrency and evaluation need repair

**Verdict: Partial.**

### What the review asked

> Reserve execution tickets and send budgets atomically before execution,
> including the multiprocess path. Test different concurrent nonces, failed
> execution and acknowledgement loss. Replace the named baseline stubs with
> faithful implementations. Implement a real conventional broker-plus-sandbox
> comparator. Also remove the evaluator's inference that a denied request
> automatically proves complete mediation.

### The budget defect, stated precisely

`send_count` was a plain int incremented _after_ a successful apply, and the gate
only read it. **Five concurrent sends with `max_sends=1` were all allowed.** The
regression test reports it as `budget of 1 admitted 5 sends` when the reservation
is disabled.

`Session` now exposes `reserve_send` / `commit_send` / `release_send` over a lock,
and the gate reserves a ticket atomically in the same locked section as the nonce.
A blocked gate releases the ticket; a failed apply does too, so a transport
failure still does not spend budget.

**This is cross-thread, not cross-process.** `_send_tickets` and the lock live in
`Session`, which is per-process. Two executor processes sharing a session are
**not** covered. This is the remaining half and it is why the row stays PARTIAL.

```
tests/test_send_budget_tickets.py         5 passed
tests/test_concurrent_subprocess.py       3 passed
  test_ten_threads_one_commit
  test_replay_after_completion_is_blocked
  test_different_nonces_both_commit
```

**Acknowledgement loss has no test.** It is named in the review and it is absent;
there is no `test_*ack*` in the suite.

### The mediation inference — why it was the worst one in the suite

It is not merely wrong, it is _inverted_ in its effect: the more successfully the
suite blocked things, the more confidently it declared mediation complete. The
scenario that would have exposed a hole — one effect escaping while another was
blocked — was exactly the one nobody checked for. At the T18 rate-limit site the
field was hardcoded `True` with the comment "rate limiting worked correctly",
which is an assertion about a different mechanism entirely.

`mediation_complete` is now nullable, requires `mediation_evaluated`, and
`__post_init__` refuses to hold a verdict without it. The old code now raises
`ValueError: ... this is the 'blocked implies complete' inference in disguise`
instead of quietly returning True.

### Comparators: honest, but still not faithful

The review's criticism was that the comparisons omitted central mechanisms of the
published systems. The stubs returned `True` unconditionally, scoring 0/20 —
a comparison against a stub measures the stub.

They now have real deny paths, and each declares what it omits
(`COMPARATOR_MECHANISMS`). Measured:

| Comparator    | Blocked | Note                                                |
| ------------- | ------- | --------------------------------------------------- |
| ECAC          | 20/20   |                                                     |
| PACT          | 14/20   | scope only; no taint, replay, content, BCC          |
| PathAllowlist | 9/20    | renamed from "conventional sandbox" — it is not one |
| FORGE         | 9/20    |                                                     |
| ArgProv       | 6/20    | argument provenance only                            |
| OS_Sandbox    | 4/20    | real Landlock/seatbelt confinement, kernel verdict  |
| CaMeL         | 4/20    | IFC at sinks only                                   |
| ChainCaps     | 3/20    |                                                     |
| Cordon        | 3/20    |                                                     |
| Allowlist     | 2/20    |                                                     |

**This table is weaker evidence than it looks, and the reason matters.** These
comparators are reimplementations of the published designs inside this codebase,
scored against this codebase's own 20 traces. A low score partly measures how
much of the published mechanism was implemented here, not how the published
system performs. It is a sanity check on the stubs, not a benchmark.

**There is still no real conventional broker-plus-sandbox comparator.** The row
was closed by _renaming_, not by implementing: `mode_conventional_sandbox.py` is
now `mode_path_allowlist.py` and states it is a path/host allowlist. That removes
a false name; it does not add the comparator the review asked for. A faithful one
needs a real Landlock/seatbelt profile and is unbuilt.

---

## Item 7 — The diagnostic comparison

**Verdict: the instrument exists and runs. Its numbers are narrower than they
appear, and both halves of that sentence are the finding.**

Feature work was frozen for this. `scripts/diagnostic_run.py` and
`metrics.diagnostic_report()` emit the seven requested measurements.

### Actual output

```
================================================================
ECAC DIAGNOSTIC RUN
================================================================
1. Unauthorized effects:   0
2. Legitimate completion:  2/2
3. False denials:          0 {}
4. UNKNOWN outcomes:       0
5. Approvals:              granted=7 used=3 expired_unused=0
6. Overhead (wall clock):  p50=0.02ms p95=0.02ms p99=0.02ms (syscalls: not measured)
7. Trusted boundary (these must tell the truth for 1-6 to mean anything):
   - effect_broker/shim_real.py — performs real I/O and reports it
   - effect_broker/broker.py — the store is the observation source
   - effect_broker/executor_subprocess.py — applies effects, reports observed targets
   - effect_broker/oracle.py — derives verdicts from external sources
   - effect_broker/metrics.py — labels scenarios attack/legitimate
8. Complete mediation:     evaluated=pass
================================================================
Context: attacks=4 blocked=4 missed=0
```

### What each number does and does not mean

I am stating these beside the numbers because a bare `0` reads as "we looked and
found none" when it can mean "this cannot happen here yet". That confusion is the
defect the previous report was retired for.

| Metric                | Value                      | What it actually establishes                                                                                                                                                                                                                                            |
| --------------------- | -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unauthorized effects  | 0                          | Zero effects reached external state without an authorization **in four scripted scenarios**. It is not a claim about arbitrary tool code.                                                                                                                               |
| Legitimate completion | 2/2                        | Both benign scenarios completed. Two is a small denominator; one scenario per shim.                                                                                                                                                                                     |
| False denials         | 0                          | No legitimate operation was blocked, by predicate.                                                                                                                                                                                                                      |
| **UNKNOWN outcomes**  | **0**                      | **This zero is structural, not a measurement.** No scenario crashes mid-operation, so nothing can be mid-flight. `tests/test_crash_harness.py` produces UNKNOWN by killing a process; the diagnostic does not include such a scenario.                                  |
| Approvals             | granted=7 used=3 expired=0 | 4 grants unused. `expired_unused=0` is **also structural** — capability expiry is caught by the gate as a denial before authorization is recorded, so nothing reaches AUTHORIZED-then-given-up. A test pins this so adding such a path forces the note to be revisited. |
| Overhead              | p50 0.02ms                 | **Wall-clock only. Syscalls are `null`, not zero** — reported as unmeasured rather than invented. The figure excludes real I/O (it measures the gate, and the scenarios are simulated).                                                                                 |
| Trusted boundary      | 5 files                    | These five must tell the truth for metrics 1–6 to mean anything. `shim_real.py` is in it _because it performs the I/O_ — which is item 1's open defect showing up in the trust list.                                                                                    |

**The most important number is the one that is absent.** The diagnostic does not
count occurrences, so it cannot say whether an effect happened once or twice.
Item 5's machinery exists; wiring it in is a small, well-defined next step and
would make metric 1 meaningfully stronger.

### What the review asked for and did not get

The review asked for a _small diagnostic comparison_ reporting seven metrics.
All seven are printed. What is missing is the **comparison**: the numbers
above are ECAC alone. A side-by-side against the comparators in the same run,
with false-denial counts for each, is not produced — the comparator harness
scores traces but does not feed the diagnostic's counters.

This is why the comparator table in item 6 is reported as a sanity check on
stubs rather than as a comparison: the two instruments do not share a scale,
and joining them by hand would produce a number that looks comparable and is
not.

### The trusted boundary, restated as a threat model

The five files above are assumed correct. What that means concretely:

- **In TCB:** the gate (`broker.py`), the effect model (`model.py`), the
  executor that performs and records, the oracle, and the metric definitions.
- **Not in TCB:** the shims' _policy_ choices, the MTA's honesty, the
  filesystem's honesty, and — critically — **the tool code itself, which is only
  confined where the kernel confines it (Linux)**.

A process that can write the MTA log can forge entries. A process that can write
the journal can forge a history. Neither is defended against here, and neither is
claimed.

---

## Test suite as it stands

```
934 passed, 14 skipped          (macOS, Python 3.12.13; 948 collected)
CI: Ubuntu, Python 3.11 and 3.12, ECAC_REQUIRE_CONFINEMENT=1 — green
ruff: clean     mypy: clean (30 source files)
verify_traces.sh: OK (22 traces)
verify_eval.sh: OK (17/18 blocked, benign M4 allowed)
```

The 14 skips are all Landlock tests on macOS. They are not counted as passing and
this report does not treat them as evidence for item 2.

---

## What the audit found that the review did not

Recorded separately because these are instances of the review's own themes that
the review did not name. Each was found by re-checking a row against running code
rather than against the document.

| Defect                                                                                                                                          | Theme            | Found by                                           |
| ----------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- | -------------------------------------------------- |
| `outcome_of()` counted a pre-I/O observation as committed while `verify()` called it unknown                                                    | Item 1           | auditing the metrics path against the verdict path |
| `target_for()` settled an effect against its **parent directory** — `sorted()[0]` picked the dir, which always exists, so the check "succeeded" | Item 5           | writing the reconcile test; it failed              |
| `/etc` granted as a subtree, so `/etc/shadow` readable                                                                                          | Item 2           | the selftest's canary read                         |
| `restrict_self` called with the FD in the flags slot, no rules added, result ignored, sandbox reported active                                   | Item 2           | reading the syscall wrapper                        |
| `shim_email` put a `frozenset` in metadata ⇒ `TypeError` in `_sign_payload` **after** authorization, leaving no verdict                         | Item 3           | multi-process email commit                         |
| Three exit criteria marked DONE that did not hold (P5-1 read confinement, P5-9, P5-10)                                                          | the meta-problem | re-checking each row against code                  |

The last row is the one worth dwelling on. It is the same failure mode that
retired `PLANS.md`, recurring in the register built to prevent it. The mechanism
that now catches it is that every criterion names a test or a grep, and each was
re-run rather than trusted.

---

## Choosing the research contribution from the evidence

The review's closing instruction was: keep features frozen, run the diagnostic,
_then_ choose the contribution from the evidence. This section is that choice,
argued from what the numbers actually support.

### What the evidence supports

**A contribution resting on "20/20 vs 4/20" would be unsound.** The comparators
are reimplementations of published designs inside this codebase, scored on this
codebase's traces, by this codebase's author. A defensible comparative claim needs
each system implemented by its own maintainers or from its own artefact, on
neutral traces. What exists now is evidence that the stubs were stubs — which is
worth reporting as a correction, not as a result.

**A contribution resting on "0 unauthorized effects" would be unsound.** Four
scenarios, two shims, and the boundary that matters is absent on the development
platform.

**What the evidence does support is a claim about the _measurement problem_.**

Every defect this cycle found — and every defect the review found — has the same
shape: **the artefact reported a property it did not have, and the report was
constructed from the same code it was describing.** Specifically:

- the sandbox reported itself active while adding no rules and ignoring its own
  failure;
- the status string reported `restricted-open` while reads were unconfined;
- the observer reported "out-of-band" while being fed by hand from the handler;
- the metrics reported commits the audit path called unknown;
- the register reported DONE for criteria that did not hold;
- the comparators reported checking a mechanism they never wired to a return
  value.

That is not a coincidence of scope. It is the characteristic failure of
self-reported security systems: **the evidence and the claim share a code path,
so a defect in one silently blesses the other.**

### The proposed contribution

> **Evidence independence** as an explicit, testable property of an
> effect-mediated agent system: a security claim is admissible only when the
> evidence for it is produced by a path that does not also produce the claim,
> and that separation is itself checkable by mutation.

This is smaller than "a new mediation architecture" and much more defensible,
because this repository already demonstrates each piece of it:

1. **Independent evidence sources** — the MTA log (item 5) rather than the
   handler; the filesystem (item 1 reconcile) rather than the executor's own
   report; a real `SIGKILL` (item 1) rather than a simulated one.
2. **Untrustworthiness made unconstructible** — `EffectEvidence(outcome="committed")`
   raises without a transport response and an observed target, so the bad state
   is not representable rather than merely discouraged.
3. **Three-valued verdicts** — `mediation_evaluated` distinct from
   `mediation_complete`, `UNKNOWN` distinct from `failed`, `None` distinct from
   `False`, so "not checked" cannot be read as "checked and passed".
4. **Mutation as the acceptance test** — a criterion is admissible only if
   breaking the code makes a named test fail. This is the operation that would
   have caught every defect in the table above, and it is cheap.

The falsifiable claim: **for each security property in the diagnostic, removing
the mechanism that enforces it must make a named test fail.** If a property can
be broken silently, it was self-reported and is not admissible. This is testable
across the whole boundary, and it is a contribution about _how to know_, which is
exactly what the failed rows in this report show is the hard part.

### Why this rather than the alternatives

| Candidate                                 | Why not now                                                                                                                                    |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| New mediation architecture                | The architecture is not the open problem; its reporting is. Building more surface before the instrument works repeats the failure.             |
| Comparative evaluation of agent mediators | Needs neutral traces and third-party implementations. Currently unsound — see above.                                                           |
| Faithful sandbox comparator               | Genuinely needed (item 6), and it is _infrastructure for_ the contribution, not the contribution.                                              |
| Formal verification of the gate           | Attractive but presupposes the TCB is the one claimed; item 1 shows the shim still holds I/O, so the TCB boundary would be formalised wrongly. |

### The honest precondition

Item 1 must close first. While the shim performs I/O after `commit()`, the
"trusted executor" the whole argument rests on is not yet the thing that performs
the effect — and any claim about evidence independence would be describing a
boundary that does not exist. That is a sequencing constraint, not a caveat.

---

### Sequencing: what comes first

The review asked to choose the contribution from the evidence. Taking the
evidence at face value:

**1. Item 1's ordering (highest value, hardest).** It is the only item where a
defect can produce a _false clean_ result: an effect authorized, performed, and
recorded in an order that loses the record. Everything else reports uncertainty;
this one can hide. The design work is one commit point spanning both execution
modes.

**2. Item 6's cross-process budget (cheapest real gap).** The thread-scoped
reservation is correct and the missing half is a file lock plus a lease for a
dead holder. The defect it fixes is demonstrated (`budget of 1 admitted 5 sends`).

**3. Item 5's diagnostic wiring.** `Occurrence` has a producer and the diagnostic
ignores it. Connecting them is small, and it turns the occurrence work from a
library into a measurement.

---

## The one thing I want the reviewer to check

Not the code — the register. `REVIEW_REMEDIATION.md` has been wrong twice: it
marked P5-9, P5-10 and P6-3 DONE while the properties were false, and a third
audit found an item with no row at all. Both times the document was green and the
code was not.

This report is written against the code, and every "Closed" row was
mutation-verified by breaking it. If any claim here fails to reproduce, that is
the finding to report — it means the register is drifting again, and the register
is the artifact that this whole exercise depends on being honest.

---

## Reproduction

Everything above is reproducible from a clean checkout.

```bash
# The diagnostic (item 7)
uv run python scripts/diagnostic_run.py

# Per-item evidence
uv run pytest tests/test_commit_ordering.py tests/test_crash_harness.py \
              tests/test_outcome_counts.py -q          # item 1
uv run pytest tests/test_confinement_honesty.py -q -rs  # item 2 (13 skip off Linux)
uv run pytest tests/test_approval_request_binding.py \
              tests/test_email_body_binding.py -q       # item 3
uv run pytest tests/test_review_remediation.py \
              tests/test_provenance_transforms.py -q    # item 4
uv run pytest tests/test_mta_log.py tests/test_occurrences.py -q  # item 5
uv run pytest tests/test_send_budget_tickets.py \
              tests/test_concurrent_subprocess.py -q    # item 6

# Full suite
uv run pytest tests/ -q      # 934 passed, 14 skipped (948 collected)
uv run ruff check . && uv run mypy effect_broker
```

Counts stated in this document were re-measured against the tree at `HEAD`,
not at `develop` @ `eb12edb`: the suite has grown to 948 tests. The
14 skips are Landlock tests; CI runs them on Ubuntu with
`ECAC_REQUIRE_CONFINEMENT=1`, where they execute rather than skip.

### Test totals for this cycle's work

| File                               | Tests | Item |
| ---------------------------------- | ----- | ---- |
| `test_commit_ordering.py`          | 31    | 1    |
| `test_crash_harness.py`            | 9     | 1    |
| `test_outcome_counts.py`           | 27    | 1    |
| `test_email_body_binding.py`       | 14    | 3    |
| `test_approval_request_binding.py` | 5     | 3    |
| `test_review_remediation.py`       | 17    | 4    |
| `test_provenance_transforms.py`    | 22    | 4    |
| `test_mta_log.py`                  | 21    | 5    |
| `test_occurrences.py`              | 13    | 5    |
| `test_oracle_reconcile.py`         | 9     | 5    |
| `test_send_budget_tickets.py`      | 5     | 6    |
| `test_concurrent_subprocess.py`    | 3     | 6    |

---

## What is not done, in one place

Listed without mitigation, because a reader scanning for gaps should find them in
one list rather than spread across prose.

1. **Shims perform I/O after `commit()`** (item 1, central requirement). The
   executor is not yet the sole performer.
2. **No cross-process send budget or ticket store** (item 6).
3. **No acknowledgement-loss test** (item 6, named in the review).
4. **No real conventional broker-plus-sandbox comparator** (item 6). Renamed, not
   implemented.
5. **Occurrences are not counted by the diagnostic; file verification is a
   boolean** (item 5).
6. **Confinement does not exist on macOS**, and the development machine is macOS.
   All kernel-boundary evidence is from CI, not from local runs.
7. **The `UNKNOWN=0` and `expired_unused=0` metrics are structural**, not
   measurements, until scenarios that produce those states are added.
8. **`docs/` is gitignored**, so this document and the plans are not in the
   repository and not in CI. They are local artefacts.
