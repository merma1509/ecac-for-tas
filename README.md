# ECAC — Effect-Complete Authority Confinement for Tool Agents

**Executable kernel** for commit-time, effect-complete authority confinement of LLM tool agents.
Every tool-call side effect passes through a four-predicate gate (`Auth ∧ FlowOK ∧ NoAmp ∧ Fresh`);
nothing mutates external state outside the gate. The kernel is derived from real OS, SMTP and IMAP
state — not from tool-provided declarations — so the tool cannot forge outcomes.

> **Status:** validated executable model. The predicates are machine-checkable and
> independently falsifiable. This is a working specification, not a production system.

## Invariant

```bash
Commit(e, t)  ⇒  Auth(e, t) ∧ FlowOK(e, t) ∧ NoAmp(e, t) ∧ Fresh(e, t)
```

| Predicate | What it checks                                                             | Theoretical target                        |
| --------- | -------------------------------------------------------------------------- | ----------------------------------------- |
| `Auth`    | Broker holds a root-anchored capability for right+target                   | no commit without valid authority         |
| `FlowOK`  | No confidentiality leak, no low-integrity control                          | no forbidden flow without declass/endorse |
| `NoAmp`   | Authority chain is monotonic from `User`, not widened                      | no authority amplification                |
| `Fresh`   | Capability unexpired, unrevoked, not replayed (checked at commit time `t`) | stale/revoked authority not reused        |

`Fresh` is split from `Auth` because the brief's own target #4
("stale/revoked authority cannot be reused") requires a **time-dependent** check —
exactly what `Fresh(e, t)` performs at commit time. Bundling it into `Auth`
would conflate existence with usability.

## Primitive effects & the commit primitive

The primitive effects are `{read, write, send, delete, network}` — all **prepared**
(staged, non-mutating). They are `Effect` objects that never touch external state.
Only `broker.commit(Commit(effect))` may apply them; the executor is the **sole
mutation path**.

**Email domain (`send` / `read`):** these effects give the email domain a concrete
meaning — `send` delivers into the outbox, `read` reads from the inbox. Mailboxes
are part of `R = F ∪ E ∪ M` (files, email, mailboxes) and are broker-enforced.

**Risk escalation (R1):** A `risk_theta` classifier may route a high-risk effect
to an `Approver`. Approval grants a **fresh one-shot capability** that must still
pass all four predicates — the classifier is not part of the allow rule. Reuse
is a `Fresh` replay rejection.

## NoAmp: why path-based, not set-based

A naive NoAmp check ("effect authority ⊆ union of authorities in the chain") is
unsound: the broker is always in the chain, so a forged capability recorded under
`principal_authority[Broker]` always passes. NoAmp is corrected to **path-based**:

- Every `Capability` records `owner` (root that seeded authority) and `derives_from`
  (parent capability, or `None` for root grants)
- A capability is **legitimate** iff `owner = "User"` and the chain is monotonic
  attenuation from a root — never widened
- `Auth` is static (right+target match); `Fresh` is dynamic (unexpired at commit time)

A network capability forged by `Mallory` and granted to the broker is rejected by
NoAmp even though right+target match — because `owner = "Mallory"`.

## Layout

```bash
effect_broker/
  lattice.py         Confidentiality / Integrity lattices (IntEnum)
  model.py           Pure types: principals, resources (File, Email, Mailbox,
                     Domain), Data, Capability, Effect (prepared), Commit,
                     LabelException, ApprovedRequest, EffectTarget
  restricted_store.py  Mutable ResourceStore (F ∪ E ∪ M) — read-only views,
                     append-only logs, apply_effect() as SOLE mutation point
  ledger.py          IndependentEffectLedger — external append-only log of
                     authorizations + observations; UNAMBIGUOUS verdicts:
                     CONFIRMED_COMMITTED / CONFIRMED_BLOCKED / UNKNOWN
  observer.py        Independent observer: records every broker.authorize() call
                     and executor.apply_effect() observation for ledger audit
  broker.py          EffectBroker — the only committer; four predicates
                     (Auth / FlowOK / NoAmp / Fresh) + declass/endorse grants
                     (broker-only) + risk evaluation / approval (R1) + SSRF
                     containment for network effects
  executor.py        IsolatedExecutor — THE sole path to external state mutation.
                     All effects (broker.commit() callers and shim calls) go
                     through executor.execute(): broker.gate() then apply_effect().
  shim.py            BrokerShim / FileShim — constructs Effect objects from tool
                     calls; derives provenance labels from data content
  shim_real.py       RealFileShim — real Python filesystem operations (open, stat,
                     os.listdir, os.remove); derives effects from actual OS state
  shim_email.py      RealEmailShim — real SMTP (RCPT TO probe → RSET, BCC
                     detection, DATA delivery) + IMAP (SELECT / SEARCH / FETCH)
  mediation.py       Tool-boundary / MCP-semantics-honesty mediation:
                     MediationVerdict / mediate(), decided before broker.commit
  ipc.py             LedgerBackend + ProcessLedgerClient + LedgerProcessServer —
                     multi-process ledger isolation for production
  executor_ipc.py    IsolatedExecutor in a separate subprocess for TCB reduction
  executor_subprocess.py  Subprocess-based executor (same-process, enforced TCB)
  ledger_process.py  Standalone process entry point for the ledger server
  traces.py          Adversarial trace suite (T1–T20 + R1); T13/T14/T15 wired
                     through the mediation module
  experiment.py      Standalone adversarial experiments (M1–M8); independent
                     ledger verification; concurrent/replay safety tests
  unknown_not_safe.py  Effect type → safety classification (safe/unsafe/conditional)
  watcher.py         Real-time effect tracing: broker._observer → audit log
  __main__.py        CLI entry point: python -m effect_broker
```

```bash
tests/
  conftest.py         pytest fixtures: smtp_server (aiosmtpd), warnings suppress
  test_broker.py      20 adversarial trace tests (T1–T20)
  test_shim_email.py  9 SMTP/IMAP tests: RSET probe, BCC detection, broker gate
  test_shim_real.py   19 filesystem tests: path traversal, label derivation, OS errors
  test_observer_integration.py  Observer + broker + ledger integration
  test_audit_regressions.py    Audit trail completeness + regression tests
  test_approval_binding.py     One-shot capability + ApprovalBinding
  test_concurrent_replay.py    Concurrent nonce tracking + replay detection
  test_noamp_flowok_edge_cases.py  NoAmp + FlowOK edge cases
  test_session_closed.py      Closed session rejects further operations
  test_mediation_boundary.py   T13/T14/T15 boundary mediation
  test_ipc_executor_isolation.py  Executor in subprocess, ledger isolation
  test_periodic_audit.py      PeriodicAuditor snapshots
  test_experiment.py         M1–M5: real untrusted tool mandatory boundary experiment
  test_right_strict.py        Right-strict capability enforcement
  test_complete_targets.py    complete_targets() + additional_targets BCC scope
  test_email_domain_scope.py  Domain label + email recipient scope
  test_flow_declass.py        Declass/endorse + FlowOK interactions
  test_multiprocess_broker.py  Multi-process broker + ledger
  test_same_process_observer.py  Same-process observer observation correctness
  test_resource_identity.py   File/Email/Mailbox resource identity
  test_lifetime_replay.py     Capability lifetime + revocation + Fresh
  test_observer_exact_matching.py  Observer exact target matching
  test_ipc.py                 IPC: client/server ledger communication
  (23 test files, 315 tests, 7 skipped)
```

## Architecture

```bash
┌─────────────────────────────────────────────────────────────────────┐
│  IndependentEffectLedger (external, not owned by broker/executor)   │
│  • Records authorization from broker.gate()                         │
│  • Records observation from executor.apply_effect()                 │
│  • Verdicts: CONFIRMED_COMMITTED / CONFIRMED_BLOCKED / UNKNOWN      │
└─────────────────────────────────────────────────────────────────────┘
           ↑ broker.gate()              executor.apply_effect()
           │  (read-only predicates)         (sole mutation point)
           ↓                                    ↓
   ┌─────────────────┐          ┌──────────────────────────────┐
   │  EffectBroker   │          │    RestrictedResourceStore   │
   │  Auth/FlowOK/   │          │     apply_effect() → F ∪ E   │
   │  NoAmp/Fresh    │          │     effects_log              │
   └─────────────────┘          └──────────────────────────────┘
           ↑                                    ↑
           │ executor.execute()                 │
           │ (both paths unify here)            │
           └────────────────┬───────────────────┘
                            ↓
                   ┌────────────────────────────────────────────────┐
                   │                 TWO PATHS TO executor          │
                   │                                                │
                   │  PATH A: direct REPL callers                   │
                   │    broker.commit(Commit(effect))               │
                   │    → executor.execute()                        │
                   │    → broker.gate() → apply_effect()            │
                   │                                                │
                   │  PATH B: tool shim callers (TCOBB — multi-process)   │
                   │    RealFileShim.write(path, content)           │
                   │    RealEmailShim.send(sender, rcpt, body)      │
                   │    → derives effect from REAL OS/SMTP state    │
                   │    → executor.execute(Commit(effect))          │
                   │    → broker.gate() → apply_effect()            │
                   └────────────────────────────────────────────────┘
```

**Key property — TCOBB (The Only Code That Can Bypass, multi-process mode only):**
`RealFileShim` and `RealEmailShim` are the **only** code that calls `open()`,
`os.write()`, `smtplib`, and `imaplib`. The tool never touches these directly.
The shim derives effects from **real OS / SMTP / IMAP state** (not from tool
declarations), so the tool cannot forge outcomes.

> **Same-process mode caveat:** In `mode="same-process"`, the broker holds a
> direct reference to `RestrictedResourceStore`. Direct mutation via
> `broker.store._files._data[key] = X` bypasses the shim entirely. The ledger
> detects this as `UNKNOWN` (never "safe"). Production deployments MUST use
> `mode="multi-process"`. See "Honest limitations" below.

```bash
1. RSET-only SMTP probe → RCPT TO for every declared recipient
2. MTA response (code 250) tells us who it will actually accept
3. actual_accepted = {recipients with 250}
4. bcc_detected = actual_accepted − declared  ← if non-empty → fail closed
5. broker.commit() with real target set
6. On ALLOW → real SMTP DATA delivery
```

RSET means no message is queued or delivered during phase 1.

## Run

Managed with **uv**. Two equivalent wrappers drive the same targets:
the **Makefile** (`make <target>`) and the **`dev.sh`** helper (`./dev.sh <target>`).

### One-shot: run the model

```bash
make all        # full CI gate: lint + typecheck + test + verify
make run        # adversarial trace suite (T1–T20 + R1) with evidence
make help       # list all available targets
```

or via `dev.sh`:

```bash
./dev.sh setup        # install uv if missing (idempotent)
./dev.sh sync         # create venv + locked deps
./dev.sh run          # T1–T20 + R1 traces
./dev.sh lint         # ruff
./dev.sh typecheck    # mypy (strict)
./dev.sh test         # pytest — 315 tests across 23 files
./dev.sh verify       # assert trace outcomes
```

### Available targets

| Target      | What it does                                                        |
| ----------- | ------------------------------------------------------------------- |
| `setup`     | Install `uv` if missing (idempotent)                                |
| `sync`      | `uv sync` — create venv + install dependencies                      |
| `lint`      | `ruff check`                                                        |
| `format`    | `ruff format --fix`                                                 |
| `typecheck` | `mypy --strict` on `effect_broker`                                  |
| `test`      | 315 pytest tests across 23 files                                    |
| `run`       | `python -m effect_broker` — T1–T20 + R1 with per-predicate evidence |
| `verify`    | Assert trace outcomes (same as CI)                                  |
| `all`       | setup → lint → typecheck → test → verify                            |

`make all` is exactly what CI (`.github/workflows/ci.yml`) runs on every push.

## Adversarial trace suite (T1–T20 + R1)

Runnable scripts: initial state → agent proposal → broker decision → expected outcome.
Each maps 1:1 to the brief's Section-4 attack classes.

| #   | Attack class                                               | Expected result  |
| --- | ---------------------------------------------------------- | ---------------- |
| T1  | clean send (benign)                                        | ✅ ALLOW         |
| T2  | prompt injection                                           | ⛔ FlowOK        |
| T3  | confused deputy                                            | ⛔ Auth          |
| T4  | attacker-controlled URL (SSRF)                             | ⛔ Auth          |
| T5  | capability laundering                                      | ⛔ FlowOK        |
| T6  | delegation widening                                        | ⛔ Auth          |
| T7  | confidential-data leakage                                  | ⛔ FlowOK        |
| T8  | low-integrity → privileged action                          | ⛔ FlowOK        |
| T9  | stale approval                                             | ⛔ Fresh         |
| T10 | replay                                                     | ⛔ Fresh         |
| T11 | declassification abuse                                     | ⛔ FlowOK        |
| T12 | endorsement abuse                                          | ⛔ FlowOK        |
| T13 | false MCP description (declared vs actual target mismatch) | ⛔ boundary stop |
| T14 | hidden side effect on declared target                      | ✅ ALLOW         |
| T15 | monitor bypass                                             | ⛔ boundary stop |
| T16 | capability forgery                                         | ⛔ NoAmp         |
| T17 | path traversal                                             | ⛔ Auth          |
| T18 | recipient spoofing via BCC/CC                              | ⛔ FlowOK        |
| T19 | memory-poisoned instruction                                | ⛔ FlowOK        |
| T20 | amplification via composition                              | ⛔ Auth          |
| R1  | risk escalation: one-shot approval reuse                   | ⛔ Fresh         |

Boundary stop (T13/T15) is a **mediation verdict**, not a predicate — the effect
never reaches the remote tool because the broker stops it or the guarantee ends
at the broker→tool boundary.

## Findings

> **TL;DR:** The invariant is machine-checkable. The multi-process mode achieves
> genuine TCOBB and true isolation. Same-process mode is a development prototype
> where direct store mutation is possible (ledger returns `UNKNOWN`, not `safe`).
> Production deployments MUST use `mode="multi-process"`.

- **The invariant is expressible and machine-checkable.** Per-predicate evidence
  (including `primary_blocker`) is produced for every commit decision.
- **Single mutation path (ADR-003).** `IsolatedExecutor.apply_effect()` is the sole
  call site for `_apply_effect()`. Both `broker.commit()` callers and shim callers
  (Path A / Path B) unify in `executor.execute()`. The ledger observes the complete
  lifecycle through one execution path.
- **TCOBB — The Only Code That Can Bypass (multi-process mode).** In `mode="multi-process"`,
  `RealFileShim` and `RealEmailShim` are the only code that calls `open()`, `os.write()`,
  `smtplib`, and `imaplib`. The tool never touches these directly. Effects are derived
  from **real OS/SMTP state**, so the tool cannot forge outcomes. In `mode="same-process"`,
  direct store mutation is possible — the ledger returns `UNKNOWN`, not `safe`. See
  "Honest limitations" below.
- **Real SMTP BCC detection.** `RealEmailShim._parse_bcc_from_smtp()` opens a real
  SMTP connection, calls `RCPT TO` for every declared recipient, reads the per-recipient
  SMTP responses, then issues `RSET` to abort the transaction (no message queued).
  If any accepted address is outside the tool's declared set → BCC detected →
  `EmailSecurityError` before `broker.commit()`. This resolves the kill-criterion
  for BCC bypass: the MTA, not the tool, determines actual recipients.
- **Real IMAP read_inbox.** `RealEmailShim.read_inbox()` connects via `IMAP4_SSL`,
  `SELECT`s INBOX, `SEARCH ALL`, and `FETCH RFC822` for each message — then
  derives confidentiality/integrity from the real mailbox content.
- **NoAmp is not redundant with Auth.** A forged capability that passes Auth
  (right+target match, held by broker) and Fresh is still blocked by NoAmp
  because it is not root-anchored (`owner ≠ "User"`).
- **Replay prevention works.** Fresh detects reused nonces.
- **Declass/endorse are broker-only.** A conf-leak/low-integrity flow commits
  only with a broker-recorded `LabelException`. An LLM-attached exception that
  was never broker-granted is rejected — T11 (declass abuse) and T12 (endorse
  abuse) confirm "LLM may request, never perform."
- **Risk escalation (R1) is outside the allow rule.** Approval grants a fresh
  one-shot capability that must still pass all four predicates; reuse is a
  `Fresh` replay.
- **BCC scope enforcement.** `check_noamp()` verifies that every BCC/CC
  recipient's domain label is contained in the capability's scope. A grant
  for `internal@corp.com` does not authorize BCC to `attacker@evil.com` unless
  `additional_targets` explicitly includes it.

## Comparative evaluation (M1/M2/M3) — limitations

`eval_comparison.py` runs a comparative evaluation of ECAC against tool-call
allowlisting (M1) and argument-provenance checking (M2). The comparison has
important limitations that the README's original table overstated:

| Mode | Mechanism                        | What it evaluates                           |
| ---- | -------------------------------- | ------------------------------------------- |
| M1   | tool-call allowlist              | Stub checker (mode1_tool_call.py)           |
| M2   | argument provenance (PACT-style) | Stub checker (mode2_argument_provenance.py) |
| M3   | ECAC effect-complete gate        | Full broker (same-process mode)             |

- **M1/M2 stubs are not production implementations.** Both are minimal stub
  checkers in `effect_broker/modes/`. They demonstrate the architectural
  distinction (tool-level vs effect-level enforcement) but are not peer systems.
- **M3 runs in same-process mode.** The 22 trace tests and `eval_comparison.py`
  all use `EffectBroker(mode="same-process")`. This means direct store mutation
  is possible — TCOBB does not fully hold. Production deployments require
  `mode="multi-process"`.
- **18/18 vs 0/21 vs 1/21 catch rates are not peer-reviewed.** These numbers
  reflect the same-process model and stub comparators. They are evidence for
  design, not a validated security evaluation. See "315 tests ≠ real confinement"
  in Honest limitations.

The qualitative distinctions (capability laundering, confidential-data leakage,
stale/replay, BCC scope) are architecturally sound and tested by the trace
suite in the same-process model. `eval_comparison.py` demonstrates the approach
but is not a peer-reviewed security evaluation.

## Honest limitations

- **315 tests ≠ real confinement.** Tests are regression evidence for the implemented
  predicates. They do not establish genuine protected-effect confinement — that requires
  isolation, independent observation, and formal guarantees. This is a working
  specification, not a verified secure system.
- **Same-process isolation is advisory.** Broker, executor, store, and ledger all
  run in the same Python process. Direct store mutation (`store._files._data[...]=X`)
  bypasses the executor; the ledger returns `UNKNOWN` for it — not `safe`. Real
  isolation requires a separate process or enclave.
- **T13/T14/T15 use metadata, not real enforcement — mitigated by strict mode.**
  `Mediator.inspect()` uses `ToolSpec` metadata set by the test author; a real
  adversarial tool can lie about its actual targets. `Mediator(..., strict=True)`
  makes mediator registration mandatory — unknown tools are BLOCKed. The mandatory
  boundary experiment (`tests/test_experiment.py`, M1–M5) uses a **real untrusted tool**
  to demonstrate that computation is actually bounded.
- **T14 (hidden side effect on declared target):** ECAC philosophy — broker authorizes
  the declared target; undisclosed side effects are caught by the ledger/observer in
  production, not blocked at the broker gate. This is the scope boundary of the broker,
  filled by the ledger.
- **Provenance labels are hand-assigned.** Labels are derived by the shim from actual
  OS/SMTP/IMAP state, but the label-to-keyword mapping is heuristic. Real taint
  propagation requires language-level taint tracking or runtime provenance APIs.
- **Resource labels are minimal.** File sensitivity (path keywords) and email domain
  are the only resource classifications; a full policy repository is not modeled.
- **TCB expansion is unquantified.** Effect mediation pulls primitives into the
  trusted core; the TCB size and correctness are not formally argued.
- **Exactly-once external semantics not claimed.** The ledger confirms each authorized
  effect is applied at most once (Fresh + occurrence count). Whether SMTP/filesystem
  deliver/process exactly-once is outside scope.
- **No performance or approval-burden metrics.** Experiments measure correctness only.
- **No external baseline comparison.** ECAC is not yet compared against a genuine
  baseline under matched assumptions.
