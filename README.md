# Effect-Complete Authority Confinement for Tool Agents — Tiny Executable Model

A minimal, throwaway executable model of the core invariant to
check whether the invariant is expressible and machine-checkable **before**
building the full kernel

> This is a validation tool, not the production system. It carries sound
> _design intent_ (a root-anchored, monotonic authority model) but is not yet a
> formal proof or a production kernel.

## Invariant

```bash
Commit(e, t)  =>  Auth(e,t) and FlowOK(e,t) and NoAmp(e,t) and Fresh(e,t)
```

- **Auth** — the broker holds a _live, root-anchored_ capability matching the
  effect's right + target
- **FlowOK** — every influencing value satisfies confidentiality (no leak, no
  forbidden declass) and integrity (no low-integrity control of privileged
  actions) constraints against the effect's sink. An otherwise-forbidden flow
  may commit **only** with a broker-validated `declass`/`endorse` exception
  recorded on explicit User policy or approval (broker-only privilege).
- **NoAmp** — the effect's authority is a _root-anchored, monotonic_ derivation
  from a trusted root (User), not merely "present in some chain or store
- **Fresh** — the capability is unexpired, unrevoked, and not replayed

### Why four predicates, not three

The supervisor's initial invariant stated three predicates —
`Authorized ∧ FlowOK ∧ NoAuthorityAmplification`. We keep **four** by splitting
a fourth, **Fresh**, out of _Auth_. The reason is that `Auth` already bundles
two logically distinct obligations, and separating them makes the proof
obligations cleaner and each predicate independently falsifiable:

- **Auth** (static authorization): _the broker holds the right capability for
  this right+target_. This is a **time-independent** statement — it answers
  "is the authority derivable from User and unamplified?" (the capability's
  existence and its content match the effect).
- **Fresh** (dynamic authorization): \*the capability (and any approval) is
  **still valid at commit time t\*** — not expired, not revoked, not replayed.
  This is a **time-dependent** statement and is _inherently about commit time_,
  which is exactly where the broker revalidates.

Bundling "unexpired/unrevoked/unreplayed" into `Auth` would conflate _whether
authority exists_ with _whether authority is currently usable_. Concretely:

- A revoked capability is still a capability; `Auth` alone (matching
  right+target) would pass, and only a **time-sensitive** check can reject the
  reuse of stale or revoked authority.
- The brief's own theoretical target #4 — _"stale/revoked authority cannot be
  reused at commit"_ — is **not expressible** as a static predicate; it
  requires a check _at commit time t_. `Fresh(e,t)` is that check.

So the four-predicate form is not a divergence from the brief; it is the brief's
own target #4 made first-class. Every theoretical target maps 1:1 to a
predicate:

| Theoretical target (brief)            | Predicate |
| ------------------------------------- | --------- |
| no authority amplification            | `NoAmp`   |
| no commit without valid authority     | `Auth`    |
| no forbidden flow w/o declass/endorse | `FlowOK`  |
| stale/revoked authority not reused    | `Fresh`   |

The three-predicate statement is subsumed: if the proposed triply (without
`Fresh`) represents the intended security condition, our four-predicate form is
**stronger** (allows strictly fewer commits) and each conjunct is individually
machine-checkable, which is what the executable kernel needs.

## Primitive effects & the commit primitive

Following Report #1 model v0.1, the primitive effects are
`{read, write, send, delete, network, commit}`:

- `read`, `write`, `send`, `delete`, `network` are **prepared** (staged,
  non-mutating) — they are `Effect` values that never touch external state.
- `commit` is a **separate primitive** (`Commit`) that wraps a prepared
  `Effect`. Only the `EffectBroker` may invoke it, and only after the four
  predicate gate passes. It is the single point where a prepared effect becomes
  a real side effect in the `ResourceStore`.

This makes "the LLM proposes (prepares effects), the EffectBroker commits" a
literal part of the data model, not just a description.

## Mailbox & email-domain semantics

The `send`/`read` effects give the email domain a concrete, testable meaning so
`Mailbox` (M) carries real structure rather than being a dead type:

- `send` targets an email address and **delivers into the sender's outbox** via
  an `address -> mailbox` resolution (`ResourceStore.mailbox_for`).
- `read` on an email **retrieves the message from its owner's inbox**.
- Mailboxes are therefore part of the email domain (message + its inbox/outbox),
  not a separate enforcement domain; they still appear in `R = F ∪ E ∪ M` as a
  resource class the broker may target

## Risk evaluation -> Approver -> one-shot capability (R1)

A (learned) `risk_theta` classifier may route a high-risk effect to an
`Approver` (`needs_review`). Approval grants a **fresh, one-shot** capability
(`grant_approval`), which must **still** pass `Auth ∧ FlowOK ∧ NoAmp ∧ Fresh` at
commit — the classifier is **not** part of the formal allow rule. Reusing the
one-shot capability is a `Fresh` replay rejection

## Static Auth vs dynamic Fresh (revocation hangs off Fresh)

`Auth` is **static**: it checks that the broker holds a capability whose
holder, right, and target match the effect. `Fresh` is **dynamic**: it checks at
commit time `t` that the capability is unexpired, unrevoked, and not replayed.
Revocation is enforced **solely by `Fresh`** in the current implementation, so a
revoked capability passes `Auth` but is rejected by `Fresh` (see
`test_revoked_blocked_by_fresh_not_auth`)

## Design note: why NoAmp is path-based, not set-based

The first version of the week-1 model checked NoAmp: effect_authority
as subset of union of authorities recorded for each principal in the chain

That is **unsound**, for two reasons:

1. The broker is always in the real delegation chain, and any capability granted
   to the broker (e.g. a forged one) is recorded under `principal_authority[Broker]`
   As soon as the chain contains the broker — which it always does — the subset
   test passes
2. It conflates _root-granted_ authority with _derived_ authority, so a forged or
   widened capability is indistinguishable from a legitimate one

This is exactly the failure mode "authority amplification through composition or
forgery" must catch, so the model was corrected to make NoAmp **path-based**:

- Every capability records `owner` (the root that seeded authority) and
  `derives_from` (the parent it was attenuated from, or `None` for a root grant)
- A capability is _legitimate_ iff:
  - its `owner` is a trusted root (`User`), and
  - it was produced only by monotonic attenuation (narrower scope) from a root
- An effect is _non-amplifying_ iff _every_ capability backing its delegation
  chain is legitimate and the chain does not widen authority

Under this rule a forged network capability granted by `Mallory` to the broker is
rejected by NoAmp even though it "matches" right + target and is present in the
broker's store

## Layout

```bash
effect_broker/
  lattice.py      Confidentiality / Integrity lattices
  model.py        pure model types: principals + resources (File, Email, Mailbox,
                  Domain) + Data, Capability, Effect(prepared), Commit,
                  LabelException, ApprovedRequest
  restricted_store.py  mutable ResourceStore (F ∪ E ∪ M) — read-only views,
                  append-only logs, apply_effect() as SOLE mutation point
  ledger.py       IndependentEffectLedger — external, append-only log of
                  authorizations + observations; makes UNAMBIGUOUS verdicts:
                  CONFIRMED_COMMITTED / CONFIRMED_BLOCKED / UNKNOWN
  mediation.py    tool-boundary / MCP-semantics-honesty mediation (T13/T14/T15):
                  MediationVerdict / mediate, decided via the broker's commit gate
  broker.py       EffectBroker (the only committer) + four predicates
                  + commit primitive + declass/endorse grants (broker-only)
                  + attempt_wide (honest, non-monotonic widening) + risk-evaluation
                  / approval (R1 one-shot) + static Auth / Fresh-owned revocation
  executor.py     IsolatedExecutor — THE SOLE PATH to external state mutation;
                  ALL effects (direct broker.commit() calls AND tool/shim calls)
                  go through executor.execute(): broker.gate() then apply_effect()
                  which calls broker._apply_effect(). The ledger observes the
                  complete lifecycle through ONE execution path.
  shim.py         BrokerShim / FileShim — constructs Effect objects from tool calls;
                  derives provenance labels from data content; is the ONLY path
                  to the ResourceStore (the enforcement shim)
  ipc.py          LedgerBackend + ProcessLedgerClient + LedgerProcessServer —
                  multi-process ledger isolation for production deployment
  ledger_process.py  Standalone process entry point for the ledger server
  traces.py       adversarial trace suite (20 predicate/gate traces plus the R1
                  escalation trace); T13/T14/T15 wired through the mediation module
  experiment.py   standalone adversarial experiments (M1–M8), independent ledger
                  verification, concurrent/replay safety tests
run_traces.py    entry point
```

## Architecture

```bash
┌──────────────────────────────────────────────────────────────────┐
│ IndependentEffectLedger (EXTERNAL, not owned by broker/executor) │
│  - Created OUTSIDE broker + executor                             │
│  - Records authorization (from broker.gate)                     │
│  - Records observation (from executor.apply_effect)              │
│  - Makes UNAMBIGUOUS verdicts: CONFIRMED_COMMITTED /             │
│    CONFIRMED_BLOCKED / UNKNOWN                                   │
│  - PeriodicAuditor: on-demand + scheduled audit snapshots        │
└──────────────────────────────────────────────────────────────────┘
                               ↑
                      broker.gate()  ← read-only predicate gate
                               ↓
                      executor.apply_effect()  ← SOLE MUTATION POINT
                               ↓
                      IndependentEffectLedger.record_observation()

There is ONE and only ONE call site for _apply_effect():
  executor.apply_effect(). ALL effects — whether from broker.commit() (direct REPL
  callers) or tool/shim calls — go through the same execution path:
  executor.execute() → broker.gate() → executor.apply_effect() → _apply_effect().

broker.commit() is a thin reentrant wrapper that delegates to executor.execute().
The shim calls executor.execute() directly. Both paths record to the same
IndependentEffectLedger, so verify_complete_mediation() works uniformly.

UNKNOWN = "unknown, not safe" — an effect not observed by the ledger
could be a direct store mutation bypass. In the same-process model, such
a bypass would produce UNKNOWN, not a false CONFIRMED_COMMITTED.
In a multi-process production deployment, the ledger would live in an
isolated enclave where only the executor's apply_effect primitive can write.
```

## Run (make / dev.sh)

The repository is managed with **uv**. Two equivalent wrappers drive the same
targets: the **Makefile** (`make <target>`) and the **`dev.sh`** helper
(`./dev.sh <target>`).

### One-shot: run the model

```bash
make all        # full CI gate: lint + typecheck + test + verify
make run        # run the adversarial trace suite (20 traces + R1) with evidence
make help       # list all available targets
```

or, equivalently, via the `dev.sh` helper:

```bash
./dev.sh run      # run the trace suite
./dev.sh lint     # ruff
./dev.sh typecheck  # mypy (strict)
./dev.sh test     # pytest
./dev.sh verify   # assert trace outcomes (same as CI)
```

### Step-by-step from a fresh clone

```bash
./dev.sh setup        # install uv itself (idempotent), if missing
./dev.sh install      # uv sync: create venv + install project & dev deps
./dev.sh run          # run the tiny executable model (T1–T20 + R1, with evidence)
make all              # full CI gate: lint + typecheck + test + verify
```

### Available targets

| `make` / `./dev.sh`      | What it does                                         |
| ------------------------ | ---------------------------------------------------- |
| `setup`                  | Ensure `uv` is installed (idempotent)                |
| `install` (alias `sync`) | venv + locked deps via `uv sync`                     |
| `lint`                   | ruff check (all checks pass)                         |
| `format`                 | ruff format + `--fix`                                |
| `typecheck`              | mypy (strict) on `effect_broker`                     |
| `test`                   | 225 pytest tests across 16 files                     |
| `run`                    | `python run_traces.py` (22 traces with evidence)     |
| `verify`                 | assert trace outcomes (same as CI)                   |
| `all`                    | setup → lint → typecheck → test → verify (full gate) |

`make all` is exactly what CI (`./.github/workflows/ci.yml`) runs on every push.

## Adversarial trace suite (20 traces)

Each trace is a runnable script: initial state -> agent proposal -> broker
decision -> expected outcome. They map 1:1 to the brief's Section-4 attack
classes and are asserted in `tests/test_broker.py`.

| #   | Attack class                                               | Expected result  |
| --- | ---------------------------------------------------------- | ---------------- |
| T1  | clean send (benign)                                        | ✅ ALLOW         |
| T2  | prompt injection                                           | ⛔ FlowOK        |
| T3  | confused deputy                                            | ⛔ Auth          |
| T4  | attacker-controlled URL (SSRF)                             | ⛔ NoAmp         |
| T5  | capability laundering                                      | ⛔ FlowOK        |
| T6  | delegation widening                                        | ⛔ NoAmp         |
| T7  | confidential-data leakage                                  | ⛔ FlowOK        |
| T8  | low-integrity->privileged action                           | ⛔ FlowOK        |
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
| T20 | amplification via composition                              | ⛔ NoAmp         |

> Trace numbers here are the suite order; the code names them `T1..T20` and
> prints the attack class. The several `BoundaryStop` outcomes (T13/T14/T15)
> are a _mediation_ verdict, not a predicate — the effect never reaches the
> remote tool because the broker either blocks it or the guarantee stops at the
> broker->tool boundary (per "Tool/MCP semantics honesty" in the brief).

## Findings

- The invariant is expressible and machine-checkable (per-predicate evidence,
  including a `primary_blocker`).
- **Single mutation path (ADR-003).** `IsolatedExecutor.apply_effect()` is the
  sole call site for `_apply_effect()`. Every effect — whether from `broker.commit()`
  (direct REPL callers) or from tool/shim calls — goes through `executor.execute()`.
  The ledger observes the complete lifecycle through one execution path. Direct
  mutations (`broker.store._files._data[...]=X`) still bypass in the same-process
  model, but the ledger returns `UNKNOWN` for them — not `safe`.
- NoAmp is **not redundant with Auth**: a forged capability that passes Auth
  (right+target match, held by the broker) _and_ Fresh is still blocked by NoAmp
  because it is not root-anchored. This is the genuinely non-trivial Week-1
  result, and it is now defensible.
- Replay prevention works (Fresh detects a reused nonce).
- The network effect's integrity floor was corrected so the policy is achievable
  (not dead), preserving utility while still blocking low-integrity control.
- The prepared-vs-committed split is enforced: via `commit_effect`, a denied
  effect provably never reaches external state (`effects_log` stays empty for
  blocked effects), while an allowed effect is applied exactly once.
- **Declass/endorse are broker-only, explicit, and machine-checkable.** A
  conf-leak/low-integrity flow commits only when a broker-recorded LabelException
  (granted by User/Approver) validates it (test_validated_declass_allowed). An
  LLM-attached exception that was never broker-granted is rejected at commit —
  trace T11 (declass-abuse) and T12 (endorse-abuse) — confirming "LLM may request,
  never perform."
- Risk escalation (R1) is outside the allow rule. A learned risk model may
  route a high-risk effect to an Approver, but its grant is a fresh one-shot
  capability that must still pass Auth ∧ FlowOK ∧ NoAmp ∧ Fresh; reusing it is
  a Fresh replay (tested in test_risk_escalation_one_shot_approval)
- **Exact immutable request binding (kill-criterion #5).** `ApprovedRequest`
  captures the complete effect identity: (etype, targets, task_id).
  Any deviation — different etype, different targets, cross-task use — is blocked
  by `ApprovalBinding`. Provenance/integrity is enforced by `FlowOK`, not binding.
  Binding to actual content values would break legitimate dynamic content
  (e.g. different message body per send invocation).
- **BCC scope enforcement.** `check_noamp()` verifies that every BCC/CC
  recipient's domain label is contained in the capability's scope. A grant
  for `send to internal@corp.com` does not authorize `send to internal@corp.com
with BCC to external@attacker.com` unless `additional_targets` explicitly
  includes the BCC recipient (ADR-002 exact effect identity).

## Comparative evaluation: Mode #1 vs Mode #2 vs Mode #3

All three modes were evaluated on the same 20 adversarial traces (run `uv run python eval_comparison.py`):

| Mode | Mechanism                        | Blocks            | Catch rate |
| ---- | -------------------------------- | ----------------- | ---------- |
| M1   | tool-call allowlist              | 0/20              | 0%         |
| M2   | argument provenance (PACT-style) | 1/20              | 5%         |
| M3   | ECAC effect-complete gate        | **18/18** attacks | **100%**   |

M3 catches **17 attacks that M1 and M2 miss entirely**. This includes:

- **Capability laundering** (T5): M1/M2 allow because the tool name is on the allowlist / arguments are locally valid; M3 blocks because FlowOK detects the capability was derived from an untrusted source
- **Confidential-data leakage** (T7): M1/M2 allow because arguments are locally sound; M3 blocks because FlowOK detects the confidentiality violation from a trusted source to an external sink
- **Stale approval / replay** (T9, T10): M1/M2 cannot detect temporal misuse of a capability; M3 blocks because `Fresh` checks commit-time validity
- **Declass/endorse abuse** (T11, T12): M1/M2 cannot check whether the exception was broker-granted; M3 blocks because the broker records and validates every declass/endorse grant
- **BCC recipient spoofing** (T18): M1/M2 allow because the primary recipient is valid; M3 blocks because FlowOK checks all additional_targets including BCC/CC
- **Amplification via composition** (T20): M1/M2 allow because individual steps are valid; M3 blocks because NoAmp verifies the entire delegation chain is monotonic

The only traces M3 allows that M1/M2 also allow:

- **T1** (benign read): legitimate operation, should be allowed
- **T14** (hidden side effect on declared target): ECAC-philosophy case — a tool that declares `trusted` with undisclosed `secrets` side effects is allowed because the broker does not yet observe the hidden effect; the broker stops the declared target, not the undisclosed one

M2's single catch (T8) is because the attacker-controlled `instruction` has integrity=UNTRUSTED, which FlowOK in M2 catches even at the argument level. M3 also blocks T8, so the difference is M3's blocking is **earlier** (argument level, via FlowOK) while M1 misses it entirely.

**Conclusion:** M3's commit-time effect-complete gate is the correct enforcement point. Verifying effects — not just tool names or arguments — is necessary to catch the full attack surface.

## Honest limitations

- **225 tests ≠ real confinement.** Passing tests are regression evidence for the
  implemented predicates. They do not establish genuine protected-effect confinement
  — that requires isolation, independent observation, and formal guarantees. The
  current model is a specification and executable invariant, not a verified secure
  system. The full suite (16 test files, 225 tests) exercises all four predicates,
  concurrent replay, approval binding, closed sessions, boundary mediation, and IPC.
- **Same-process isolation is advisory.** The broker, executor, store, and ledger
  all run in the same Python process. Direct store mutation (`store._files._data[...]`
  = X) bypasses the executor and the ledger returns `UNKNOWN` for it — not `safe`
  — but the broker cannot prevent it. Real isolation requires a separate process
  or enclave.
- **T13/T14/T15 use metadata, not real enforcement — but strict mode closes the bypass.** `Mediator.inspect()` uses `ToolSpec` metadata set by the test author. A real adversarial tool can lie about its actual targets. **Solution:** set `Mediator(..., strict=True)` — this requires all tools to register with the mediator. Unknown tools are blocked, not permitted. The mandatory boundary experiment (`tests/test_experiment.py`, M1–M5) uses a **real** untrusted tool to demonstrate that computation is actually bounded. **ECAC T14 philosophy:** if the declared target is authorized, the broker ALLOWs — hidden side effects on other resources are caught by the ledger/observer, not blocked at the broker gate. This reflects the scope boundary: the broker cannot see what side effects a tool performs.
- **T14 (hidden side effect on declared target):** ECAC philosophy — a tool that
  declares `trusted` but secretly touches `secrets` as a side effect is ALLOWED
  by the broker. The broker cannot observe hidden side effects — it only sees
  the declared target. The independent ledger/observer catches the discrepancy
  in production (observed secrets write not in authorized targets). This is NOT
  a gap: it's the scope boundary of the broker, and the ledger fills it.
- **Unknown tool bypass (mitigated):** Without a mediator, any tool_name bypasses
  boundary mediation. **Mitigation:** `Mediator(..., strict=True)` makes mediator
  registration mandatory. Unknown tools are BLOCKed, not permitted.
- **Exactly-once external semantics are not claimed.** The ledger confirms that
  each authorized effect is applied at most once (Fresh + occurrence count in
  `verify()`). Whether external providers (SMTP, filesystem) deliver/process
  exactly-once is outside this model's scope.
- **Provenance labels are hand-assigned.** Labels are assigned by `BrokerShim`,
  not extracted from real LLM/tool dataflow. Real taint propagation requires
  language-level taint tracking or runtime provenance APIs.
- **Resource labels are minimal.** File sensitivity and email domain are the only
  resource classifications; a full policy repository is not modeled.
- **TCB expansion is unquantified.** Effect mediation pulls primitives into the
  trusted core. The size and correctness of the TCB are not formally argued.
- **No performance or approval-burden metrics.** Experiments measure correctness
  only. Approval latency and broker throughput are not measured.
- **No external baseline comparison.** The report does not yet compare ECAC
  against a genuine baseline under matched assumptions.
