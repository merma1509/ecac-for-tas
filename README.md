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
  lattice.py     Confidentiality / Integrity lattices
  model.py       pure model types: principals + resources (File, Email, Mailbox,
                 Domain) + Data, Capability, Effect(prepared), Commit, LabelException
  resources.py   mutable ResourceStore (F ∪ E ∪ M) — the broker's external state
  broker.py      EffectBroker (the only committer) + four predicates
                 + commit primitive + declass/endorse grants (broker-only)
  traces.py      adversarial trace suite (all 20 traces). The T13/T14/T15
                 tool-boundary / MCP-semantics-honesty traces are modeled as a
                 mediation step (MediationVerdict / mediat) alongside the
                 predicate-gate traces — no separate module
run_traces.py    entry point
```

## Run

```bash
python run_traces.py     # prints all 20 traces with per-predicate evidence
make                     # full gate: lint + test + run (trace outcomes asserted)
```

## Adversarial trace suite (20 traces)

Each trace is a runnable script: initial state → agent proposal → broker
decision → expected outcome. They map 1:1 to the brief's Section-4 attack
classes and are asserted in `tests/test_broker.py`.

| #   | Attack class                         | Expected result  |
| --- | ------------------------------------ | ---------------- |
| T1  | clean send (benign)                  | ✅ ALLOW         |
| T2  | prompt injection                     | ⛔ FlowOK        |
| T3  | confused deputy                      | ⛔ Auth          |
| T4  | attacker-controlled path/URL (SSRF)  | ⛔ Auth/NoAmp    |
| T5  | capability laundering                | ⛔ FlowOK        |
| T6  | delegation widening                  | ⛔ NoAmp         |
| T7  | confidential-data leakage            | ⛔ FlowOK        |
| T8  | low-integrity→privileged action      | ⛔ FlowOK        |
| T9  | stale approval                       | ⛔ Fresh         |
| T10 | replay                               | ⛔ Fresh         |
| T11 | declassification abuse               | ⛔ FlowOK        |
| T12 | endorsement abuse                    | ⛔ FlowOK        |
| T13 | false MCP description (hidden write) | ⛔ boundary stop |
| T14 | hidden side effect                   | ⛔ boundary stop |
| T15 | monitor bypass                       | ⛔ no commit     |
| T16 | capability forgery                   | ⛔ NoAmp         |
| T17 | path traversal                       | ⛔ Auth/FlowOK   |
| T18 | recipient spoofing via BCC/CC        | ⛔ FlowOK        |
| T19 | memory-poisoned instruction          | ⛔ FlowOK        |
| T20 | amplification via composition        | ⛔ NoAmp         |

> Trace numbers here are the suite order; the code names them `T1..T20` and
> prints the attack class. The several `BoundaryStop` outcomes (T13/T14/T15)
> are a _mediation_ verdict, not a predicate — the effect never reaches the
> remote tool because the broker either blocks it or the guarantee stops at the
> broker→tool boundary (per "Tool/MCP semantics honesty" in the brief).

## Findings (Week 1, after fix)

- The invariant is expressible and machine-checkable (per-predicate evidence,
  including a `primary_blocker`).
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
  `conf-leak`/`low-integrity` flow commits **only** when a broker-recorded
  `LabelException` (granted by User/Approver) validates it (T3-completeness).
  An LLM-attached exception that was never broker-granted is rejected at commit
  (T7), confirming "LLM may request, never perform".

## Honest limitations

- Resource labels (file sensitivity, email domain) are minimal — a full
  metadata repository (R = F ∪ E ∪ M with rich policies) is Week-3 work, but
  the resource + `commit_effect` primitive mechanics are now modeled.
- Provenance lists are hand-assigned, not extracted from a real LLM/tool layer
  (real taint propagation is Week-3 work).
- The tool-boundary / MCP-semantics-honesty decision is **scaffolded**, not
  fully modeled: T13/T14/T15 show a `MediationVerdict` (`MediationVerdict` /
  `mediat`) where the effect is screened _before_ forwarding to the remote
  tool, but real tool adapters and the mechanized checker ↔ semantics proof
  are **not yet modeled** — they are the next steps and the two sharpest
  differentiators.
- The TCB-expansion trade-off (effect mediation pulls small primitives into the
  trusted core) must be argued explicitly in Week 2; this model does not decide it.
