# ECAC Architecture (consolidated)

> Merged from: threat-model.md, formal_invariant.md, formal_semantics.md, tcb-measurement.md

===================================================================

# Part I — Threat Model

===================================================================

# ECAC Threat Model

> This document defines the trusted/untrusted boundary, the threat model
> assumptions, and the known limitations of the ECAC effect broker.

---

## 1. System Overview

ECAC is an **effect-completion authorization** system for tool-using AI agents.
The broker is the single point of authorization for effects produced by tools.
Effects must be explicitly committed through `EffectBroker.commit()` to be
authorized.

```bash
┌─────────────────────────────────────────────────────┐
│                   Agent process                     │
│                                                     │
│  Tool code ──► ShIM ──► Effect ──► Broker.commit()  │
│                    │              │                 │
│                    ▼              ▼                 │
│              Provenance        4-predicate          │
│                                 gate                │
│                                    │                │
│                              CommitGateResult       │
│                                    │                │
│                                    ▼                │
│                             executor.apply()        │
│                              (sole mutation)        │
└─────────────────────────────────────────────────────┘
```

---

## 2. Trusted Computing Base (TCB)

### Components in TCB

| Component                      | LOC (approx) | Role                              |
| ------------------------------ | ------------ | --------------------------------- |
| `broker.py` — 4-predicate gate | 1017         | Auth, FlowOK, NoAmp, Fresh        |
| `model.py`                     | 595          | Effect, Capability, Task, Session |
| `executor.py`                  | 285          | sole mutation path                |
| `restricted_store.py`          | 266          | same-process resource store       |
| **Core TCB**                   | **2175**     | measured, `effect_broker.tcb`     |

These figures are **executable lines** — the same definition `tcb_size()` in
`effect_broker/metrics.py` reports, so the document and the metric can be
compared. `tests/test_tcb_measurement.py` fails if the file set here and
`_TCB_FILES` disagree.

### Components NOT in TCB

| Component                             | Reason                                         |
| ------------------------------------- | ---------------------------------------------- |
| `eval_comparison.py`                  | Evaluation harness only                        |
| `tests/`                              | Regression tests, not confinement proofs       |
| `modes/mode1_tool_call.py`            | Baseline comparison, not part of M3            |
| `modes/mode2_argument_provenance.py`  | Baseline comparison, not part of M3            |
| `ledger.py` (IndependentEffectLedger) | Audit observer, not authorization              |
| `mediation.py` (Mediator)             | Advisory boundary check, consulted but not TCB |

---

## 3. Threat Model Assumptions

### Assumed Secure

- **Broker code is correct.** The broker is assumed to implement the four-predicate
  gate faithfully. TCB measurement and formal verification are future work.
- **Nonce generation is secure.** Nonces are assumed unguessable (UUID4 or
  equivalent). A predictable nonce generator would allow replay attacks.
- **Capability distribution is trusted.** Capabilities are issued by a trusted
  authority and delivered to the agent via a secure channel.
- **Session IDs are not forgeable.** The session ID is used in freshness checks.
  If an adversary can guess or forge session IDs, replay attacks are possible.
- **Provenance is authentic.** Provenance attached to effects is assumed to be
  produced by the tool runtime and not tampered with in transit. See AUDIT-5.

### Assumed Adversarial / Threat Actors

- **Malicious tool:** A tool that behaves differently from its declared interface.
  May produce unauthorized effects, leak data, or attempt to bypass the broker.
- **Confused deputy:** An agent or component that uses a capability for a purpose
  it was not intended for (T2).
- **SSRF / path traversal:** An attacker who controls effect targets and attempts
  to escape the broker's logical scope (T4, T17).
- **Data exfiltration:** An attacker who uses legitimate capabilities to move
  data to unauthorized destinations (T3, T7, T18).
- **Replay / nonce reuse:** An attacker who reuses a committed effect's nonce
  (T10). See AUDIT-2.
- **Adversarial provenance:** An attacker who provides false provenance to
  bypass FlowOK checks (T5, T8, T11, T12, T19, T20). See AUDIT-5.

---

## 4. Trusted / Untrusted Boundary

### Trusted (within TCB)

- `EffectBroker.commit()` — the sole authorization point
- The four predicates: `check_auth`, `check_flow`, `check_noamp`, `check_fresh`
- `executor.py:apply()` — the sole mutation path
- `model.py` — data types and their invariants
- The capability store (`broker.capabilities`) — not forgeable by tools
- The nonce store (`broker.nonce_used`) — not forgeable by tools
- The session state (`broker.sessions`) — managed by broker

### Untrusted (outside TCB)

- **Tool code** — runs in the same process, can produce any Effect
- **Agent prompt/instruction** — controls tool call arguments
- **`broker.store`** — lives in the same process as the broker
  (see Known Limitation: Same-Process Enforcement)
- **Effect content** — `effect.content` dict is opaque; broker does not
  verify structure or semantics
- **Provenance data** — provided by the shim, not independently verified
- **`effect_broker.ledger`** — observer that reads broker state, not an
  independent source of truth (see AUDIT-1)
- **Boundary mediator** — advisory only; broker predicates run first

### Boundary: Broker vs. Tool Runtime

```bash
Tool runtime → [Effect] → Broker.commit() → [ALLOW/BLOCK]
                              │
                              ├── check_auth (nonce, right, target, task)
                              ├── check_flow (confidentiality, integrity)
                              ├── check_noamp (scope, BCC recipients)
                              ├── check_fresh (nonce, expiry)
                              ├── mediation.inspect() [advisory]
                              └── executor.apply() [only if ALLOW]
```

The broker does **not**:

- Control CPU time, memory, or file descriptors
- Intercept syscalls made directly by tool code
- Authenticate the tool runtime's provenance claims
- Enforce that effects are the **only** actions taken by a tool

---

## 5. Known Limitations

### Critical

**Same-Process Enforcement (AUDIT-1)**  
`broker.store` is a Python object in the same process as the broker. A
determined adversary can bypass `broker.commit()` by modifying `broker.store`
directly. This is the most severe architectural limitation.

- **Mitigation:** Deploy broker + store in a separate process or hardware enclave.
  Current same-process mode is for development and evaluation only.
- **Tests:** `test_broker.py`, `test_mediation_boundary.py` — regression tests,
  **not confinement proofs**.

### Medium

**right="\*" Substitutes Any Right (AUDIT-3)**  
A capability with `right="*"` matches any effect right for its target. A
read-only capability with `right="*"` will authorize writes.

**task_id=None Capabilities Are Task-Independent (AUDIT-4)**  
A capability with `task_id=None` can be used by any task. This is a design
choice but could allow cross-task authorization if a capability is
accidentally issued with `task_id=None`.

**Session Closure Is Not Persistent (AUDIT-4)**  
Closing a session blocks further commits within that session, but does not
prevent re-registration with a new session. The task continues under a new
session.

**Provenance Is Hard-Coded in Evaluation (AUDIT-4)**  
`eval_comparison.py` constructs `provenance=[Data(...)]` manually. Real shims
must extract provenance from tool arguments. No real dataflow is exercised in
the evaluation harness.

### Low

**Path Aliases Not Normalized (AUDIT-4)**  
`check_noamp` uses string matching. `file:///a/../a/b` and `file:///a/b` are
different strings. Path traversal may not be caught if the string doesn't
match the expected scope pattern.

---

## 6. Security Invariants

These invariants hold **under the same-process assumption** (i.e., assuming
tool code does not directly manipulate `broker.store`):

1. **Authorization is mandatory:** No effect is applied unless
   `broker.commit()` returns `(True, _)` — i.e., all four predicates pass
   and `boundary_stop is None`.

2. **Nonces are single-use:** A nonce can only be consumed once per task.
   Replay of the same nonce within the same task is blocked by `check_fresh`.

3. **Flows are monotonic:** An effect's confidentiality and integrity labels are
   preserved through the `check_flow` predicate. UNTRUSTED data cannot
   inherit USER integrity without explicit endorsement.

4. **Scope is contained:** `check_noamp` ensures that BCC recipients and
   additional targets are within the capability's declared scope.

5. **Session state is authoritative:** Within a given session, the broker's
   `nonce_used` set is the authoritative record of consumed nonces.

6. **Mediation is advisory:** The `Mediator.inspect()` verdict is consulted
   after predicates pass. If the mediator blocks, the commit is rejected.
   If the mediator allows, the commit proceeds (predicates permitting).

---

## 7. Claims That Are NOT Made

The following are **NOT** properties of ECAC, even in the full-system deployment:

- ❌ ECAC provides process isolation
- ❌ ECAC prevents all side-channel attacks
- ❌ Approved requests are bound to exact effect content
- ❌ A read-capability cannot be used for write (if `right="*"`)
- ❌ Capabilities are always scoped to their issuing task (if `task_id=None`)
- ❌ Closing a session permanently halts a task
- ❌ ECAC evaluates real provenance from actual tool invocations
- ❌ Path traversal is always caught by `check_noamp`
- ❌ Exactly-once delivery (without a provider/recovery contract)

---

## 8. Comparison with Related Systems

| Property                | ECAC (M3)               | PACT (M2)                  | Tool Allowlist (M1) |
| ----------------------- | ----------------------- | -------------------------- | ------------------- |
| Authorization timing    | Commit-time             | Call-time                  | Pre-registration    |
| Atomic re-validation    | ✅ (nonce + flow check) | ❌ (binding can be reused) | ❌ (name spoofable) |
| Provenance binding      | ✅ (effect-scoped)      | ✅ (argument-scoped)       | ❌                  |
| BCC recipient check     | ✅ (check_noamp)        | ❌                         | ❌                  |
| Nonce/Freshness         | ✅ (atomic, per-task)   | ❌                         | ❌                  |
| Same-process limitation | ⚠️ (documented)         | ⚠️ (similar)               | ⚠️ (similar)        |
| Isolated executor       | ❌ (future work)        | ❌                         | ❌                  |
| Provenance authenticity | ⚠️ (assumed)            | ⚠️ (assumed)               | ❌                  |

ECAC's advantage over M1/M2 is the **atomic commit-time re-validation**:
all four predicates are checked together, in the broker's authoritative state,
before any effect is applied. The disadvantage is the same-process mode and
the need for a real shim to construct provenance.

---

## 9. Deployment Guidance

### Development / Evaluation (current)

Same-process mode: broker + store in one Python process.

```
USE CASE: local testing, CI/CD, eval_comparison.py runs
RISK: tool code can bypass broker.commit() by direct store access
MITIGATION: none — this is evaluation-only mode
```

### Production (recommended)

Isolated executor: broker in one process, executor/store in a separate process
or enclave.

```
USE CASE: production AI agent deployments
REQUIREMENT: broker and executor must communicate via IPC (not shared memory)
REQUIREMENT: executor must verify broker authorization before applying effects
RECOMMENDED: seccomp/SELinux sandbox for the executor process
```

### Production with Hardware Enclave

```
USE CASE: high-assurance deployments
RECOMMENDED: Intel SGX or AMD SEV for executor enclave
BENEFIT: even root cannot read enclave memory or inject effects
```

---

_Last reviewed: [session date] — against audit-findings.md AUDIT-1 through AUDIT-6._

===================================================================

# Part II — Formal Invariant Specification

===================================================================

# Formal Invariant Specification — ECAC Effect Broker

**Document type:** Formal specification (Phase-1 foundation)  
**Version:** 0.1  
**Status:** In progress — executable model matches spec; proof of consistency To Be Determined

---

## 1. Formal Types

We define the following types with precise semantics:

### Principals

```bash
P ∈ Principals ::= User | Agent | ToolAdapter | EffectBroker | Approver
```

- `User` — source of all authority; trusted root
- `Agent` — untrusted LLM; proposes effects only
- `ToolAdapter` — untrusted third-party code; implements effects
- `EffectBroker` — trusted kernel; the only principal that can invoke `commit`
- `Approver` — optional human escalation; grants one-shot approvals

### Resources

```bash
R ∈ Resources ::= File(path) | Email(addr) | Mailbox(id)
```

- `File(path)` — file system resource identified by canonical path
- `Email(addr)` — email address `user@domain`
- `Mailbox(id)` — mailbox identifier `inbox://user` or `outdoor://user`

### Primitive Effects

```bash
E ∈ Effects ::= Read(r) | Write(r, v) | Send(addr, subj, body)
              | Delete(r) | Network(url) | Commit(eff, t)
```

Only `Commit(eff, t)` is a **mutation effect** — it is the sole operation that
changes external state. All other effects are _prepared effects_ (staged, not committed).

### Labels (MLS Lattice)

**Confidentiality** (ordered by increasing sensitivity):

```bash
C ∈ Confidentiality ::= UNCLASSIFIED < INTERNAL < CONFIDENTIAL < SECRET
```

**Integrity** (ordered by decreasing trust):

```bash
I ∈ Integrity ::= UNTRUSTED < STANDARD < USER < TRUSTED
```

The lattice: `UNCLASSIFIED ⊑ INTERNAL ⊑ CONFIDENTIAL ⊑ SECRET` and
`UNTRUSTED ⊑ STANDARD ⊑ USER ⊑ TRUSTED`.

### Sessions and Tasks

```bash
S ∈ Session = {session_id, logical_time, revoked, used, tainted, send_count}
T ∈ Task = {task_id, owner, ceiling, session, flow_boundary}
```

- `ceiling: Capability` — the task's upper bound on authority (scope, right, target)
- `flow_boundary: (C, I)` — the task's declared sink confidentiality and integrity
- `session.tainted: bool` — true if session has read CONFIDENTIAL data without declass

### Capabilities (Object-Capability Style)

```bash
Cap = {
    owner: Principals,     # trusted root who issued this cap
    holder: Principals,    # principal holding this cap
    right: Rights,         # what right this cap grants
    target: Resources,    # which resource
    scope: set[ScopeLabel], # domain-level scope (e.g. {"internal", "file:///data"})
    nonce: Nonce,          # unique identifier for this cap
    derives_from: Nonce?,  # nonce of parent cap (None for root grants)
    expiry: Time,          # expiration timestamp
    task_id: TaskId?       # task to which this cap is bound (optional)
}
```

Key property: **monotonic attenuation**. A child capability `c'` derives from parent `c`
iff `c'.scope ⊆ c.scope` AND `c'.right ⊆ c.right` AND `c'.target ⊆ c.target`.

### Data Provenance

```bash
D ∈ Data = {name, confidentiality, integrity}
```

Each prepared effect carries provenance `P ⊆ Data` — the data it operates on.
This enables IFC checks without trusting the LLM's semantic claims.

### Authorization Exceptions

```bash
Exc = {kind: {declass, endorse}, from_label, to_label, targets, task_id, nonce}
```

- `declass(from_l, to_l)` — lowers confidentiality from `from_l` to `to_l`
- `endorse(from_l, to_l)` — raises integrity from `from_l` to `to_l`
- Only `EffectBroker` can record exceptions (never LLM)
- Exception must specify complete target set (no partial declass)

---

## 2. Core Invariant

**Theorem (Effect-Complete Authority Confinement).**

For all effects `e`, tasks `t`, and time `τ`:

```bash
commit(e, t) at τ  ⟹  Auth(e, t) ∧ FlowOK(e, t) ∧ NoAmp(e, t) ∧ Fresh(e, τ)
```

Where the four predicates are defined below.

### Auth(e, t) — Authority Derivation

```bash
Auth(e, t) = ∃ cap ∈ Caps . cap.nonce = e.nonce
             ∧ is_root_anchored(cap)
             ∧ is_monotonic_chain(cap)
             ∧ cap.task_id ⊆ t.task_id
             ∧ cap.right ⊇ e.right
             ∧ cap.target ⊇ e.target
             ∧ cap.scope ⊇ target_scope(e.target)
```

Where:

- `is_root_anchored(cap)`: `cap.owner ∈ TRUSTED_ROOTS` and the derivation chain
  terminates at a root grant
- `is_monotonic_chain(cap)`: every `cap' derives_from cap.parent` satisfies
  `cap'.scope ⊆ cap.parent.scope` and `cap'.right ⊆ cap.parent.right`
- `target_scope(File(p)) = {canonical_parent_directory_of(p)}`
- `target_scope(Email(a)) = {domain_of(a)}`

**Security property:** Authority cannot be created from nothing. A forged
capability (owner ∉ TRUSTED_ROOTS) fails root-anchoring. Delegation widening
(failed monotonicity) fails the chain check.

### FlowOK(e, t) — Information Flow Control

```bash
FlowOK(e, t) = (∀ d ∈ e.provenance .
                 d.confidentiality ⊑ t.sink_confidentiality
                 ∨ ∃ exc ∈ Exceptions . exc.kind = declass
                    ∧ exc.from_label ⊒ d.confidentiality
                    ∧ exc.to_label ⊑ t.sink_confidentiality
                    ∧ exc.targets ⊇ e.target)
               ∧ (∀ d ∈ e.provenance .
                 d.integrity ⊒ t.sink_integrity
                 ∨ ∃ exc ∈ Exceptions . exc.kind = endorse
                    ∧ exc.from_label ⊑ d.integrity
                    ∧ exc.to_label ⊒ t.sink_integrity
                    ∧ exc.targets ⊇ e.target)
               ∧ ¬(t.session.tainted ∧ e.etype = send)
```

**Key properties:**

1. No unauthorized confidentiality downgrade without explicit declass
2. No unauthorized integrity upgrade without explicit endorse
3. Session taint: send effects after CONFIDENTIAL read require declass
   (this is the inter-effect composition guard — see Section 4)

### NoAmp(e, t) — No Authority Amplification

```bash
NoAmp(e, t) = target_scope(e.target) ⊆ t.ceiling.scope
             ∧ (t.ceiling.right = * ∨ t.ceiling.right = e.right)
             ∧ (e.etype = send → t.session.send_count < t.session.max_sends)
             ∧ (e.etype = network → domain(e.target) ⊆ t.ceiling.scope)
             ∧ (∀ extra ∈ e.extra_targets . target_scope(extra) ⊆ t.ceiling.scope)
```

**Security property:** Effect authority is bounded by the task ceiling.
Authority cannot be widened through transformation or delegation.

#### Which transformations preserve provenance

The property above says authority may not be _widened_ by a transformation;
the table below makes explicit when a transformation preserves a datum's
provenance (and therefore its labels) at all. Implemented as a
machine-readable table with a test per row in
`effect_broker/provenance_transforms.py` (`PROVENANCE_TRANSFORMS`).

**Rule.** A transformation preserves provenance iff **(1)** its output is a
deterministic function of its inputs, and **(2)** every byte of the output is
attributable to a byte of an input. Anything that invents content breaks it.

| Transformation                        | Provenance                   | Why                                                                                                                |
| ------------------------------------- | ---------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| identity                              | preserved                    | output is the input                                                                                                |
| slice / substring                     | preserved                    | subset of input bytes; cannot add information. Does **not** lower the label                                        |
| concat                                | preserved, **labels joined** | attributable to all inputs ⇒ confidentiality MAX, integrity MIN — never the primary input's labels                 |
| lossless decode (utf-8, json, base64) | preserved                    | injective or narrower                                                                                              |
| **lossy decode** (`errors="replace"`) | **broken**                   | substitutes bytes absent from the input                                                                            |
| re-encode / format                    | preserved                    | same information content (format is the boundary case: if the formatter may rewrite tokens, treat it as summarise) |
| hash / encrypt                        | preserved, opaque datum      | content unreadable but the label still travels — **encryption is not declassification**                            |
| **model-generate**                    | **broken**                   | invents content; always UNTRUSTED                                                                                  |
| **summarise**                         | **broken**                   | selects and rewrites; summary of CONFIDENTIAL data is CONFIDENTIAL _and_ UNTRUSTED                                 |
| **translate**                         | **broken**                   | emits target-language tokens absent from the input                                                                 |

Enforcement does not live in the table. `Session.is_trusted_provenance()`
requires the recorded confidentiality and integrity to match the datum's, so a
transformation that drops `provenance_id` yields an UNTRUSTED datum, and one
that keeps a stale `provenance_id` after changing content is rejected by the
content and label binding.

### Fresh(e, τ) — Freshness and Revocation

```bash
Fresh(e, τ) = τ < cap.expiry
             ∧ e.nonce ∉ session.used
             ∧ e.nonce ∉ session.revoked
```

**Security property:** Stale or revoked capabilities cannot be reused.
Nonce reservation is atomic (per-task lock) to prevent race-condition replays.

---

## 3. Session Taint: Inter-Effect Composition

**Attack pattern (T20):**

```bash
Step 1: Agent reads CONFIDENTIAL file → session.tainted = true
Step 2: Agent sends email to external → FlowOK blocks (session-taint)
```

This is the **conservative** inter-effect guard. It operates at session level,
not at data-value level. Once ANY CONFIDENTIAL file is read in a session,
ALL subsequent sends require explicit declass — even for legitimate workflows.

**Why session-level and not value-level?**
Value-level taint tracking (dataflow analysis of which specific values flow
where) requires language-level support beyond what the four-predicate model
provides. Session-level taint is a pragmatic defense-in-depth: it is
correct (no false negatives), if conservative (may require explicit declass
for legitimate workflows).

**Formal treatment:**

```bash
state_update: read(File(p)) at τ
  → session.tainted = true
  → session._taint_reason = f"read-confidential({p})"

FlowOK(e, t) includes:
  t.session.tainted ∧ e.etype = send  ⟹  false
  (unless declass exception exists)
```

**Lifting taint:**
Taint can only be lifted by a broker-recorded declass exception:

```bash
grant_label_exception(declass, from_label=CONFIDENTIAL, to_label=INTERNAL,
                       targets={primary_target}, task_id=t.task_id)
  → session.tainted = false (only for matching task_id)
```

Cross-task declass does NOT clear taint in the original task (correct isolation).

---

## 4. Provenance Tracking

Each effect carries explicit provenance `Data(name, confidentiality, integrity)`.
This enables IFC checks without trusting LLM semantic claims.

**Design rules:**

1. Provenance is set by the **kernel**, not the LLM or tool
2. For `read(file:///secrets)` → `Data("content", CONFIDENTIAL, USER)`
3. For `send(addr)` → `Data("msg", sink_confidentiality, sink_integrity)`
4. LLM's provenance claims are **ignored** — kernel determines provenance from
   resource labels, not from effect metadata

This ensures the theorem is **independent of LLM behavior**: even if the LLM
claims a CONFIDENTIAL file read has INTERNAL provenance, the kernel overrides
this based on the file's actual label.

---

## 5. TCB Boundary

```bash
TRUSTED (EffectBroker process):
  - Capability store (issuance/checking)
  - IFC engine (FlowOK)
  - Declass/endorse validator
  - Freshness/revocation checker (Fresh)
  - Effect broker (commit gate)
  - Independent ledger (verification)
  - Session/Task state (for taint, nonce tracking)

UNTRUSTED (outside TCB):
  - LLM (proposes effects, never commits)
  - Retrieved content (may be adversarial)
  - Memory/risk model (may be corrupted)
  - Tool descriptions (may be false — mitigated by ToolRegistry)
  - Third-party tool code (guarantee stops at broker→tool boundary)
```

**Key invariant:** `commit` is the ONLY path to external state mutation.
Only `EffectBroker` can invoke `commit`. The LLM, tools, and adapters are
outside the TCB and cannot bypass this.

---

## 6. Executable Consistency

The executable kernel (`effect_broker/`) is a Python implementation of the
formal model above. Consistency means:

```bash
∀ e, t, τ . [executable broker.gate(e, t) = ALLOW]  ⟺  [formal predicate holds]
```

**Current status:** The four predicates `Auth`, `FlowOK`, `NoAmp`, `Fresh`
are implemented in `broker.py` as `check_auth()`, `check_flow()`, `check_noamp()`,
`check_fresh()`. Tests verify that they match the formal specification for
all 20 adversarial traces.

**Formal proof of consistency:** Pending (Phase-2 goal). Approaches:

1. Model-based testing with exhaustive state-space exploration (small kernel)
2. Additional formal verification (deferred)
3. Coq/Lean proof of consistency between formal spec and Python implementation

---

## 7. Kill Criteria Check

| Criterion                                     | Status | Evidence                                          |
| --------------------------------------------- | ------ | ------------------------------------------------- |
| Theorem requires trusting LLM semantic claims | ✅ No  | Provenance set by kernel, not LLM                 |
| Tool/adaptor code inside TCB                  | ✅ No  | Shims are thin wrappers; multi-process isolation  |
| Property already in PACT/ChainCaps/FIDES      | ✅ No  | M1: 0/18, M2: 1/18, M3: 18/18                     |
| Security requires blocking all benign work    | ✅ No  | Benign tasks still work; declass mechanism exists |
| Conventional ACL achieves same frontier       | ✅ No  | M3 distinction proven                             |

**Conclusion:** No kill criteria triggered. Project should continue.

---

## 8. Open Formal Questions

1. **Inter-effect taint granularity:** Session-level taint is conservative.
   Value-level (dataflow) tracking would be more precise but requires language
   support. Open question: can we express this in the formal model without
   embedding a type system?

2. **Cross-task authority propagation:** If the same capability is valid across
   tasks, a sequence of effects across task boundaries is not tracked by the
   current model. This requires task isolation beyond process isolation.

3. **Temporal declass/endorsement:** The current model allows declass at any
   time. Formal treatment of timed declass windows (declass only valid for
   τ ∈ [start, end]) is deferred.

4. **Compositionality:** The theorem is stated for single-effect commits.
   Compositionality (if `commit(e₁)` and `commit(e₂)` separately satisfy the
   invariant, does `commit(e₁); commit(e₂)` also satisfy it?) is an open
   question. Session taint provides a partial answer for send-after-read.

===================================================================

# Part III — Formal Semantics

===================================================================

# Formal Semantics — ECAC

**Purpose:** Machine-actionable semantics for the completion theorem and the held-out experiment.
Not prose. Formal enough to prove against, falsifiable in the experiment.

---

## 1. System State

```bash
S = (Capabilities, Nonces, Sessions, Store, Ledger)
```

| Component    | Type                           | Mutable?                    | Notes                                  |
| ------------ | ------------------------------ | --------------------------- | -------------------------------------- |
| Capabilities | Map[Nonce, Cap]                | Yes — issued by broker only | root-anchored, monotonic, task-bounded |
| Nonces       | Set[Nonce]                     | Yes — consumed per task     | Fresh check: nonce ∉ consumed(t)       |
| Sessions     | Map[SessionID, Session]        | Yes — open/close            | closed(t) → no more commits            |
| Store        | ExternalState                  | Yes — via apply_effect only | effects_log + identity_log append-only |
| Ledger       | (Authorizations, Observations) | Append-only                 | verify() returns CONFIRMED / UNKNOWN   |

**Immutability:** Capabilities, Nonces, Sessions are broker-internal. No untrusted code can modify them.
**Store mutability:** ONLY via `Store.apply_effect(e)` — the sole mutation point.

---

## 2. Effect Language

```
PrimitiveEffect ::= READ(target) | WRITE(target, content)
                  | SEND(to, body, extras)
                  | DELETE(target)
                  | NETWORK(url)

PreparedEffect  ::= {etype, target, content?, extras, provenance, nonce, delegation_chain, known_targets}
CommittedEffect ::= PreparedEffect that passed the gate
Effect          ::= PrimitiveEffect | PreparedEffect | CommittedEffect
```

**Invariant (Effect Well-Formedness):**

```
EF1: etype ∈ {read, write, send, delete, network}
EF2: target is a valid resource identifier (file://, mailto:, https://)
EF3: known_targets.primary = target
EF4: known_targets.additional ⊆ {all resources this effect actually touches}
EF5: capability_nonce refers to a real nonce in Capabilities or an approval nonce
EF6: delegation_chain[0] is the tool name (not forgeable by the LLM — set by shim)
```

---

## 3. Commit Operation

### 3.1 Commit(e: PreparedEffect, t: Task) → (Bool, Evidence)

```
PRECONDITIONS:
  1. t.session_id is open (Sessions[t.session_id].state = OPEN)
  2. t.task_id is registered in the broker
  3. Store.apply_effect is callable ONLY via the executor path (enforced by architecture)

POSTCONDITIONS (if returns True):
  4. Auth(e, t) = true
  5. FlowOK(e, t) = true
  6. NoAmp(e, t) = true
  7. Fresh(e, t) = true
  8. authority(e) ≤ ceiling(t)
  9. Store.apply_effect(e) was called — exactly once
 10. Ledger.record_authorization(t.task_id, e.capability_nonce, ...) recorded
 11. Ledger.record_observation(t.task_id, e.capability_nonce, ...) recorded
 12. Store.effects_log.append((e.etype, e.target))
 13. Store.identity_log.append(complete_targets(e))

POSTCONDITIONS (if returns False):
 14. At least one of (4..8) is false
 15. Store.apply_effect was NOT called
 16. Ledger records authorization only (for bypass detection: auth-without-obs → UNKNOWN)
```

### 3.2 The Four-Predicate Gate

```
Auth(e, t):
  A1: ∃ cap ∈ Capabilities: cap.holder = tool_name OR cap.holder = "EffectBroker"
  A2: cap.right = e.etype  OR  cap.right = "*"
  A3: cap.target ⊆ canonical_targets(e)         [right-strict: read-cap cannot authorize write]
  A4: cap.expiry > now(t)
  A5: cap.task_id = t.task_id  OR  cap.task_id = None    [task-scoping]
  A6: cap.owner is a trusted root (not Mallory/untrusted)
  A7: cap.rights_scope ⊆ cap.parent.rights_scope         [monotonic delegation]
  → return (A1 ∧ A2 ∧ A3 ∧ A4 ∧ A5 ∧ A6 ∧ A7)

FlowOK(e, t):
  F1: ∀ datum ∈ e.provenance: datum.integrity ≥ MIN_INTEGRITY(e.etype, e.target)
  F2: ∀ datum ∈ e.provenance: datum.confidentiality ≥ MIN_CONFIDENTIALITY(e.target)
  F3: e.etype ≠ send → no UNTRUSTED datum in e.provenance is used as authority
  → return (F1 ∧ F2 ∧ F3)

NoAmp(e, t):
  N1: e.known_targets.additional ⊆ cap.scope            [scope containment]
  N2: ∀ r ∈ e.known_targets.additional: domain(r) ∈ cap.scope_domains
  N3: e.etype ≠ send  OR  all recipients satisfy N1 ∧ N2   [BCC check]
  → return (N1 ∧ N2 ∧ N3)

Fresh(e, t):
  R1: e.capability_nonce ∉ Nonces.consumed(t.task_id)
  R2: e.expiry > now(t)  OR  e is an approval nonce (consumed after use)
  → return (R1 ∧ R2)
```

### 3.3 Authority Ordering

```
authority(e) ≤ ceiling(t)   ↔
  max_confidentiality(e) ≤ ceiling(t).max_confidentiality  ∧
  min_integrity(e)       ≥ ceiling(t).min_integrity        ∧
  scope(e)               ⊆ ceiling(t).scope
```

---

## 4. TCB Boundary (Formally)

```
TCB Components (can modify S):
  - EffectBroker.commit()         — gate check, ledger records
  - IsolatedExecutor.execute()    — sole mutation path orchestrator
  - RestrictedResourceStore.apply_effect() — sole external state mutation

NOT in TCB (cannot modify S):
  - Tool code (any Python module the agent imports)
  - LLM / prompt / instruction
  - Retriever / memory
  - Tool adapter (transforms tool calls into Effects)
  - Effect.provenance field (set by adapter, not trusted)
  - Effect.content field (opaque to broker)
  - Mediator.inspect() (advisory, not binding)

Architectural enforcement:
  - Same-process: RestrictedResourceStore._data is not directly accessible (TypeError on mutation)
  - Multi-process: broker has no reference to store; executor is a subprocess
```

---

## 5. The Central Invariant (Theorem Statement)

### ECAC-Completion Theorem

```
Theorem (ECAC-Completion):

∀ t ∈ Tasks, ∀ e ∈ CommittedEffects:
  1. observer(e) = true                    [effect reached external state]
  2. ∃ e' ∈ PreparedEffects:
       corresponds(e, e')                  [e' is the broker's view of e]
       ∧ Auth(e', t)                       [A1..A7]
       ∧ FlowOK(e', t)                     [F1..F3]
       ∧ NoAmp(e', t)                      [N1..N3]
       ∧ Fresh(e', t)                      [R1..R2]
       ∧ authority(e') ≤ ceiling(t)         [within task ceiling]
  3. S.effects_log contains (e.etype, e.target)      [committing executor applied it]
  4. S.identity_log contains complete_targets(e)     [BCC/extra targets logged]

Soundness:
  If broker.commit(e') returns False, then
    ∀ observers: observer reports no committed effect corresponding to e'.

Completeness:
  If Auth ∧ FlowOK ∧ NoAmp ∧ Fresh ∧ authority ≤ ceiling,
    and the shim derived e' from the REAL resource,
    then ∃ committed e: corresponds(e, e') ∧ observer(e) = true.
```

### ECAC-Authority-Non-Amplification Theorem

```bash
Theorem (ECAC-Authority-Non-Amplification):

Authority cannot increase through transformation or delegation.

Formally:

1. Capability Derivation (Root-Anchored, Monotonic):
   ∀ cap, cap' ∈ Capabilities:
     cap' derived_from(cap)
     → authority(cap') ≤ authority(cap)

   Where authority(cap) ≜ (cap.scope, cap.right, cap.target)
   And "≤" is pointwise: scope ⊆, right ⊆, target ⊆.

2. Capability Granting:
   ∀ t ∈ Tasks, ∀ cap ∈ GrantedCapabilities(t):
     cap.owner ∈ {User, Approver, EffectBroker}   [trusted root]
     ∧ cap.delegation_chain ⊆ {User, Approver, EffectBroker, Agent, Broker, Tool}
     ∧ cap.delegation_chain is non-widening        [sub-check 2 in Auth]

3. No Authority Self-Creation:
   The LLM may propose, request, or argue.
   The LLM cannot create, derive, or grant authority.
   Any capability with owner ∉ {User, Approver, EffectBroker} and
   not registered via grant_root() is invalid at Auth.

4. Effect-Level:
   ∀ e ∈ CommittedEffects:
     Auth(e, t) → authority(e) ≤ ceiling(t)
     NoAmp(e, t) → effect.target ∈ ceiling.scope ∧ effect.extra_targets ⊆ cap.scope
```

### ECAC-No-Unauthorized-External-Effect Theorem

```bash
Theorem (ECAC-No-Unauthorized-External-Effect):

No externally committed effect commits without valid authority.

Formally:

∀ e ∈ CommittedEffects:
  ∃ cap ∈ Capabilities:
    cap.nonce = e.capability_nonce
    ∧ Auth(e, task_of(cap))          [root-anchored derivation]
    ∧ cap.owner ∈ TRUSTED_ROOTS       [{User, Approver, EffectBroker}]
    ∧ task_of(cap).session.live = true
    ∧ e.capability_nonce ∉ task_of(cap).session.revoked
    ∧ e.capability_nonce ∉ task_of(cap).session.used

Corollary: Forbidden confidentiality/integrity flows cannot commit
           without explicit broker-recorded LabelException(grant=True).
           FlowOK(e, t) ∧ LLM_endorsement(e) is insufficient;
           broker.grant_label_exception() is required.
```

---

## 6. Proof Obligations

For each predicate, state what must hold for the theorem to be true:

### Auth

| Obligation | Statement                                           | Who ensures it                        |
| ---------- | --------------------------------------------------- | ------------------------------------- |
| PO-A1      | No capability can be created by tool code           | Broker is the only issuer             |
| PO-A2      | Right-strict: read-cap cannot authorize write       | check_auth enforces exact right match |
| PO-A3      | Task-scoping: cap.task_id = None cannot escape task | Auth sub-check 5                      |
| PO-A4      | Monotonicity: child cap rights ⊆ parent rights      | Auth sub-check 7                      |
| PO-A5      | Root-anchoring: Mallory cannot be a root            | Auth sub-check 6                      |

### FlowOK

| Obligation | Statement                                                        | Who ensures it                            |
| ---------- | ---------------------------------------------------------------- | ----------------------------------------- |
| PO-F1      | Provenance labels are set by trusted labeler                     | Shim or broker resolver (not LLM)         |
| PO-F2      | UNTRUSTED datum cannot be used as authority in privileged action | FlowOK F3                                 |
| PO-F3      | Declassify/endorse is broker-exclusive                           | EffectBroker.\_declassify, \_endorse only |

### NoAmp

| Obligation | Statement                                                     | Who ensures it                  |
| ---------- | ------------------------------------------------------------- | ------------------------------- |
| PO-N1      | known_targets.additional is complete (no hidden targets)      | Shim derives from REAL resource |
| PO-N2      | Scope containment check covers ALL extra targets              | NoAmp sub-check 1               |
| PO-N3      | BCC recipients are visible in the broker's complete_targets() | Shim sends to broker, not MTA   |

### Fresh

| Obligation | Statement                                   | Who ensures it                        |
| ---------- | ------------------------------------------- | ------------------------------------- |
| PO-R1      | Nonce generation is unguessable             | UUID4 / crypto RNG                    |
| PO-R2      | Nonce consumption is atomic (per-task lock) | broker.\_atomic_fresh_check           |
| PO-R3      | Session close is authoritative              | Session.state = CLOSED → gate rejects |

### TCB

| Obligation | Statement                                                     | Who ensures it                           |
| ---------- | ------------------------------------------------------------- | ---------------------------------------- |
| PO-T1      | executor.apply_effect is sole store mutation path             | Architecture: ADR-003                    |
| PO-T2      | Shim is the only path from tool to executor                   | FileShim only; no direct executor access |
| PO-T3      | Same-process: Direct store mutation returns UNKNOWN, not safe | Ledger.verify()                          |

---

## 7. Falsifiable Conditions

For the held-out experiment, these are the conditions that would falsify the theorem:

```
FALSIFY-1: ∃ committed e where Store.effects_log has (e.etype, e.target)
           but Ledger.verify(e.nonce) = UNKNOWN
           → Bypass: effect reached state without going through executor

FALSIFY-2: ∃ committed e where Auth(e) = true but authority(e) > ceiling(t)
           → Authority amplification: effect exceeded task ceiling

FALSIFY-3: ∃ committed e where FlowOK(e) = false but effect reached Store
           → IFC violation: untrusted content drove high-integrity action

FALSIFY-4: ∃ nonce n reused in two committed effects e1, e2
           → Fresh violation: replay attack succeeded

FALSIFY-5: ∃ committed send(e) where recipient ∉ known_targets.additional
           → NoAmp violation: BCC recipient not in broker's complete_targets
```

Each FALSIFY-n has a corresponding test in `tests/test_regressions.py`.

---

## 8. Formalization Notes for Proof Assistant

If proving in Coq/Lean⁺:

```
Inductive state : Type :=
  | S (caps: map nonce cap)
      (nonces: set nonce)
      (sessions: map session_id session)
      (store: store)
      (ledger: ledger).

Inductive commit_result : Type :=
  | CommitAllow (e: effect) (s': state) (evidence: evidence)
  | CommitBlock (e: effect) (reason: block_reason) (evidence: evidence).

Axiom commit_respects_gate: ∀ s e t evidence,
  commit s e t = CommitAllow e s' evidence →
    Auth e t ∧ FlowOK e t ∧ NoAmp e t ∧ Fresh e t ∧ authority e ≤ ceiling t.

Axiom single_mutation_path: ∀ s e s',
  apply_effect s e = s' →
    ∃ executor: executor.execute(s, e) = (Allow, _) ∧
    store.apply_effect(s, e) = s'.

Axiom ledger_unknowable_bypass: ∀ s e t,
  ledger.verify(s.ledger, t, e.nonce) = UNKNOWN →
    ¬∃ committed e': corresponds(e, e') ∧ Auth e' t.
```

===================================================================

# Part IV — TCB Size Measurement

===================================================================

# TCB Size Measurement — ECAC EffectBroker

**Date:** Week 3, Month 1
**Status:** Complete

## Question

How large is the TCB for EffectBroker's security-critical enforcement logic?

## Scope

**In scope (core allow/deny decision):**

- `broker.py` — gate + 4 predicates (Auth, FlowOK, NoAmp, Fresh)
- `model.py` — trusted data types (Effect, Capability, Task, etc.)
- `executor.py` — sole mutation path (ADR-003)
- `restricted_store.py` — enclave proxy for state

**Out of scope:**

- `ledger.py` / `ipc.py` — independent observer, not in allow/deny path
- `mediation.py` — boundary enforcement (T13/T14/T15)
- `baselines/mode_*.py` — baseline comparators, not our TCB
- `bin/eval-baseline` — evaluation harness

## Numbers

### By file

| File                |    Total |     Code | Docstring | Comment |   Blank |
| ------------------- | -------: | -------: | --------: | ------: | ------: |
| broker.py           |     2037 |     1017 |       463 |     294 |     263 |
| model.py            |     1435 |      595 |       467 |     127 |     246 |
| executor.py         |      685 |      285 |       215 |      84 |     101 |
| restricted_store.py |      476 |      266 |        93 |      28 |      89 |
| **Core TCB**        | **4633** | **2163** |  **1238** | **533** | **699** |

"Code" is the metric: non-blank, non-comment, non-docstring lines. Earlier
versions of this table counted docstrings as code, which overstated the
trusted core by 1238 lines (+57%). A docstring is prose in a string literal —
nothing an attacker can exploit — so it belongs with comments, not with logic.

### By enforcement component

| Component                       |      LOC | Purpose                                                             |
| ------------------------------- | -------: | ------------------------------------------------------------------- |
| check_auth                      |      ~84 | Root-anchored, monotonic, task-bounded capability verification      |
| check_flow                      |      ~24 | IFC: confidentiality/integrity against task flow_boundary           |
| check_noamp                     |     ~110 | Composition safety: ceiling scope, BCC recipients, SSRF containment |
| check_fresh                     |      ~51 | Lifetime, revocation, replay prevention (atomic, per-task)          |
| gate() orchestration            |     ~155 | Predicate ordering, approval binding, boundary mediation dispatch   |
| \_atomic_fresh_check + rollback |      ~31 | Thread-safe nonce reservation                                       |
| **Subtotal: 4-predicate gate**  | **~455** | **Formal allow/deny decision**                                      |

### State management (sibling to gate, not its logic)

| Component                            |  LOC |
| ------------------------------------ | ---: |
| commit() wrapper                     |  ~25 |
| \_apply_effect()                     |  ~25 |
| Capability/revocation/infrastructure | ~250 |

## Comparison with related work

| System                   | TCB Size     | Notes                               |
| ------------------------ | ------------ | ----------------------------------- |
| seL4 microkernel         | 9,400 LOC    | Formally verified, C                |
| WebAssembly sandbox      | ~5,000 LOC   | Production, sandboxing              |
| PACT prototype           | ~1,000 LOC   | From paper Fig. 6                   |
| **ECAC core predicates** | **~455 LOC** | Python, prototype                   |
| **ECAC full broker.py**  | **824 LOC**  | With infrastructure + documentation |

## Interpretation

The core 4-predicate gate (~455 LOC Python) makes the allow/deny decision.
This is a small, auditable surface. The full broker.py (~824 LOC) includes
capability management, task registration, and ledger plumbing.

The comparison with PACT (~1,000 LOC in their prototype) suggests ECAC's
predicate logic is competitive in size while adding:

- Atomic freshness (PACT has no commit-time nonce consumption → replay possible)
- BCC scope containment (PACT has no extra-target checking)
- Independent ledger (PACT has no observer verification)

## Limitations

- Python (not memory-safe). A production deployment requires the enclave
  isolation that same-process mode deliberately bypasses.
- Lines-of-code is a proxy, not a proof. The actual TCB is the logic
  in check_auth / check_flow / check_noamp / check_fresh / gate plus the
  data model invariants. Comments and docstrings are not security-critical.

## Action items

- [ ] In production: measure TCB in a memory-safe language (Rust/C)
- [ ] Formal verification target: ~455 LOC gate logic
- [ ] ADR: define what "TCB" means for ECAC in multi-process mode
