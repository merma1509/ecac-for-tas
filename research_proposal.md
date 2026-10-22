# Research Proposal

## Effect-Complete Authority Confinement for Tool Agents

**Author:** [student name — to be filled]
**Supervisor:** [supervisor name — to be filled]
**Program:** Innopolis University, BSc/MSc [select]
**Date:** [fill in]

---

## 1. Problem and Motivation

Large language model (LLM) agents are deployed with tools that mutate external
state: send email, write files, perform network requests. Today's agent
frameworks authorize tool _calls_, not _effects_. A tool call that "reads a
report" may, in practice, also write an exfiltration file, send email to a
hidden recipient, or follow an attacker-controlled symlink. Because the LLM
and third-party tool code are untrusted, any security property that assumes
they truthfully declare their side effects is unsound.

The central research question is whether a _commit-time, effect-complete_
authority confinement guarantee is (1) formally meaningful, (2) novel with
respect to existing defenses, and (3) practically enforceable — preserving
substantially more autonomous utility than coarse blocking or universal human
confirmation.

## 2. Research Gap and Related Work

We position the work against the closest existing defenses and state exactly
what our invariant adds to each:

- **CaMeL / FIDES** — deterministic enforcement and IFC in agent pipelines.
  We adopt their deterministic-enforcement lesson, but bind the check to the
  _primitive effect at commit time_, not to the tool-call argument.
- **PACT / ChainCaps** — provenance, capabilities and attenuation. Closest
  competitors. We add the _monotonic-authority + IFC + commit-time freshness_
  conjunction evaluated on the prepared effect, with all three falsifiable by
  an independent ledger.
- **Progent / AgentSpec / FORGE** — policy DSLs and runtime authorization.
  We do not propose a new DSL; we evaluate a minimal executable kernel and
  show where DSL-level checking is insufficient.
- **Cordon / commit-time authorization** — motivates why proposal-time
  authorization fails. We make commit-time revalidation a first-class gate.
- **AgentDojo / AutoDojo** — realistic benign tasks and adaptive attacks,
  reused for evaluation.
- **MCP security** — schema/implementation mismatch, tool-description
  attacks, hidden side effects. We treat tool descriptions and third-party
  tool code as _untrusted_.

From classical work we build on object-capability security (Miller), IFC
(Myers–Liskov), Biba integrity, Schneider's reference monitors / security
automata, and proof-carrying authorization. The novelty is an agent-specific
property these classical ideas do not already provide: _no externally
committed effect without a machine-checkable, non-amplifying authority
derivation and a valid information-flow derivation, with the LLM and tool
computation outside the trusted computing base._

## 3. Invariant

The core security invariant, evaluated at commit time for every effect `e`
and task `t`:

```
Commit(e, t)  ==>  Auth(e, t) ∧ FlowOK(e, t) ∧ NoAmp(e, t) ∧ Fresh(e, t)
```

| Predicate     | Meaning                                                                                                     |
| ------------- | ----------------------------------------------------------------------------------------------------------- |
| `Auth(e,t)`   | Broker holds a root-anchored capability for `e` (no commit without valid authority)                         |
| `FlowOK(e,t)` | No confidentiality leak and no low-integrity control of privileged actions without explicit declass/endorse |
| `NoAmp(e,t)`  | Authority chain is monotonic from `User`; authority cannot increase through transformation or delegation    |
| `Fresh(e,t)`  | Capability unexpired, unrevoked, not replayed; stale/revoked authority cannot be reused                     |

The LLM may propose actions, arguments, policies, declassification, or
approval requests. It is never allowed to create authority or make the final
security decision. No learned risk classifier appears inside the formal allow
rule; it may trigger escalation or human review, but the theorem stays true
even if the classifier is wrong.

## 4. Trust Model and Trusted Boundary

**Untrusted:** the LLM, retrieved content, memory, risk model, tool
descriptions, and preferably third-party tool code.

**Trusted core (deterministic, minimal):**
capability issuance/checking, IFC/provenance enforcement,
declassification/endorsement validation, freshness/revocation checks, and the
final effect broker.

**Boundary rule (MCP/tool semantics):** we cannot claim security by assuming
every third-party tool truthfully declares its side effects. Either effects
are actually mediated by our broker, or the guarantee explicitly stops at the
remote-tool boundary. In multi-process mode, `RealFileShim` and
`RealEmailShim` are the only code that calls `open()`, `os.write()`,
`smtplib`, or `imaplib`, and effects are derived from real OS/SMTP state.

## 5. Methodology and First-Month Deliverable

**Phase 0 (no large gateway/GUI/DSL):** fix one small domain — email + files.
Define: principals, resources, primitive effects, capabilities/authority,
confidentiality and integrity labels, provenance, delegation/attenuation,
declassification/endorsement, revocation/replay, and the exact trusted
boundary.

**Compare three checking levels:**
tool-call checking → argument/provenance checking → primitive-effect +
commit-time checking.

**First-month end-to-end prototype:**

```
request → untrusted agent/tool proposal → authority derivation → IFC check
→ prepared effect → commit-time revalidation → allow/deny
→ machine-checkable evidence
```

**Implementation path:** closest-baseline reproduction → adversarial traces →
formal semantics → executable trusted kernel → capability attenuation → IFC →
declassification/endorsement → commit-time freshness → email/file/MCP
integration → adaptive attacks → sealed held-out evaluation.

## 6. Adversarial Trace Suite

15–20 adversarial traces covering: prompt injection, confused deputy,
attacker-controlled recipient/path/URL, capability laundering, delegation
widening, confidential-data leakage, low-integrity data controlling
privileged actions, stale approval, replay, declassification/endorsement
abuse, false MCP descriptions, hidden side effects, and attempts to bypass
the monitor.

Kill criteria: stop or radically pivot if (a) the theorem requires trusting
LLM/tool-generated semantic claims; (b) complete mediation requires putting
most tool/adaptor code inside the trusted core; (c) the final property is
already essentially provided by related work; (d) security is achieved only
by blocking most benign work or repeatedly asking the human; (e) a
conventional access-control solution achieves the same security–utility
frontier.

## 7. Evaluation

Metrics: unauthorized committed effects, benign utility, confidentiality /
integrity violations, false denials, approvals, latency/cost, annotation
burden, TCB size. Hold out tasks, attacks, models, policies, tools/MCP
servers and ideally one domain.

Mandatory baselines: ordinary allowlists, call-level policy checking,
argument-level checking, IFC-only, capability-only, strongest existing
defenses (PACT/CaMeL/ChainCaps/FORGE/FIDES/Cordon), and human confirmation
before every sensitive action.

The result must demonstrate, within a clearly stated mediated boundary, that
untrusted agents/tools cannot produce unauthorized committed effects, that
authority cannot be amplified through composition, and that this protection
preserves substantially more autonomous utility than coarse blocking or
universal human confirmation on unseen tools and adaptive attacks. If that
distinction cannot be demonstrated, the project should be narrowed or killed
rather than manufacture novelty.

## 8. Feasibility and Current Prototype

A working executable model already exists in this repository (ECAC kernel):
a four-predicate gate (`Auth and FlowOK and NoAmp and Fresh`), a
`RestrictedResourceStore` as the sole mutation point, and an
`IndependentEffectLedger` that independently falsifies gate vs. execution.
Multi-process enforcement confines real file/email I/O to shims, and the
ledger returns `UNKNOWN` (never "safe") if state may have been mutated
outside the gate.
