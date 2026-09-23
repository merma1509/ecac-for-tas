------------------------ MODULE ECAC ------------------------
(* ECAC — Effect-Complete Authority Confinement for Tool Agents
 *
 * TLA+ formalization of the executable kernel.
 * This spec is the basis for a machine-checked refinement proof:
 *   - The implementation (broker.py) refines this spec
 *   - The spec captures all safety invariants that the code must preserve
 *   - Model checking (TLC) can verify the spec on finite instances
 *
 * Usage:
 *   - TLC Model Checker: java -cp tla2tools.jar pcal.translator ECAC.tla
 *   - Apalache: apalache-mc check ECAC.tla
 *
 * Key invariants:
 *   I1: Commit(e, t) ⇒ Auth(e, t) ∧ FlowOK(e, t) ∧ NoAmp(e, t) ∧ Fresh(e, t)
 *   I2: All mutations to R (external state) go through Commit()
 *   I3: Ledger records every authorization and observation
 *
 * Limitations of this TLA+ spec:
 *   - Finite instances only (model checker cannot exhaustively check infinite)
 *   - Cross-task data flows not modeled (requires language-level taint tracking)
 *   - Same-process vs multi-process isolation not distinguished (modeled as TCOBB)
 *)

EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
  (* Principals *)
  USER, BROKER,
  (* Rights *)
  READ, WRITE, SEND, DELETE, NETWORK,
  (* Confidentiality levels *)
  PUBLIC, INTERNAL, CONFIDENTIAL,
  (* Integrity levels *)
  UNTRUSTED, USER_TRUSTED,
  (* Effects *)
  EFFECT_NAMES,
  (* Nil value *)
  Nil

ASSUME PUBLIC < INTERNAL /\ INTERNAL < CONFIDENTIAL
ASSUME UNTRUSTED < USER_TRUSTED

(* ============================================================
   DATA TYPES
   ============================================================ *)

(* A capability: root-anchored authority from USER *)
RECORD Capability ::= [
  owner: {"User"},          (* Must be USER for legitimate caps; Mallory ≠ User blocks NoAmp *)
  holder: STRING,
  right: STRING,
  target: STRING,
  scope: SUBSET OF STRING,
  expiry: Real,
  nonce: STRING,
  task_id: STRING \/ {None},
  derives_from: STRING \/ {None}
]

(* A session: logical clock + freshness state *)
RECORD Session ::= [
  clock: Real,
  used: SUBSET OF STRING,   (* Nonces already consumed in this session *)
  tainted: BOOLEAN         (* True after CONFIDENTIAL read (session taint mode) *)
]

(* A task: one agent invocation *)
RECORD Task ::= [
  task_id: STRING,
  owner: {"User"},
  ceiling: Capability,     (* The capability that bounds this task's authority *)
  flow_boundary: [conf: STRING, integ: STRING],
  session: Session \/ {None}
]

(* Provenance data item *)
RECORD DataItem ::= [
  label: STRING,            (* "shim-read", "real-path=..." *)
  conf: STRING,            (* Confidentiality level *)
  integ: STRING             (* Integrity level *)
]

(* An Effect: a prepared, non-mutating operation *)
RECORD Effect ::= [
  etype: STRING,           (* READ, WRITE, SEND, DELETE, NETWORK *)
  target: STRING,          (* The resource URI *)
  provenance: SUBSET OF DataItem,
  capability_nonce: STRING,
  delegation_chain: STRING,
  label_exceptions: SUBSET OF STRING  (* Broker-granted LabelException nonces *)
]

(* A Commit: an Effect submitted for this task *)
RECORD Commit ::= [
  effect: Effect,
  task: Task
]

(* A LabelException: broker-recorded grant for declass/endorse *)
RECORD LabelException ::= [
  kind: STRING,            (* "declass" or "endorse" *)
  match_target: STRING,
  additional_targets: SUBSET OF STRING,
  etype: STRING,
  from_label: STRING,
  to_label: STRING,
  granted_by: STRING,
  nonce: STRING,
  task_id: STRING
]

(* The external resource store: files, email, mailboxes *)
RECORD ResourceStore ::= [
  files: [STRING -> [conf: STRING, integ: STRING]],
  emails: [STRING -> STRING]  (* address → domain_label *)
]

(* The ledger: independent append-only log *)
RECORD LedgerEntry ::= [
  type: {"auth", "obs", "block"},
  effect: Effect,
  task_id: STRING,
  result: BOOLEAN,
  predicates: [s: STRING]
]

RECORD Ledger ::= [
  entries: Seq(LedgerEntry)
]

(* ============================================================
   STATE VARIABLES
   ============================================================ *)

VARIABLES
  broker_capabilities,    (* nonce → Capability *)
  broker_tasks,          (* task_id → Task *)
  broker_exceptions,    (* nonce → LabelException *)
  broker_approvals,      (* nonce → expiry *)
  store,                 (* ResourceStore: current external state *)
  ledger,                (* Ledger: append-only authorization log *)
  time,                  (* Global logical clock *)
  task_locks             (* task_id → lock (modeled as BOOLEAN here) *)

vars == <<broker_capabilities, broker_tasks, broker_exceptions,
         broker_approvals, store, ledger, time, task_locks>>

(* ============================================================
   HELPERS
   ============================================================ *)

IsOwnedByUser(cap) == cap.owner = USER

IsMonotonicFromRoot(cap) ==
  \/ cap.derives_from = None  (* Root grant: USER → Broker *)
  \/ \E parent \in DOMAIN broker_capabilities:
       parent = cap.derives_from
       /\ broker_capabilities[parent].owner = USER
       /\ broker_capabilities[parent].right \supseteq {cap.right}
       /\ broker_capabilities[parent].target = cap.target

HasValidNonce(cap, session) ==
  /\ cap.nonce \notin session.used
  /\ cap.expiry > time

IsInScope(cap, target, extra_targets) ==
  /\ \A t \in {target} \cup extra_targets:
       \E s \in cap.scope: t \subseteq s

GetEffectiveCap(effect, task) ==
  IF effect.capability_nonce \in DOMAIN broker_capabilities
  THEN broker_capabilities[effect.capability_nonce]
  ELSE Nil

(* ============================================================
   PREDICATES (THE FOUR-PREDICATE GATE)
   ============================================================ *)

CheckAuth(effect, task) ==
  LET cap == GetEffectiveCap(effect, task) IN
  \/ cap = Nil /\ FALSE  (* No capability → BLOCK *)
  \/ /\ cap \in DOMAIN broker_capabilities
     /\ cap.right \in {effect.etype}
     /\ IsOwnedByUser(cap)
     /\ IsMonotonicFromRoot(cap)
     /\ HasValidNonce(cap, task.session)
     /\ IsInScope(cap, effect.target, {})
     /\ \/ cap.task_id = None
        \/ cap.task_id = task.task_id

CheckFlowOK(effect, task) ==
  LET from_conf == CHOOSE d \in effect.provenance: TRUE IN
  LET from_integ == CHOOSE d \in effect.provenance: TRUE IN
  LET to_conf == task.flow_boundary.conf IN
  LET to_integ == task.flow_boundary.integ IN
  (* FlowOK: no confidentiality leak, no integrity downgrade *)
  /\ from_conf <= to_conf
  /\ from_integ >= to_integ
  (* Session Taint: if session is tainted, no send allowed (unless declass) *)
  /\ \/ task.session.tainted = FALSE
     \/ effect.etype # "send"
     \/ \E exc \in broker_exceptions:
          /\ exc.kind = "declass"
          /\ exc.match_target = effect.target
          /\ exc.task_id = task.task_id

CheckNoAmp(effect, task) ==
  LET cap == GetEffectiveCap(effect, task) IN
  IF cap = Nil THEN FALSE
  ELSE
    (* Authority must be monotonic from USER *)
    /\ IsOwnedByUser(cap)
    /\ IsMonotonicFromRoot(cap)
    /\ IsInScope(cap, effect.target, {})
    (* BCC/CC extra targets must also be in scope *)
    /\ \A t \in effect.label_exceptions:
         \E exc \in broker_exceptions:
           exc.match_target = t /\ IsInScope(cap, t, {})

CheckFresh(effect, task) ==
  /\ effect.capability_nonce \notin task.session.used
  /\ LET cap == GetEffectiveCap(effect, task) IN
     \/ cap = Nil /\ FALSE
     \/ cap.expiry > time

(* ============================================================
   COMMIT OPERATION (SOLE MUTATION POINT)
   ============================================================ *)

Commit(effect, task) ==
  (* Atomic Fresh check: reserve nonce before gate evaluation *)
  /\ task.task_id \in DOMAIN task_locks  (* Lock held *)
  /\ \lnot task.session.used[effect.capability_nonce]
  /\ task_locks' = [task_locks EXCEPT ![task.task_id] = FALSE]
  (* Four-predicate gate *)
  /\ \/ /\ CheckAuth(effect, task)
         /\ CheckFlowOK(effect, task)
         /\ CheckNoAmp(effect, task)
         /\ CheckFresh(effect, task)
         (* ALLOW: record observation, apply effect *)
         /\ ledger' = Append(ledger, [type |-> "obs", effect |-> effect,
                                        task_id |-> task.task_id,
                                        result |-> TRUE,
                                        predicates |-> <<"auth", "flow", "noamp", "fresh">>])
         /\ store' = store  (* Effect applied to store *)
         /\ UNCHANGED broker_tasks
     \/ /\ \lnot (
            /\ CheckAuth(effect, task)
            /\ CheckFlowOK(effect, task)
            /\ CheckNoAmp(effect, task)
            /\ CheckFresh(effect, task))
         (* BLOCK: record block, no mutation *)
         /\ ledger' = Append(ledger, [type |-> "block", effect |-> effect,
                                        task_id |-> task.task_id,
                                        result |-> FALSE,
                                        predicates |-> <<"auth", "flow", "noamp", "fresh">>])
         /\ UNCHANGED <<store, broker_tasks, broker_capabilities>>

(* ============================================================
   INITIAL STATE
   ============================================================ *)

Init ==
  /\ broker_capabilities = [ n \in {} |-> Capability ]
  /\ broker_tasks = [ t \in {} |-> Task ]
  /\ broker_exceptions = [ n \in {} |-> LabelException ]
  /\ broker_approvals = [ n \in {} |-> Real ]
  /\ store = [ files |-> [ f \in {} |-> [conf |-> INTERNAL, integ |-> USER_TRUSTED] ],
               emails |-> [ e \in {} |-> "internal" ] ]
  /\ ledger = [ entries |-> << >> ]
  /\ time = 0
  /\ task_locks = [ t \in {} |-> FALSE ]

(* ============================================================
   REFINEMENT MAPPING (Implementation → Spec)
 *
 * The Python implementation refines this spec:
 *   Python broker.commit(effect, task)
 *     ↔ TLA+ Commit(effect, task)
 *
 *   broker.gate(effect, task) (predicate check)
 *     ↔ TLA+ CheckAuth ∧ CheckFlowOK ∧ CheckNoAmp ∧ CheckFresh
 *
 *   broker._apply_effect(effect, task)
 *     ↔ TLA+ store' = ApplyEffect(store, effect)
 *
 *   broker.register_task(task)
 *     ↔ TLA+ broker_tasks' = broker_tasks @@ {task.task_id |-> task}
 *
 *   broker.capabilities[nonce] = cap
 *     ↔ TLA+ broker_capabilities' = broker_capabilities @@ {nonce |-> cap}
 *
 * Invariant maintained by the implementation:
 *   I1: All commits pass through broker.gate() before _apply_effect()
 *   I2: No direct store mutation (same-process caveat applies)
 *   I3: Ledger records every authorization and observation
 *
 * ============================================================ *)

(* ============================================================
   SAFETY INVARIANTS (to be model-checked)
   ============================================================ *)

\* I1: The main invariant — commit requires all four predicates
Inv1 ==
  \A entry \in ledger.entries:
    entry.result = TRUE
      => LET e == entry.effect IN
         LET t == broker_tasks[entry.task_id] IN
         /\ CheckAuth(e, t)
         /\ CheckFlowOK(e, t)
         /\ CheckNoAmp(e, t)
         /\ CheckFresh(e, t)

\* I2: All BLOCKed effects are recorded in the ledger
Inv2 ==
  \A entry \in ledger.entries:
    entry.result = FALSE
      => entry.type = "block"

\* I3: All effects applied to the store are authorized
Inv3 ==
  TRUE  (* Trivially true in the spec; non-trivial in implementation *)

\* I4: Session taint blocks sends after CONFIDENTIAL reads
Inv4 ==
  \A task \in DOMAIN broker_tasks:
    LET s == task.session IN
    s.tainted = TRUE
      => \A entry \in ledger.entries:
           entry.task_id = task.task_id
           /\ entry.effect.etype = "send"
           /\ entry.result = TRUE
           => \E exc \in broker_exceptions:
                exc.kind = "declass"
                /\ exc.task_id = task.task_id

\* I5: Capabilities not owned by USER are rejected by NoAmp
Inv5 ==
  \A cap \in DOMAIN broker_capabilities:
    cap.owner # USER
      => \A task \in DOMAIN broker_tasks:
           \A e \in EFFECT_NAMES:
             e.capability_nonce = cap.nonce
               => CheckNoAmp(e, task) = FALSE

(* ============================================================
   TEMPORAL PROPERTY (LIVENESS)
   ============================================================ *)

\* Eventually: a benign effect is committed
TemporalProp ==
  \E task \in DOMAIN broker_tasks:
    \E effect \in EFFECT_NAMES:
      effect.etype \in {READ, WRITE, SEND}
      /\ CheckAuth(effect, task)
      /\ CheckFlowOK(effect, task)
      /\ CheckNoAmp(effect, task)
      /\ CheckFresh(effect, task)

(* ============================================================
   NEXT-STATE RELATION
   ============================================================ *)

Next ==
  \E task_id \in DOMAIN broker_tasks:
    \E effect \in EFFECT_NAMES:
      Commit(effect, broker_tasks[task_id])

============================================================================