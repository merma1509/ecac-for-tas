# ECAC TLA+ Formalization

This directory contains the TLA+ specification of the ECAC executable kernel,
providing a machine-checkable basis for the refinement proof.

## Files

| File        | Description                                                                   |
| ----------- | ----------------------------------------------------------------------------- |
| `ECAC.tla`  | TLA+ spec of the four-predicate gate, commit operation, and safety invariants |
| `README.md` | This file                                                                     |

## What's in the spec

**`ECAC.tla`** formalizes:

1. **Data types**: `Capability`, `Session`, `Task`, `Effect`, `Commit`,
   `LabelException`, `ResourceStore`, `Ledger`, `LedgerEntry`

2. **Four-predicate gate** (the core invariant):
   - `CheckAuth(effect, task)` — capability exists, owned by USER, monotonic, in-scope
   - `CheckFlowOK(effect, task)` — confidentiality ≤ boundary, integrity ≥ boundary,
     session not tainted (or declass exception exists)
   - `CheckNoAmp(effect, task)` — authority monotonic from USER, scope covers target
   - `CheckFresh(effect, task)` — nonce not replayed, not expired

3. **Commit operation** (sole mutation point): atomically reserves nonce,
   evaluates all four predicates, records ledger entry, applies effect

4. **Safety invariants**:
   - `Inv1`: Every committed effect passes all four predicates
   - `Inv2`: Every BLOCKed effect is recorded as blocked in the ledger
   - `Inv4`: Session taint blocks sends after CONFIDENTIAL reads (unless declass)
   - `Inv5`: Capabilities not owned by USER are rejected by NoAmp

## How to run

### Apalache (recommended — handles TLA+ with records and sets)

```bash
# Install Apalache
brew install apalache  # macOS
# or: pip install apalache

# Type-check the spec
apalache-mc typecheck ECAC.tla

# Check Inv1 on a small model
apalache-mc check --inv=Inv1 ECAC.tla

# Check all invariants
apalache-mc check ECAC.tla
```

### TLC Model Checker (classic)

```bash
# Install TLA+ Tools
# https://github.com/tlaplus/tlaplus/releases

# Create a model in TLC (or use the config below)
java -cp tla2tools.jar tlc.TLC ECAC.tla
```

### Minimal model for sanity checking

Create `ECAC.cfg`:

```bash
CONSTANTS
USER = "User"
BROKER = "Broker"
READ = "read"
WRITE = "write"
SEND = "send"
DELETE = "delete"
NETWORK = "network"
PUBLIC = 0
INTERNAL = 1
CONFIDENTIAL = 2
UNTRUSTED = 0
USER_TRUSTED = 1
Nil = "Nil"

INVARIANT
Inv1
Inv2
Inv4
Inv5
```

## Refinement mapping (Implementation → Spec)

The Python implementation in `effect_broker/broker.py` refines this spec:

| TLA+                       | Python                                                   |
| -------------------------- | -------------------------------------------------------- |
| `Commit(effect, task)`     | `broker.commit(Commit(effect, task))`                    |
| `CheckAuth/OK/NoAmp/Fresh` | `broker.gate()` → four predicates                        |
| `broker_capabilities[n]`   | `broker.capabilities[n]`                                 |
| `broker_tasks[id]`         | `broker.tasks[id]`                                       |
| `broker_exceptions[n]`     | `broker.label_exceptions[n]`                             |
| `store'`                   | `broker.store.apply_effect(effect)`                      |
| `ledger'`                  | `ledger.record_authorization()` + `record_observation()` |

## What's NOT in the spec (documented limitations)

| Not modeled                                | Reason                                 |
| ------------------------------------------ | -------------------------------------- |
| Same-process vs multi-process isolation    | Abstracted as TCOBB                    |
| Email domain classification                | Simplified to `trust` / `external`     |
| BCC/CC scope check in `CheckNoAmp`         | Only primary target in scope           |
| `_unsafe_bootstrap_*` state initialization | Precondition, not part of commit       |
| `ProvenanceResolver` OS statx derivation   | Platform-specific; not in formal model |
| `ToolRegistry` structural check            | Shim-level; not broker-level           |
| Cross-task data flows                      | Requires language-level taint tracking |

## Why TLA+ (vs Coq/Isabelle)

TLA+ is well-suited here because:

- The system is stateful and concurrent (multiple tasks, locks, logical clock)
- Model checking can exhaustively verify finite instances
- Apalache provides bounded model checking for the infinite state space
- The spec is readable by non-formal-methods experts

Coq/Isabelle formalization would provide **proof** (not just model checking), but:

- Significant effort (weeks vs days)
- Marginal additional assurance at this stage
- TLA+ spec + unit tests (330 tests) provide strong evidence

Defer Coq/Isabelle to a future stage where:

- The TLA+ spec is validated (no invariant violations found)
- The implementation is stable
- A security review certifies the formalization is complete
