# ECAC — Effect-Complete Authority Confinement for Tool Agents

**Executable kernel** for commit-time, effect-complete authority confinement of LLM tool agents.
Every tool-call side effect passes through a four-predicate gate
(`Auth and FlowOK and NoAmp and Fresh`); nothing mutates external state outside the gate.

> **Status:** validated executable model. Machine-checkable predicates, independently falsifiable.
> Working specification — not a production system.

## Invariant

```bash
Commit(e, t)  ==>  Auth(e, t) and FlowOK(e, t) and NoAmp(e, t) and Fresh(e, t)
```

| Predicate | What it checks                                    | Target                                    |
| --------- | ------------------------------------------------- | ----------------------------------------- |
| `Auth`    | Broker holds a root-anchored capability           | No commit without valid authority         |
| `FlowOK`  | No confidentiality leak, no low-integrity control | No forbidden flow without declass/endorse |
| `NoAmp`   | Authority chain is monotonic from `User`          | No authority amplification                |
| `Fresh`   | Capability unexpired, unrevoked, not replayed     | Stale/revoked authority not reused        |

`Fresh` is split from `Auth` because target #4 ("stale/revoked authority cannot be reused")
requires a **time-dependent** check — exactly what `Fresh(e, t)` performs at commit time.

## Architecture

```bash
IndependentEffectLedger  ← records broker.gate() + executor.apply_effect()
     ↑ broker.gate()          ↓ executor.apply_effect()
     ┌────────────────┐  ┌──────────────────────────┐
     │  EffectBroker  │  │  RestrictedResourceStore │
     │  Auth/FlowOK/  │  │  apply_effect() → F ∪ E  │
     │  NoAmp/Fresh   │  │                          │
     └────────────────┘  └──────────────────────────┘
              ↑
        executor.execute()  ← broker.commit() + shim callers unify here
```

**TCOBB (multi-process mode):** `RealFileShim` and `RealEmailShim` are the only code
that calls `open()`, `os.write()`, `smtplib`, `imaplib`. Effects are derived from **real
OS/SMTP state** — the tool cannot forge outcomes.

> **Production:** use `mode="multi-process"`. In `mode="same-process"`, direct store
> mutation bypasses the executor; the ledger returns `UNKNOWN` (never "safe").

## Run

```bash
make all          # lint + typecheck + test + held-out + comparative + experiment
make test         # pytest suite
make held-out     # 8 sealed adversarial traces
make comparative  # ECAC vs 7 baselines
make experiment   # M1–M5, H1–H3, T9–T20
make run          # T1–T20 + R1 traces
```

Or via `dev.sh`:

```bash
./dev.sh setup
./dev.sh test
./dev.sh verify    # full CI gate
```

## Findings

- **The invariant is machine-checkable.** Every commit decision produces per-predicate evidence.
- **Single mutation path.** `RestrictedResourceStore.apply_effect()` is the only call site
  for `_apply_effect()`. Both `broker.commit()` and shim callers unify in `executor.execute()`.
- **TCOBB (multi-process).** RealFileShim/RealEmailShim derive effects from real OS/SMTP state.
- **Real SMTP BCC detection.** `RCPT TO` probe → RSET → no message queued before commit.
- **NoAmp ≠ Auth.** A forged capability that passes Auth still fails NoAmp (`owner ≠ "User"`)
- **Session Taint Mode.** `read(CONFIDENTIAL file)` taints the session; FlowOK blocks
  subsequent `send` unless a broker-recorded declass exists.
- **ToolRegistry structural enforcement.** Undeclared tool operations raise `SecurityError`
  before reaching the broker gate — closes T14 (hidden write) that the four-predicate gate
  alone cannot catch
- **Held-out evaluation:** 8/8 traces blocked, 6/6 high-severity defended (SHA-256 `e0239fbfa49c1cbe`)
- **Baseline comparison:** ECAC 20/20 vs next baseline 9/20 (+11 advantage, ≥4 kill criterion passes)
- **Experiment traces:** 17/18 blocked; M4 benign correctly allowed

## Honest limitations

- **All tests ≠ real confinement.** Regression evidence, not proven protected-effect confinement
- **Same-process isolation is advisory.** Direct store mutation returns `UNKNOWN`. Use multi-process mode.
- **Tool declarations require a trusted manifest.** The structural check is only as strong as
  the trust placed in the tool schema
- **Cross-task data composition not enforced.** Requires language-level taint tracking (deferred)
- **TCB expansion unquantified.** Formal TCB size argument deferred
- **No performance or approval-burden metrics.**
- **Formal specification** implementation verified in `tests/test_formal_invariants.py`
