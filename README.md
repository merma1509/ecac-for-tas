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
make comparative  # ECAC vs 8 baselines
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
- **Held-out evaluation:** 8/8 supplied held-out traces blocked by the gate regression (SHA-256 `e0239fbfa49c1cbe`)
- **Baseline regression:** ECAC's gate blocks all 20 supplied adversarial traces, and every
  comparator in `baselines/` misses at least one. Read this carefully: the comparators are
  **reduced models**, not deployments of the systems they are named after. Each one's enforced
  and omitted mechanisms are declared in `baselines.COMPARATOR_MECHANISMS`; a number here
  therefore measures ECAC's gate against those reduced models, and is regression coverage of
  gate logic on supplied traces — NOT a causal evaluation of mechanism effectiveness, and not a
  claim about the real systems (see "Honest limitations")
- **Adversarial workload regressions:** 17/18 supplied traces blocked; M4 benign correctly allowed
- **Independent oracle (out-of-band).** `effect_broker/oracle.py` re-derives 'did this effect
  occur?' from the real filesystem / real SMTP MTA log, never the broker store — it can refute
  a ledger that claims success the effect did not actually produce.
- **Path/host allowlist baseline (not a sandbox).** `baselines/mode_path_allowlist.py` checks
  target paths and hosts by string comparison. It was previously named
  `mode_conventional_sandbox.py` and described as "seccomp/landlock-style"; it never enforced
  either, so the claim was removed and the file renamed rather than the mechanism implemented.
  There is currently **no faithful conventional-sandbox comparator** — a real one needs Landlock
  or a seatbelt profile enforced by the kernel, proven by a denied path failing with `EACCES`.
  Every comparator's enforced and omitted mechanisms are listed in
  `baselines.COMPARATOR_MECHANISMS`.
- **Mechanism-level attack regressions.** Each named predicate (Auth/FlowOK/NoAmp/Fresh) is
  exercised by an attack pair (legitimate allowed + attack blocked by that predicate).

## Honest limitations

- **What is kernel-enforced, per platform.** On Linux 5.13+ with the Landlock LSM enabled, the
  executor subprocess applies a Landlock ruleset and _keeps_ the claim only if a selftest
  observes a write outside the permitted directories (`/tmp`, `/var/tmp`, `/dev/shm`, or
  `ECAC_LANDLOCK_WRITE_ROOT` when set) being denied (`EACCES`) **and** a write inside them
  succeeding — a ruleset that denies everything would otherwise read as success. On macOS there is
  **no kernel confinement**: the Python-level restricted-open wrapper and import blocklist are
  hygiene, not a security boundary. `_get_confinement_status()` names what is actually in effect,
  and `ECAC_REQUIRE_CONFINEMENT=1` makes the executor refuse to start where no kernel mechanism
  exists (off by default for local development, on in CI).
- **Read confinement is allowlisted per file, not per directory.** Landlock grants a subtree, so
  listing `/etc` as a read root also granted `/etc/shadow` and `/etc/sudoers`. Measured in a
  container, a confined process read `/etc/shadow` while the status said `restricted-open`. The
  roots no longer include `/etc`; the individual files that are needed are granted by name. If you
  run the executor with `ECAC_REQUIRE_CONFINEMENT=1`, note that **`HOME` must be outside the
  permitted write roots** (`/tmp`, `/var/tmp`, `/dev/shm`): with `HOME=/tmp` the selftest cannot
  observe a denied home read and the executor correctly refuses to start.
- **All tests ≠ real confinement.** Regression evidence, not proven protected-effect confinement
- **Same-process isolation is advisory.** Direct store mutation returns `UNKNOWN`. Use multi-process mode.
- **Tool declarations require a trusted manifest.** The structural check is only as strong as
  the trust placed in the tool schema
- **Cross-task data composition not enforced.** Requires language-level taint tracking (deferred)
- **TCB expansion unquantified.** Formal TCB size argument deferred
- **Evaluation metrics (regression scope).** `effect_broker/metrics.py` reports defense
  rate, false positives/negatives, per-predicate contribution, latency percentiles,
  annotation burden, and TCB line count on a fixed labeled scenario set — regression
  metrics on supplied scenarios, not a causal estimate vs adaptive/live attackers.
- **Formal specification** implementation verified in `tests/test_formal_invariants.py`
