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
  actions) constraints against the effect's sink
- **NoAmp** — the effect's authority is a _root-anchored, monotonic_ derivation
  from a trusted root (User), not merely "present in some chain or store
- **Fresh** — the capability is unexpired, unrevoked, and not replayed

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
  model.py       Data, Capability, Effect dataclasses + principals
  broker.py      EffectBroker (the only committer) + four predicates
  traces.py      adversarial trace suite
run_traces.py    entry point
```

## Run

```bash
python run_traces.py
```
