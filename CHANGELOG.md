# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versioning reflects the **EffectBroker / ECAC** package (`effect-broker`),
whose current `pyproject.toml` version is `0.1.0`.

---

## [Unreleased]

### Added

- `CONTRIBUTING.md`: documented the three-branch workflow
  (`develop` → `staging` → `main`), quality gates, release/tagging process.
- `CHANGELOG.md`: this file.
- `.github/PULL_REQUEST_TEMPLATE.md`: PR template aligned with the workflow and
  security-gate review.
- `SECURITY.md`: vulnerability reporting policy for this research kernel.

### Security

- **Evaluation results (real runs):**
  - Held-out: **8/8 (100%)** sealed traces blocked (SHA-256 `6e1d14c872d495bd`).
  - Baseline comparison: **ECAC 20/20 (100%)**, next-best baseline 9/20 (45%);
    kill criterion (ECAC ≥4 beyond PACT) passes.
  - Adversarial experiment: **17/18** traces blocked; M4 (benign) correctly allowed.

---

## [0.1.0] - 2026-10-12

Initial baseline of the Effect-Complete Authority Confinement (ECAC) broker.

### Added

- **Core broker & gate** (`effect_broker/broker.py`, `model.py`):
  - Commit-time gate over four predicates: `Auth`, `FlowOK`, `NoAmp`, `Fresh`.
  - Capability model with owner/holder/right/target/scope, attenuation and
    ceiling scope enforcement.
  - Task/session model with flow boundary, session taint, send budget, replay set.
  - Label exceptions (approve/declass) recorded by the broker.
- **Confinement & executors:**
  - `enforcer.py`: restricted `os.open`, blocked system paths, allowed-path set.
  - `executor.py` / `executor_subprocess.py`: isolated effect execution,
    secure-import blocklist, content-hash binding (`authorized_content_hash`).
- **Independent verification:**
  - `ledger.py`, `observer.py`, `oracle.py`: independent ledger/observer/oracle
    to detect bypass (observed-but-not-confirmed).
- **Evaluation infrastructure:**
  - Trace suite T1–T20 (22 traces) with expected `primary_blocker` per trace
    (`traces.py`, `baselines/traces.py`, `run_traces.py`).
  - Baselines: CaMeL, PACT, Cordon, ChainCaps, Allowlist, ArgProv, FORGE,
    ConvSandbox (`effect_broker/baselines/`).
  - `metrics.py`: §6 evaluation metrics (defense rate, per-mechanism breakdown,
    latency percentiles, annotation burden, TCB size, session-taint honesty).
  - Held-out evaluator (8 sealed traces) and adversarial experiment runner
    (`bin/eval-*`, `experiment.py`).
- **Project tooling:**
  - `uv`-locked reproducible environment (`uv.lock`, `--frozen`).
  - `Makefile` targets: `lint`, `format`, `format-check`, `typecheck`, `test`,
    `held-out`, `comparative`, `experiment`, `run`, `doctor`, `clean`.
  - CI (`.github/workflows/ci.yml`): lint + strict typecheck + pytest +
    trace-outcome assertions on 22 traces.
  - 508 passing tests.

### Changed

- Type-annotated and reformatted the codebase; `mypy` strict passes with
  zero errors across the package.
- `mode_cordon.py`, traces, and tests reformatted to a consistent style.

### Security

- Gate binds the check to the **primitive effect at commit time**, not the
  tool-call argument: no externally committed effect without a machine-checkable
  authority and information-flow derivation.

---

[0.1.0]: https://github.com/merma1509/ecac-for-tas/releases/tag/v0.1.0
