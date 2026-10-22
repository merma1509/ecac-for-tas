# Contributing to ECAC / EffectBroker

This document is the single source of truth for how changes flow from an idea
to production.

- **Project scope:** Effect-Complete Authority Confinement (ECAC) for LLM tool agents.
- **Codebase:** `effect_broker/` (broker, model, enforcer, executors, baselines),
  `tests/`, `bin/` evaluators, `docs/`.
- **Tooling:** `uv` (pinned via `uv.lock`, `--frozen`), `ruff` (lint + format),
  `mypy` (strict), `pytest`.

---

## 1. Branch model

Three long-lived branches. Nothing else should be created or pushed directly
without going through the workflow below.

| Branch    | Purpose                                   | Push policy                   | Merge policy           |
| --------- | ----------------------------------------- | ----------------------------- | ---------------------- |
| `main`    | **Production** — stable, deployable       | Protected (via PR only)       | PR required + CI green |
| `staging` | **QA / testing** milestone before release | Protected (via PR only)       | PR required + CI green |
| `develop` | **Development / draft** — day-to-day work | Direct pushes allowed (or PR) | Direct or PR           |

> `main` is the default branch and the only branch that should ever be
> deployed or tagged for release.

---

## 2. Release flow

```bash
feature/xyz ──PR──▶ develop ──PR──▶ staging ──PR/merge──▶ main
                        ▲                    tests / QA
        day-to-day work        gated evaluation before release
```

Detailed rules:

1. **Start from `develop`.** Create a short-lived feature branch:
   ```bash
   git checkout develop
   git pull
   git checkout -b feature/your-change
   ```
2. **Do your work** and commit with clear, conventional messages
   (see [Commit messages](#4-commit-messages)).
3. **Open a Pull Request** targeting `develop`.
   - The CI gate (lint + typecheck + test + trace outcomes) must pass.
   - Local quality checks must pass before opening: `make lint`,
     `make typecheck`, `make test`.
4. **Merge into `develop`** after review + green CI.
5. **Promote to `staging`** with a PR from `develop` → `staging`.
   - Run the evaluation suite here: `make held-out`, `make comparative`.
6. **QA on `staging`.** If QA passes, promote `staging` → `main` via PR
   (or merge after review).
7. **Tag the release** on `main`:
   ```bash
   git checkout main
   git pull
   git tag -a v0.1.0 -m "Describe the release"
   git push origin v0.1.0
   ```

> **Keep the changelog in sync.** Move features from `## [Unreleased]` into the
> new version section in `CHANGELOG.md` in the same PR that promotes changes to
> `main`. Never tag a release without a corresponding `CHANGELOG.md` entry.
> Keep `develop` always mergeable into `main`; when `main` advances, merge it
> back into `develop`.

---

## 3. Setup

Requirements: `git`, `uv` (install via `make setup`), Python 3.12.

```bash
make install      # uv sync --all-extras --dev --frozen (reproducible, lockfile-pinned)
make doctor       # verify the environment is healthy
```

Everything runs through `uv`; there is **no** `PYTHONPATH` or global venv
juggling. A thin wrapper `dev.sh` exists as a convenience:
`./dev.sh lint`, `./dev.sh typecheck`, `./dev.sh test`, etc.

---

## 4. Commit messages

Use the conventional pattern `type(scope): summary`:

- `feat(metrics): add per-mechanism breakdown`
- `fix(executor): preserve send budget on failure`
- `refactor(traces): make traces data-driven`
- `test(security): cover replay after declass`
- `chore(makefile): add format-check target`

Keep the summary under 72 characters, imperative mood, capitalized first letter.

---

## 5. Quality gates

These must pass **before** opening a PR; CI enforces them too.

```bash
make lint          # ruff check effect_broker/ tests/
make typecheck     # mypy (strict) effect_broker/
make test          # pytest tests/
make format-check  # ruff format --check (files must be formatted)
```

To auto-fix formatting issues:

```bash
make format        # ruff format + ruff check --fix
```

### CI pipeline (`.github/workflows/ci.yml`)

Runs on every PR and on push to `main`:

- `uv sync --frozen --all-extras --dev` (reproducible install)
- `ruff check .` (lint)
- `mypy effect_broker` (strict typecheck)
- `pytest` (full suite)
- **Trace outcome verification** — runs `run_traces.py` and asserts the exact
  expected blocker per trace (T1–T20, 22 traces). If your change touches the
  gate semantics, this step must still produce the expected `primary_blocker`
  values.

> If you change security-relevant code (predicates, gate, models), add or
> update tests in `tests/` that demonstrate the behavior, and run the trace
> assertion step locally: `make run | grep -E "T[0-9]+"`.

---

## 6. What to touch where

| Area                                 | Location                                     |
| ------------------------------------ | -------------------------------------------- |
| Broker / gate / commit semantics     | `effect_broker/broker.py`, `model.py`        |
| Filesystem / process confinement     | `effect_broker/enforcer.py`, `executor*.py`  |
| Resource store & bootstrap           | `effect_broker/restricted_store.py`          |
| Baselines (CaMeL, PACT, Cordon, ...) | `effect_broker/baselines/`                   |
| Trace suite & evaluators             | `bin/`, `run_traces.py`                      |
| Metrics / evaluation report          | `effect_broker/metrics.py`                   |
| Tests                                | `tests/` (mirror `effect_broker/`)           |
| Docs / proposal                      | `README.md`, `docs/`, `research_proposal.md` |

**Traces** live in `effect_broker/traces.py` and
`effect_broker/baselines/traces.py` and are structured data (scenarios with
expected blockers), not scattered ad-hoc code. When adding an attack/defense
scenario, extend that data — do not hardcode new one-off assertion paths in
arbitrary modules.

---

## 7. Definition of Done (DoD)

A contribution is done when **all** of these hold:

- [ ] `make lint`, `make typecheck`, `make test`, `make format-check` pass.
- [ ] New behavior covered by tests in `tests/`.
- [ ] If gate/predicate semantics changed, the 22 trace outcomes still hold.
- [ ] No secrets, absolute personal paths, or generated artifacts committed
      (`.venv/`, caches, `dist/`, `build/` are gitignored).
- [ ] Commit message follows the conventional format.

---

## 8. Code review etiquette

- Request review from at least one person for `main`-bound changes.
- Keep PRs focused and reasonably sized; split large rewrites.
- Resolve the `primary_blocker` question explicitly in the PR description for
  any security-relevant change: _what is blocked, by which predicate, and why._
- Reply to review comments; do not force-push over reviewed history unless the
  branch is not yet merged and rebasing is agreed upon.

---

## 9. Protected branches & admin

- `main` and `staging` are **protected**: direct pushes are disabled; changes
  arrive via PR with required checks.
- Repository admins configure branch protection via
  **GitHub → Settings → Branches → Branch protection rules**.
- Release tags are created only on `main`, after QA on `staging`.

---

_If the workflow changes, update this file in the same PR._
