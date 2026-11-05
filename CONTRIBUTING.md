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

Two long-lived branches plus short-lived feature branches. Releases are
identified by **tags**, not by long-lived milestone branches.

| Branch      | Purpose                             | Push policy             | Merge policy           |
| ----------- | ----------------------------------- | ----------------------- | ---------------------- |
| `main`      | **Production** — stable, deployable | Protected (via PR only) | PR required + CI green |
| `develop`   | **Integration** — day-to-day work   | Protected (via PR only) | PR required + CI green |
| `feature/*` | Short-lived topic branches          | Free                    | PR into `develop`      |

> `main` is the default branch and the only branch that is ever tagged for
> release. Feature branches are deleted after merge.

**Why no `staging` branch.** A long-lived QA branch diverges from `main` the
moment either side advances, and keeping it in sync costs a PR per change
(observed repeatedly in this repo's own history). The QA gate it used to
provide is now enforced by CI instead: the `eval` job in
`.github/workflows/ci.yml` runs on every push and every pull request
(held-out + baseline comparison + experiment assertions). For a frozen
pre-release snapshot, use a release candidate tag on `develop`
(e.g. `v0.2.0-rc.1`) rather than a branch.

---

## 2. Release flow

```bash
feature/xyz ──PR──> develop ──PR (release)──> main ──> tag vX.Y.Z
        ▲                │
   day-to-day work       └── eval gate runs on every PR and push
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
5. **Open a release PR** from `develop` --> `main`.
   - The **eval gate** (`held-out`, `comparative`, `experiment` assertions) has
     already run on this branch, but it is additionally a required status check
     on `main`, so it will run again on the release PR.
   - Review the eval output in the CI log; it must show the sealed traces
     blocked, the baseline advantage, and the benign case allowed.
6. **Merge the release PR** once CI (including eval) is green.
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
make verify        # assert every trace's expected primary_blocker
make eval          # release eval gate (held-out + baseline + experiment)
```

To auto-fix formatting issues:

```bash
make format        # ruff format + ruff check --fix
```

### Workflows (`.github/workflows/`)

Three workflow files with non-overlapping responsibilities:

| File     | Trigger                                | Purpose                                     |
| -------- | -------------------------------------- | ------------------------------------------- |
| `ci.yml` | every PR, push to `main` and `develop` | quality gate + sealed eval gate             |
| `pr.yml` | PR metadata events                     | PR hygiene: title, changelog, size advisory |
| `cd.yml` | push of a `v*` tag                     | validate tag, re-run gates, publish release |

**`ci.yml`** — the quality gate. Runs on every PR and on push to `main` /
`develop`:

- `uv sync --frozen --all-extras --dev` (reproducible install)
- `ruff check .` (lint)
- `mypy effect_broker` (strict typecheck)
- `pytest` (full suite)
- **Trace outcome verification** via `scripts/verify_traces.sh` — asserts the
  exact expected blocker per trace (T1–T20, 22 traces). If your change touches
  gate semantics, this step must still produce the expected `primary_blocker`
  values.

A second job, **`eval`**, runs on **every push and every pull request** and is
the release gate that replaced the old `staging` QA step, executed by
`scripts/verify_eval.sh`. Running it everywhere means the sealed evaluation
cannot silently rot between releases; on `main` it is the required
`Release eval gate` status check:

- held-out — asserts **8/8** sealed traces are blocked.
- baseline — asserts ECAC blocks **20/20** and the kill criterion
  (`ECAC >= 4 beyond PACT`) passes.
- experiment — asserts **17/18** traces blocked and the benign case (M4) is
  allowed.

The eval scripts print a report but exit `0` regardless of outcome, so the
script greps for the expected assertions; a regression fails the job.

**`pr.yml`** — PR hygiene, on `pull_request_target` (metadata only, no PR code
is executed):

- **title** — must follow `<type>(<scope>): <summary>` (blocking).
- **changelog** — a PR touching `effect_broker/`, `tests/`, `bin/` or `scripts/`
  must add a line under `## [Unreleased]` in `CHANGELOG.md`. Opt out with the
  `skip-changelog` label for genuinely internal changes (blocking).
- **size** — posts a one-time advisory comment above 20 files / 400 changed
  lines. Never blocking.

**`cd.yml`** — release pipeline, triggered by pushing a `v*` tag:

1. **validate** — the tag must be an ancestor of `main`, must match the
   `pyproject.toml` version (release candidates map to the version they
   precede), and `CHANGELOG.md` must have a `## [<version>]` section.
2. **gate** — lint, typecheck, pytest, `verify_traces.sh`, `verify_eval.sh`.
3. **release** — `uv build`, then attach wheel + sdist to a GitHub Release whose
   notes are the changelog section for that version. `-rc.` tags are marked as
   prereleases.

There is **no deploy step and no PyPI publishing**: both need an explicit
decision and credentials. Adding one is a deliberate change to `cd.yml`.

> If you change security-relevant code (predicates, gate, models), add or
> update tests in `tests/` that demonstrate the behavior, and run the trace
> assertion step locally: `./scripts/verify_traces.sh`.

---

## 6. What to touch where

| Area                                 | Location                                      |
| ------------------------------------ | --------------------------------------------- |
| Broker / gate / commit semantics     | `effect_broker/broker.py`, `model.py`         |
| Filesystem / process confinement     | `effect_broker/enforcer.py`, `executor*.py`   |
| Resource store & bootstrap           | `effect_broker/restricted_store.py`           |
| Baselines (CaMeL, PACT, Cordon, ...) | `effect_broker/baselines/`                    |
| Trace suite & evaluators             | `bin/`, `run_traces.py`                       |
| Gate assertions used by CI/CD        | `scripts/verify_*.sh`, `scripts/pr_checks.sh` |
| Metrics / evaluation report          | `effect_broker/metrics.py`                    |
| Tests                                | `tests/` (mirror `effect_broker/`)            |
| Docs / proposal                      | `README.md`, `docs/`, `research_proposal.md`  |

**Traces** live in `effect_broker/traces.py` and
`effect_broker/baselines/traces.py` and are structured data (scenarios with
expected blockers), not scattered ad-hoc code. When adding an attack/defense
scenario, extend that data — do not hardcode new one-off assertion paths in
arbitrary modules.

---

## 7. Definition of Done (DoD)

A contribution is done when **all** of these hold:

- [ ] `make lint`, `make typecheck`, `make test`, `make format-check` pass.
- [ ] `make verify` passes (trace outcomes unchanged).
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

- `main` and `develop` are **protected**: direct pushes are disabled; changes
  arrive via PR with required checks (lint + typecheck + test + trace outcomes).
- Repository admins configure branch protection via
  **Settings -> Branches -> Branch protection rules**.
- Release tags are created only on `main`, after the eval gate on the release PR
  has passed.

---

_If the workflow changes, update this file in the same PR._
