<!--
  Thank you for contributing! Please fill out everything marked with
  (REQUIRED) / (REQUIRED if applicable). The Definition of Done below mirrors
  the quality gates in CONTRIBUTING.md — the PR will not merge unless those
  hold and CI is green.
-->

## Summary

<!-- One short paragraph: what changes and why. (REQUIRED) -->

## Target branch

<!-- Which branch should this land in? Default: develop. (REQUIRED) -->

- [ ] `develop` (development / draft)
- [ ] `staging` (QA / testing milestone)
- [ ] `main` (production release)

## Type of change

<!-- (REQUIRED if applicable) Select what applies. -->

- [ ] `feat` — new capability
- [ ] `fix` — bug fix
- [ ] `refactor` — no behavior change
- [ ] `test` — tests only
- [ ] `docs` — documentation only
- [ ] `chore` — tooling / infra

## Security impact

<!-- This project enforces an effect-complete security gate. For any
     security-relevant change, answer explicitly; otherwise skip. (REQUIRED) -->

- **Affected predicate(s):** <!-- e.g. Auth / FlowOK / NoAmp / Fresh / none -->
- **What is blocked / allowed differently, and by which predicate?**
  <!-- e.g. "T14 hidden writes now blocked at Auth in multi-process mode" -->

- **Does this change affect the 22 trace outcomes?**
  - [ ] Yes — list which `primary_blocker` values changed and why
  - [ ] No

## How was this tested?

<!-- (REQUIRED) Local gates and CI. Be specific. -->

- [ ] `make lint`
- [ ] `make typecheck`
- [ ] `make test`
- [ ] `make format-check`
- [ ] Trace outcomes still hold (if gate/predicates touched)

## Definition of Done

<!-- This entire checklist must be true before merging. (REQUIRED) -->

- [ ] All local quality gates above pass.
- [ ] New behavior covered by tests in `tests/`.
- [ ] No secrets, absolute personal paths, or generated artifacts committed.
- [ ] Commit messages follow the conventional format.
- [ ] Changelog entry added under `## [Unreleased]` in `CHANGELOG.md`
      (if user-visible behavior changed).

## Related

<!-- Links: issue, related PR, docs. (REQUIRED if applicable) -->

Closes #<!-- issue number -->
