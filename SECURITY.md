# Security Policy

## Supported status

**This is a research/working specification, not a production system.**

ECAC is an executable kernel for studying commit-time, effect-complete authority
confinement of LLM tool agents. It is published to support the research thesis,
teaching, and collaboration. It is **not** a hardened, FIPS/PCI/anything-certified
security product, and it must **not** be used as the sole protection layer for a
real deployment.

See `README.md` → "Honest limitations" for the known boundaries (regression
evidence vs. real confinement, advisory same-process isolation, trusted-manifest
requirements, deferred cross-task taint tracking, etc.).

## What is actually enforced, per platform

| Mechanism                             | Linux 5.13+ (Landlock LSM on)                                                        | macOS                     |
| ------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------- |
| Kernel path confinement (writes)      | yes — only under `/tmp`, `/var/tmp`, `/dev/shm`                                      | **none**                  |
| Kernel path confinement (reads)       | yes — `/usr`, `/lib`, `/etc`, `/dev`, `/proc`, `/sys`, cwd, IPC key dir; **not `~`** | **none**                  |
| `restricted-open` (`os.open` wrapper) | yes — Python-level hygiene                                                           | Python-level hygiene only |
| Import blocklist                      | hygiene, not a boundary                                                              | hygiene, not a boundary   |

The permitted write set matches the Python-level policy in `executor.py`, so the
same boundary is enforced twice rather than the two layers disagreeing. Set
`ECAC_LANDLOCK_WRITE_ROOT` to narrow it to a single directory — when that
variable is set, it becomes the only writable location.

Reads are handled too (`READ_FILE` is in the ruleset), which is what keeps
`~/.ssh/id_rsa` and `~/.aws/credentials` out of reach. Two exceptions are
deliberate and auditable: the working directory, so a workload can read its own
inputs, and `ECAC_IPC_KEY_DIR`, so the executor can read the HMAC key it verifies
IPC messages with. `ECAC_LANDLOCK_READ_ROOTS` adds deployment-specific data
roots. **Anything under a write root is readable by design** — do not keep
secrets inside the sandbox root.

The confinement status reported by the executor names what is in effect and
never says `landlock` unless a selftest observed a write outside the permitted
directories being denied (`EACCES`) _and_ a write inside them succeeding. Both
halves are required: a ruleset that denies everything also denies the "outside"
probe, and a process confined out of its own sandbox is broken, not confined.
Set `ECAC_REQUIRE_CONFINEMENT=1` to make the executor refuse
to start where no kernel mechanism exists (CI sets this; local development
defaults off). On macOS the Python-level layers are a speed bump, not a
security boundary — treat the platform as unconfined.

---

## Reporting a vulnerability

If you believe you have found a security-relevant issue in the ECAC gate,
the executors (`enforcer.py`, `executor*.py`), the baselines, or the evaluation
harness, please report it **privately and responsibly**:

1. **Do not** open a public issue or PR that exposes the exploit.
2. **Email / DM the repository maintainers privately** with:
   - A concise description of the issue.
   - A minimal reproduction (code or trace) — no real secrets.
   - Which component and predicate (if any) is involved.
   - Suggested fix, if you have one.
3. Expect a first response within **5 business days**.

### What to include

- Affected files/modules (e.g. `effect_broker/broker.py`, `executor.py`, `shim_real.py`).
- Whether the issue affects `mode="same-process"` or `mode="multi-process"`.
- A proposed test case (even a failing one) — this repository values tests
  that demonstrate the behavior.

---

## What we will do

- Acknowledge receipt of the report.
- Investigate, and corroborate or push back with reasoning.
- Fix or explicitly document as a known limitation.
- Track the fix in `CHANGELOG.md` under `## [Unreleased]` → `### Security`.
- If the issue is a real design limitation rather than a bug, we will document
  it in the "Honest limitations" section rather than silently patching around it.

---

## Out of scope

- **Direct store mutation in `same-process` mode.** This is an advisory mode by
  design; the ledger returns `UNKNOWN` (never "safe"). Not a regression.
- **Attacks requiring real physical access or OS root outside our sandbox.**
- **Tool declarations in an untrusted manifest.** The structural check is only
  as strong as the trust placed in the tool schema.
- **Bugs in third-party dependencies** — report them upstream.

---

## No bug bounty

This is a thesis/research project with no bug bounty program. We will credit
reporters in release notes where appropriate.

---

## Disclosure

We prefer coordinated disclosure: 30 days from acknowledgement before a public
disclosure, or sooner if a fix is already merged.
