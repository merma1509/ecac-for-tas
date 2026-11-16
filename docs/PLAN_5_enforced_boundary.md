# PLAN 5 — Enforced Boundary: OS Confinement, Canonical Request & Provenance

**Status:** Proposed
**Priority:** HIGH (the security claims in README depend on it)
**Supersedes:** PLAN 1 §2 and §3 (marked COMPLETE; both are demonstrably incomplete)

---

## Why this plan exists

Three distinct defects are bundled here because all three decide _what the tool
is allowed to do_, _what it is allowed to send_, and _under which labels_:

1. The OS boundary does not exist. It is documented as defense-in-depth but the
   Landlock code is wrong and the Python-level patch covers only one function.
2. The approved request does not identify the operation unambiguously, so the
   executor cannot prove it transmits exactly what was approved.
3. Provenance validation checks the _identity_ of a datum but not its _labels_,
   so a valid provenance ID can be re-labelled at will.

Trigger: external review, items 2, 3 and 4.

---

## Part A — The boundary is not enforced

### Evidence

**A1 — Landlock is broken in four independent ways.**

`effect_broker/executor_subprocess.py:276-315`:

```python
SYS_landlock_create_ruleset = 451      # wrong: 444 on x86_64
LANDLOCK_RESTRICT_SELF     = 0x03      # this is a FLAG, not a syscall number
ACCESS_FS_READ  = 1   # actually LANDLOCK_ACCESS_FS_EXECUTE
ACCESS_FS_WRITE = 2   # actually LANDLOCK_ACCESS_FS_WRITE_FILE
ACCESS_FS_EXEC  = 4   # actually LANDLOCK_ACCESS_FS_READ_FILE

ruleset_fd = libc.syscall(451, 0, byref(attr), sizeof(attr))
if ruleset_fd >= 0:
    libc.syscall(451, 0x03, ruleset_fd, 0, 0)   # also 451 — should be 446
    return True                                  # return value never checked
```

Verified empirically on the development machine:

```
syscall 444 (real create_ruleset, VERSION flag) -> -1, errno=14 (EFAULT)
syscall 451                                     -> -1, errno=22 (EINVAL)
```

Additional gaps beyond the wrong numbers:

- **No `landlock_add_rule` (445) call at all.** A ruleset with no allow rules
  permits nothing — but since `restrict_self` is never verified, nothing is
  enforced either.
- **`restrict_self` return value discarded**, so `_apply_landlock_sandbox()`
  returns `True` on the strength of `create_ruleset` alone.
- `_landlock_active` then feeds `_get_confinement_status()` (`:320`), which is
  what reports the active confinement methods. **The system can claim
  `landlock` while enforcing nothing.**

**A2 — The Python-level patch covers one call out of many.**

`effect_broker/enforcer.py:213`:

```python
os.open = _restricted_open
```

Verified: this is the _only_ patch. Not patched:

- builtin `open()` — which is what `shim_real.py` actually uses (`:722`, `:728`);
- `os.remove`, `os.unlink`, `os.stat`, `os.listdir`, `os.rename`, `os.mkdir`.

So a tool calling `open("/secrets/x")` or `os.remove(...)` bypasses the enforcer
entirely.

**A3 — The blocklist contradicts itself.**

`/etc` is in `_BLOCKED_PATHS` (`:53`) and is also in `_ALLOWED_READ_SYSTEM`
(`:179`), which permits reading it. Whichever branch is reached first decides.

**A4 — Import blocking is not a boundary.**

A `builtins.__import__` hook is trivially bypassed by `__import__` reassignment,
`importlib`, already-imported modules, or `ctypes`. It raises the cost of a
mistake; it does not confine arbitrary code. It should be described as hygiene,
not as confinement.

**A5 — The documented claim does not match the mechanism.**

`README.md:86` promises a "seccomp/landlock-style OS path+syscall confinement
baseline". The baseline is a ~50-line path/host string check
(`baselines/mode_conventional_sandbox.py`) with no syscall at all. See PLAN 6 §C.

### Design

**Fail closed on absence.** Landlock must either be verified active or the
executor must refuse to run untrusted code.

```python
class LandlockUnavailable(RuntimeError):
    """Raised when confinement was requested but could not be verified."""

def apply_landlock(allowed_write: Sequence[str], allowed_read: Sequence[str]) -> None:
    """Apply and VERIFY a Landlock ruleset. Raises if not enforced."""
    abi = _landlock_abi_version()            # 444 + VERSION flag
    if abi is None:
        raise LandlockUnavailable("landlock not supported by this kernel")

    ruleset = _create_ruleset(_handled_access(abi))     # 444
    for path in allowed_read:
        _add_rule(ruleset, path, _READ_RIGHTS(abi))     # 445
    for path in allowed_write:
        _add_rule(ruleset, path, _WRITE_RIGHTS(abi))    # 445

    if _restrict_self(ruleset) != 0:                    # 446, MUST check
        raise LandlockUnavailable(f"restrict_self failed: {os.strerror(ctypes.get_errno())}")

    if not _selftest_confinement():                     # probe a denied path
        raise LandlockUnavailable("restrict_self returned 0 but confinement is not active")
```

`_selftest_confinement()` is the part that makes the claim true: after applying,
attempt to open a path that must be denied and assert `EACCES`. If it succeeds,
confinement is not in effect, whatever the syscalls returned.

**Correct constants** (x86_64, `linux/landlock.h`):

```
__NR_landlock_create_ruleset   = 444
__NR_landlock_add_rule         = 445
__NR_landlock_restrict_self    = 446

LANDLOCK_ACCESS_FS_EXECUTE     = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE  = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE   = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR    = 1 << 3
LANDLOCK_CREATE_RULESET_VERSION = 1
```

**Portability.** Landlock is Linux-only. On macOS there is no equivalent
without a container. The honest options are: refuse to run untrusted code, or
run inside a container. Silence is not an option — `ECAC_REQUIRE_CONFINEMENT=1`
should make absence fatal, and default-on in CI.

### Tasks

- [x] Rewrite `_apply_landlock_sandbox()` with correct syscall numbers/flags.
      (`restrict_self` previously received the ruleset FD where its flags
      argument belongs, so no restriction was ever applied while the code read
      as if one had been.)
- [x] Call `landlock_add_rule` for every allowed read/write root.
      (Write roots, then read roots, then individual files — see the `/etc`
      entry below.)
- [x] Check `restrict_self` return value; refuse to report active on failure.
      (`ConfinementUnavailable` is the class name; the plan's working name
      `LandlockUnavailable` was not used.)
- [x] Add `_selftest_confinement()`; refuse to report active if the probe fails.
      (Two-sided: a write outside is denied **and** a write inside succeeds. A
      one-sided probe also passes for a ruleset that denies everything, which is
      a broken executor rather than confinement.)
- [x] Add `ECAC_REQUIRE_CONFINEMENT` (fail closed) and wire it into CI.
      (The CI `Test` step sets it to `1`. Note: the variable alone was not
      enough — see "Why the CI wiring was not enough" below.)
- [x] Patch `builtins.open`, `os.remove`, … — or rely solely on Landlock.
      (Chosen: the Python-level wrappers stay, but they are documented as
      **hygiene**, not confinement, and the status string names them separately
      from `landlock`. See the next item.)
- [x] Resolve the `/etc` contradiction.
      (`_BLOCKED_PATHS`/`_ALLOWED_READ_SYSTEM` no longer exist. The replacement
      found a worse bug — see "What /etc was hiding" below.)
- [x] Demote import blocking from "Layer 4 confinement" to "hygiene" in docstrings.
- [x] Update `README.md` and `SECURITY.md` to state exactly what is enforced,
      and on which platforms.
- [x] Test: `_selftest_confinement()` fails when Landlock is stubbed out.
- [x] Test: a tool calling builtin `open("/etc/shadow")` is denied.
      (`TestEtcIsNotOpenedWholesale::test_a_confined_process_cannot_read_shadow`;
      it fails if `/etc` is put back in the read roots.)
- [x] Test: a tool calling `os.remove` outside the sandbox is denied.
- [x] CI: a Linux job with Landlock enabled (kernel 5.13+).
      (The `Verify kernel confinement (P5-1)` step refuses to skip: on a runner
      whose kernel reports Landlock, failing to confine is a failure, not a
      skip.)

**What `/etc` was hiding.** `/etc` was listed as a read root, and Landlock
grants a _subtree_. Measured in a container with ABI 4 against this commit's
predecessor: a confined process read `/etc/shadow` successfully while
`_get_confinement_status()` reported `restricted-open`. Asking for `hosts` and
`resolv.conf` also granted `shadow`, `gshadow` and `sudoers`.

That is the worst shape this class of bug takes — the status string advertised a
confinement layer, and the one file a reader would ask about was readable
through it. `/etc` is gone from the roots; `_LANDLOCK_READ_FILES` grants the
specific files that are needed. Verified in the same container: `shadow` denied,
`hosts`/`passwd`/`resolv.conf` still readable, `smtplib`/`ssl`/`socket` still
import, and the full suite passes with `ECAC_REQUIRE_CONFINEMENT=1`.

**Why the CI wiring was not enough.** `ECAC_REQUIRE_CONFINEMENT` was described
in `README.md` as "on in CI" while no CI step set it. Every confinement test ran
unconfined, and the suite was green either way — the exact failure mode the flag
exists to prevent, committed in the act of documenting it. The `Test` step now
sets it, and that was verified by running the suite in a Linux container with
Landlock active and `HOME` outside the writable roots: 840 passed, 3 skipped,
exit 0.

One caveat found while verifying: if `HOME` points inside a permitted write root
(`/tmp`, say), the read-confinement selftest cannot observe a denied home read
and activation correctly reports False. That is not a defect — probing a
permitted directory has to be allowed — but it means a container that sets
`HOME=/tmp` will fail closed under `ECAC_REQUIRE_CONFINEMENT=1`. Set a real home
for the executor.

---

## Part B — The approved request is ambiguous

### Evidence

**B1 — `ApprovedRequest` omits identity-bearing fields.**

`model.py:645-653`:

```python
nonce, etype, targets, expiry, task_id, granted_by, content_hash
```

The review asks for a canonical request containing _the task, operation, acting
account, sender, complete recipients, exact content and attachment digests_.
Mapping each requirement against what exists:

| Required by review  | Present in `ApprovedRequest`?                          |
| ------------------- | ------------------------------------------------------ |
| task                | ✅ `task_id`                                           |
| operation           | ⚠️ `etype` only — not e.g. "send-on-behalf"            |
| **acting account**  | ❌ **absent**                                          |
| sender (MAIL FROM)  | ❌ absent                                              |
| complete recipients | ⚠️ `targets`, but not distinguished from other targets |
| exact content       | ⚠️ `content_hash`, ambiguous (see B2/B3)               |
| attachment digests  | ❌ absent                                              |

**Acting account and sender are different things and both are needed.** _Acting
account_ is the principal whose authority is being exercised (the mailbox the
tool is operating on, i.e. whose credentials are in play); _sender_ is the
envelope MAIL FROM. A tool can be authorized to act for `alice@corp.com` while
sending as `noreply@corp.com`. Approving one must not authorize the other.
Today neither is bound, so two operations differing only in sender or acting
account are indistinguishable to the approval.

**B2 — The content hash is ambiguous by construction.**

`model.py:882`:

```python
combined = f"{subject}|{body}"
```

Verified collision:

```
subject='a|b' body='c'   -> a52dd81bfd5e4e66
subject='a'   body='b|c' -> a52dd81bfd5e4e66
```

**B3 — The two processes hash raw bytes differently.**

`model.py:897` decodes with `errors="replace"` before hashing; the subprocess
(`executor_subprocess.py:154`) hashes the bytes directly. Verified:

```
raw bytes  sha: cd85f4c7d89dbebe...
model.py   sha: f5257b9c17daa3fc...    MATCH? False
```

Any non-UTF-8 attachment produces a hash that can never match — so the binding
either blocks legitimately or is bypassed, depending on which side is trusted.

**B4 — The live email effect omits the body.**

`shim_email.py:411-421` puts `subject` and `body_size` into `metadata` but never
`body`. The real `_smtp_send` transmits `raw_msg`, built separately at `:365`.
The effect that was approved and the bytes that were transmitted are not the
same object, and nothing checks that they agree.

### Design

**One canonical structure, hashed over raw bytes.**

```python
@dataclass(frozen=True, order=True)
class CanonicalRequest:
    version: int                     # explicit, for future evolution
    operation: str                   # "send" | "write" | "read" | "delete"
    task_id: str
    acting_account: str              # who is authorised to perform this
    sender: str | None               # MAIL FROM for send
    recipients: tuple[str, ...]      # sorted, complete, primary+BCC+CC
    target: str
    resource_digests: tuple[tuple[str, str], ...]  # (name, sha256hex), sorted
    attachments: tuple[tuple[str, str], ...]       # (name, sha256hex), sorted

    def canonical_bytes(self) -> bytes:
        """Length-prefixed, version-tagged, deterministic. No delimiters."""
```

Why length-prefixing rather than a separator: separators are the defect in B2.
Each field is encoded as `len(field_bytes).to_bytes(8, "big") + field_bytes`,
so no field content can impersonate a boundary.

**Body bytes, not a string.** `resource_digests` for a send carries
`("body", sha256(raw_body_bytes))` and one entry per attachment, each hashed
over raw bytes in the process that will transmit them. Both sides use the same
function — one implementation, imported, not mirrored.

**The executor transmits exactly the approved bytes.** The shim hands over the
raw message; the executor verifies `sha256(raw) == approved.digest("body")`
immediately before the transport call, and refuses otherwise.

### Tasks

- [ ] Add `CanonicalRequest` with `canonical_bytes()` (length-prefixed).
- [ ] Add `sha256_raw(bytes)` as the single hashing helper; delete the
      `decode/encode` path in `model.py` and the mirrored copy in the subprocess.
- [ ] Extend `ApprovedRequest` to carry `request_hash` = sha256(canonical_bytes).
- [ ] Populate `sender`, `acting_account`, full `recipients`, attachment digests
      in `shim_email.send()`.
- [ ] Put the real `body` bytes into the effect (or a digest, per policy) so the
      approved and transmitted payloads are comparable.
- [ ] Executor verifies `request_hash` before dispatch; mismatch ⇒ `denied`.
- [ ] IPC carries `CanonicalRequest` verbatim (see PLAN 6 §B for the
      `LabelException` fields that are currently dropped).
- [ ] Migration: keep `content_hash` as a derived view during transition, with a
      deprecation note, so baselines keep working.
- [ ] Test: `subject='a|b', body='c'` vs `subject='a', body='b|c'` produce
      different `request_hash`.
- [ ] Test: non-UTF-8 attachment produces identical digests in both processes.
- [ ] Test: body mutated between approval and dispatch ⇒ `denied`.
- [ ] Test: `ApprovedRequest` for send A (different sender) does not authorize
      send B.
- [ ] Test: `ApprovedRequest` for acting account A does not authorize the same
      send on behalf of acting account B.
- [ ] Test: adding an attachment blob (same subject/body) changes `request_hash`.

---

## Part C — Provenance semantics: labels, transitions, round-trip

This part covers the review item that the first draft of this plan missed
entirely: _"a valid provenance ID must not permit changing the associated labels
or substituting unrelated content. Explicitly define which transformations
preserve provenance."_

### Evidence

**C1 — A valid provenance ID allows arbitrary re-labelling.** ⚠️ _verified by
execution_

`model.py:444-463` (`is_trusted_provenance`) verifies `provenance_id`,
`scope_hash`, `name` and `content_hash` — but never compares
`confidentiality`/`integrity` against what the registry recorded. Running the
real code:

```
registered labels: PUBLIC UNTRUSTED
forged labels    : CONFIDENTIAL HIGH
is_trusted_provenance(forged) -> True
```

A tool can read a public file, keep the legitimate `prov_id`, and declare the
result `CONFIDENTIAL`/`HIGH`. That defeats Myers–Liskov (claims more secrecy than
held) and Biba (claims more integrity than held) in one move.

**C2 — A declass does not survive the process boundary.** ⚠️ _verified by
execution_

```
tainted before clear: True
tainted after clear : False     # clear_taint(exception) worked
tainted after IPC   : True      # taint is back
```

`session_state_to_dict` (`executor_ipc.py:341-355`) emits `reason` and
`cleared_by` per resource, but `dict_to_session` (`:369-376`) restores only
`reason` via `taint_for_send()`. `cleared_by` is dropped, so a cleared record is
re-created as an active one. A legitimately granted declass therefore becomes a
_false denial_ after crossing into the executor subprocess — exactly the outcome
PLAN 4 is supposed to be able to count honestly (PLAN 6 Part E).

This is the concrete meaning of the review's "inconsistent taint-resource field
names": the dict keys are consistent (`reason`, `cleared_by`), but the restore
path ignores a field it just decoded.

**C3 — No definition of provenance-preserving transformations.**

Grep for `preserves`/`transformation` yields only the prose line
`ARCHITECTURE.md:482` "Authority cannot be widened through transformation or
delegation". There is no function, no table and no test that says which
operations keep a datum's provenance and which break it. Without that,
"provenance is preserved" is neither provable nor falsifiable.

**C4 — What already works (do not "fix" these).** Verified:

- A declass does **not** clear integrity: `check_flow` (`broker.py:1120-1128`)
  evaluates `declass` and `endorse` independently, so a confidentiality release
  leaves the integrity check active — the review's requirement is met.
- `clear_taint(exception)` is safe by default: empty `data_resources` clears
  nothing, `{"*"}` clears all explicitly (`model.py:322-342`).

These two are correct today; changing them during this work would be a
regression. Add regression tests to pin them, and nothing else.

### Design

**Labels are not part of the claim — they are part of the record.**

`is_trusted_provenance` must treat a datum as trusted only when the _whole_
recorded tuple matches:

```python
def is_trusted_provenance(self, datum: Data) -> bool:
    entry = self._read_provenance.get(datum.provenance_id)
    if entry is None or entry.scope_hash != datum.scope_hash:
        return False
    if entry.data.name != datum.name:
        return False
    # NEW: labels are part of identity, not decoration.
    if entry.data.confidentiality != datum.confidentiality:
        return False
    if entry.data.integrity != datum.integrity:
        return False
    if entry.content_hash is not None:
        return compute_content_hash(datum.content) == entry.content_hash
    return True
```

Why this is safe and does not break legitimate labelling: labels are already
derived from trusted OS state in one place — `statx.derive_provenance()`
(statx bits → permission bits → keyword → deny-most), and its integrity is
always `USER` for OS-derived content. So the label recorded at read-commit time
is the authoritative one. A caller that wants a different label must obtain a
\_new committed read under a different capability — not edit the field.

**Provenance transitions, stated explicitly.**

Define, in code and in `ARCHITECTURE.md`, an enumerable set of operations and
whether each preserves provenance:

| Transformation                           | Provenance                                          | Rationale                                                |
| ---------------------------------------- | --------------------------------------------------- | -------------------------------------------------------- |
| identity (`x`)                           | preserved                                           | no change                                                |
| concatenation (`x + y`)                  | preserved only if all inputs trusted; labels = join | result is at least as sensitive/untrusted as worst input |
| substring / slicing                      | preserved                                           | cannot add information                                   |
| parsing / decoding (utf-8, json, base64) | preserved                                           | bijective or narrower; result ⊆ input                    |
| re-encoding / formatting                 | preserved                                           | same information content                                 |
| lossy encoding (e.g. `errors="replace"`) | **broken**                                          | bytes are altered irreversibly                           |
| hashing / encryption                     | preserved as an opaque datum                        | content unavailable, label still travels                 |
| model-generated text                     | **broken**                                          | new content; must be `UNTRUSTED`                         |
| summarisation / translation              | **broken**                                          | new content even when derived                            |
| cross-process transport                  | preserved only if codec is lossless                 | see C2                                                   |

Rule of thumb: a transformation preserves provenance iff its output is a
function of its inputs _and_ every byte of the output is attributable to an
input byte. Anything that invents content breaks it.

**`cleared_by` must survive the codec.**

```python
for resource, rec in resources.items():
    session.taint_for_send(resource=resource, reason=str(rec["reason"]))
    if rec.get("cleared_by") is not None:
        session._tainted_resources[resource].cleared_by = rec["cleared_by"]
```

Better: a dedicated `restore_taint(records)` method rather than reaching into a
private field, matching the existing intent of `dict_to_session` to use the
public API.

### Tasks

- [x] `model.py`: compare `confidentiality` and `integrity` in
      `is_trusted_provenance`.
- [x] `model.py`: reject `HIGH`/`ADMIN` integrity claims whose recorded label
      differs, with the actual vs. recorded labels in the evidence string.
      (`provenance_mismatch_reason()` names the diverging field.)
- [x] `executor_ipc.py`: restore `cleared_by` (dedicated `restore_taint()`).
- [x] Define `PROVENANCE_PRESERVING_TRANSFORMS` as a data table with tests
      asserting one representative input per row.
      (Landed as `effect_broker/provenance_transforms.py`:
      `PROVENANCE_TRANSFORMS`, 22 tests in
      `tests/test_provenance_transforms.py`.)
- [x] Document the transformation table in `ARCHITECTURE.md` and link it from
      `model.py`'s `Data` docstring.
- [x] Add regression tests pinning C4 (declass keeps integrity active; empty
      `data_resources` clears nothing).
- [x] Test: forged labels under a valid `prov_id` ⇒ untrusted (C1).
- [x] Test: declass survives `session_state_to_dict → dict_to_session` (C2).
- [x] Test: lossy decode breaks provenance; lossless decode preserves it.

## Exit criteria

> IDs are the register keys in [REVIEW_REMEDIATION.md](REVIEW_REMEDIATION.md).
> Each must be checked by a test or a grep, never by reading the diff.

1. **P5-1** — On a Landlock-capable kernel, `_selftest_confinement()` proves
   reads/writes outside the sandbox fail with `EACCES`.
2. **P5-2** — On a non-capable host with `ECAC_REQUIRE_CONFINEMENT=1`, the
   executor refuses to run — it does not silently degrade.
3. **P5-3** — `CanonicalRequest` round-trips byte-identically across processes
   for a non-UTF-8 attachment.
4. **P5-4** — Zero ambiguous concatenations remain in the approval path.
5. **P5-5** — README/SECURITY state the enforced mechanism per platform, with no
   code path able to report `landlock` unless the probe passed.
6. **P5-6** — A valid `provenance_id` cannot carry labels that differ from the
   recorded ones — verified by test, not by inspection.
7. **P5-7** — A granted declass survives `session_state_to_dict →
dict_to_session` unchanged (`cleared_by` preserved), so it does not resurface
   as a false denial in the executor process.
8. **P5-8** — The provenance-preserving-transformation table exists in
   `ARCHITECTURE.md` and every row has a test.
9. **P5-9** — An approval for sender/acting-account A does not authorize the same
   operation for B.
10. **P5-10** — Adding or changing an attachment blob (identical subject/body)
    changes `request_hash`.
11. **P5-11** — A declass leaves integrity checks active, and an empty
    `data_resources` clears nothing (regression pins for the two behaviours that
    are already correct).

## Non-goals

- Replacing Landlock with containers (future work; document as deployment
  requirement).
- Seccomp filtering of syscall _numbers_ — Landlock covers path access, which is
  the actual dependency here.

## Risks

- **Platform split.** Development is on macOS where none of this is testable;
  a Linux CI runner is a hard prerequisite, not a nice-to-have.
- **`CanonicalRequest` is an ABI change** — it touches every baseline and every
  trace. Mitigated by the `content_hash` compatibility view.
- **Fail-closed default can break local development.** `ECAC_REQUIRE_CONFINEMENT`
  should default off locally, on in CI, and be loudly reported in both cases.
