# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versioning reflects the **EffectBroker / ECAC** package (`effect-broker`),
whose current `pyproject.toml` version is `0.1.1`.

---

## [Unreleased]

### Changed

- **The five non-blocking comparators now enforce their named mechanism
  .** CaMeL, PACT, ChainCaps, Cordon and ArgProv each
  returned `True` unconditionally: the docstring described a check that was
  never wired to a return value, so they scored 0/20 and every comparative
  claim resting on that number was unsupported — a comparison against a stub
  measures the stub. Each now has a real deny path:

  | Comparator | Enforces                                       | Still misses                  |
  | ---------- | ---------------------------------------------- | ----------------------------- |
  | CaMeL      | IFC: untrusted provenance at a publish sink    | taint, replay, scope, content |
  | PACT       | capability scope covers (etype, target)        | taint, replay, content, BCC   |
  | ChainCaps  | capability scope, EXPAND honored as documented | taint, replay, content        |
  | Cordon     | proposal revalidation: expiry + target match   | taint, provenance, replay     |
  | ArgProv    | argument provenance (untrusted denies)         | capability, scope, taint      |

  Scores are now CaMeL 4/20, PACT 14/20, ChainCaps 3/20, Cordon 3/20,
  ArgProv 6/20 against ECAC's 20/20. `COMPARATOR_MECHANISMS` states
  enforced-versus-omitted per comparator, `tests/test_comparator_honesty.py`
  pins both the counts and the table, and `docs/VERIFICATION.md` no longer
  quotes the 0/20 stub figures. The dead ECAC-setup branch (which imported a
  `_capability` helper that does not exist in `traces.py`) is gone.

- **The comparator honesty test no longer demands a block the host cannot
  perform.** `test_comparator_honesty.py` failed any comparator that declared
  enforced mechanisms yet blocked nothing, which flagged `OS_Sandbox` by design:
  on a kernel without Landlock (or in a container where the syscall is refused,
  as inside `python:3.12-slim`) it reports `mechanism="none"` and blocks 0
  traces. Treating that as a false claim would push the comparator to simulate a
  deny — the dishonesty the file exists to prevent. The exemption is narrow and
  itself checked: it applies only when `mode_os_sandbox.selftest().verified` says
  no mechanism is in effect, and `test_host_exemption_is_not_a_blanket_escape`
  asserts that a host which _can_ confine still has to block something.

### Added

- **Block basis is reported per trace, so a count cannot be read as a
  mechanism.** `baselines.block_basis()` labels every comparison result
  `coverage`, `check` or `none`, and `summarise_basis()` totals them per
  baseline. PACT is the case that motivated it: it blocks 14 of 20 traces, and
  every one of those denials reads `no capability for (etype, target)` — the
  fixture never issued the grant. Those fourteen therefore describe
  **provisioning**, not a check above it, and a reader seeing the bare count
  would credit PACT with fourteen defences.

  Measured on this tree (`summarise_basis(run_comparison())`):

  | Baseline      | blocks by `check` | blocks by `coverage` | allowed |
  | ------------- | ----------------: | -------------------: | ------: |
  | ECAC          |                20 |                    0 |       0 |
  | CaMeL         |                 4 |                    0 |      16 |
  | PACT          |             **0** |               **14** |       6 |
  | ChainCaps     |                 3 |                    0 |      17 |
  | Cordon        |                 3 |                    0 |      17 |
  | PathAllowlist |                 9 |                    0 |      11 |
  | OS_Sandbox    |                 4 |                    0 |      16 |
  | FORGE         |                 9 |                    0 |      11 |
  | Allowlist     |                 2 |                    0 |      18 |
  | ArgProv       |                 6 |                    0 |      14 |

  PACT is the only comparator whose entire score is provisioning rather than
  inspection, and that zero is now a column instead of a sentence.
  `tests/test_block_basis.py` pins the classification, pins that ECAC blocks by
  `check` only, and fails if PACT grows a real check — so the disclosure in
  `docs/VERIFICATION.md` cannot silently rot.

- **The documented gaps are now executable facts.**
  `tests/test_documented_limitations.py` turns three limitations this
  repository cannot close by writing Python into facts the suite verifies.
  - **Same-process mode is detection, not prevention.** A store write reaches
    external state with no gate and no executor, because it is an ordinary
    object in the same address space as the tool. Only process isolation
    closes this.
  - **Network egress is unconfined.** `socket` cannot be blocked by the import
    hook while delivery needs `smtplib`/`imaplib`, and no syscall filter is
    installed, so a compromised subprocess can reach any host.
  - **Envelope discovery depends on the transport.** Envelope-derived
    occurrences must carry `source="smtp-envelope"`, so evidence from the MTA's
    own transaction record stays distinguishable from a probe over addresses the
    broker already knew. A relay that exposes no transactions degrades discovery
    to that probe.

  Each test passes _while the gap exists_ and is worded so that passing is not
  mistaken for success: closing a gap breaks the test and forces the
  documentation to be updated instead of quietly becoming wrong.

- **Mediation is reported as three states in the diagnostic run.**
  `diagnostic_report()["mediation"]` is `{evaluated, complete, failures, note}`,
  so `evaluated=false` is distinguishable from `false`: when the ledger check
  cannot run, `complete` is `None` and the text form prints `NOT EVALUATED`
  rather than a bare `False`, which would send a reader looking for a hole that
  was never searched for.
- **Diagnostic run** `scripts/diagnostic_run.py` and
  `metrics.diagnostic_report()` emit all seven metrics: unauthorized effects,
  legitimate completion, false denials by predicate, UNKNOWN outcomes,
  approvals (granted/used/expired unused), wall-clock overhead (syscall counts
  reported as `null` rather than invented) and the reviewed trusted boundary.
  UNKNOWN is read from the ledger's own verdict, not inferred from gate
  evidence, which carries none.
- **Occurrence records.** `oracle.Occurrence` and
  `count_occurrences` count repeats instead of collapsing them: two identical
  writes are two occurrences, a write followed by a delete keeps both, a
  repeated send is two, and an effect landing outside its window is flagged.
- **Concurrent-ticket coverage in the multiprocess path (P6-3).** Ten threads
  racing one nonce through subprocess `APPLY_COMMIT` yield exactly one commit.
- **The oracle can read a real MTA log.** `oracle.smtp_log` has always carried
  the comment "in a real deployment this is the MTA's mail log, read
  out-of-band", but nothing read one: every caller filled the list in by hand
  from the handler it had just written, which makes the independent observer a
  listener to the sender's own account of itself. `mta_log.read_postfix_log()`
  and `IndependentOracle.from_mta_log()` read the MTA's accounting instead, and
  `hidden_recipients()` names recipients the broker never declared.
  `tests/data/postfix-maillog.txt` was captured from a real Postfix 3.7.11
  instance (`scripts/capture_mta_log.sh`) and holds one honest send and one
  carrying an undeclared BCC. Not a trust boundary — a process that can write
  the log can forge it — but the observations no longer come from the code being
  observed.
- **`oracle.reconcile_unknowns()` settles a crash-torn write from outside the
  writer.** A write that lands and then loses its process stays UNKNOWN for the
  ledger's whole life, because nothing in the write path returns to fill the gap.
  The oracle checks the filesystem and records evidence attributed to
  `oracle.reconcile`, leaving `authorized_not_observed` and absent or non-file
  targets untouched.

### Fixed

- **A declass grant could bypass the integrity (Biba) check, and a
  task-scoped wildcard grant could be reused on another task's effect.**
  `check_flow`'s session-taint branch returned early on a validated declass,
  so the per-datum integrity check was never reached for a tainted send — a
  send steered by an UNTRUSTED datum committed as soon as a declass existed.
  The declass now sets a flag and falls through to the per-datum loop: it
  waives the confidentiality clause only; integrity still runs and only an
  explicit `endorse` clears it. Separately, `LabelException.matches_effect`
  short-circuited on `match_target="*"` before the `task_id` check, so a
  task-scoped wildcard grant matched another task's effect; the task check
  now runs first and is never wildcardable. Pinned by
  `tests/test_declass_integrity.py` and
  `tests/test_wildcard_grant_task_binding.py` (982 passed).

- **An attachment could be swapped without moving the approval hash, and the
  live shim had no attachment support at all.** Writing the round-trip test that
  P3 asked for found three defects rather than one:
  - The live `RealEmailShim` had no attachment support — `send()` took no
    attachment argument and `metadata` never carried one, so an approval covered
    a message with no attachments regardless of what was transmitted.
  - `canonical_request_from_effect` accepted attachment bytes only as `bytes`,
    but `executor_ipc._json_safe` base64-encodes them at the process boundary.
    In multi-process mode every attachment dropped out of the canonical request,
    so `request_hash()` differed between the two paths and **substituting the
    blob left the hash unchanged** — the binding was absent in the most isolated
    mode, which is where the claim matters most.
  - No test reached either path, which is why both were invisible.

  `canonical_request_from_effect` now decodes the base64 form and hashes text it
  cannot decode instead of dropping the field, `RealEmailShim.send()` takes
  `attachments`, `_build_message()` emits real MIME parts, and the effect carries
  the blobs so the gate can bind them. `tests/test_smtp_attachment_binding.py`
  covers the round trip, hash equality across processes, blob substitution, a
  non-UTF-8 payload, name binding, and a live send through aiosmtpd asserting the
  attachment reaches the wire.

- **A shim was judged against the `default` task's mandate, not its own.**
  `FileShim._commit_op()` built `Commit(effect=effect, task=None, ...)`, and
  `gate()` resolves a `None` task by substituting `broker.tasks["default"]`. The
  `task_id` the shim was constructed with reached `IsolatedExecutor` and never
  reached the gate. A shim bound to a task whose ceiling covered only
  `file:///allowed` therefore read `file:///secret/creds.txt` successfully
  whenever the unrelated default task allowed it — the tool's mandate silently
  replaced by another task's. The shim now resolves and passes its own `Task`,
  and `_require_task()` raises `SecurityError` for an unregistered task instead
  of inheriting somebody else's authority. Pinned by
  `tests/test_shim_task_and_holder.py`.
- **A capability could be used by a holder it was not issued to.**
  `_find_capability()` ended with a "last resort" scan matching on
  `(right, target)` and ignoring `holder` entirely, while
  `Auth._check_derivation()` proves only that a capability is _legitimate_
  (root-anchored and monotonically attenuated) and never compares its `holder`
  to the acting tool. Together, a capability issued to `admin` for a specific
  secret file was usable by an unrelated tool. The fallback is removed; lookup
  is restricted to credentials the tool may actually hold (`tool_name`, then
  `EffectBroker`), and a miss returns an unresolvable nonce so Auth fails
  closed.
- **A rejected recipient was reported as a BCC bypass.**
  `executor_subprocess.py` (`real_smtp_probe`) filled `bcc_detected` with the
  addresses the MTA _refused_ while probing only the declared set, so an
  ordinary delivery failure — no such mailbox, greylisting — became an incident
  and the send was refused before delivery, with an error naming an address the
  tool _had_ declared. The probe now reports acceptances and rejections
  separately and never claims to detect BCC: it can only ask about addresses it
  was given, so an undeclared recipient is "not asked", not "rejected". Pinned
  by `tests/test_bcc_rejection_not_bypass.py`, which drives both modes against a
  real MTA and asserts that a refused CC delivers.
- **The `send()` envelope check could not fire, and two tests said otherwise.**
  `shim_email.py` computed `actual_accepted - all_declared` against a probe that
  only ever asks about `all_declared`, so the difference was empty by
  construction. A BCC to a wildcard-scoped capability therefore delivered;
  measured against a live aiosmtpd accepting every recipient. Two tests in
  `tests/test_smtp_real_bcc.py` passed regardless, because they monkeypatch
  `_smtp_probe` to return an address the shim never asked about — they pin the
  wiring, not the discovery, and are now named `..._wiring_...` to say so.
  **Undeclared recipients are confined by `NoAmp` and the capability scope, not
  by this envelope arithmetic.** The check is kept as defence in depth against a
  compromised or lying probe, and
  `test_bcc_envelope_check_cannot_fire` records that it stays silent for an
  honest one.
- **A blocked read still transferred the file into the broker process.**
  `RealFileShim._stat_pre()` opened every regular file and read it in full to
  derive provenance labels, and it ran _before_ `broker.commit()`. A read of a
  file outside the capability scope was refused correctly — after all 4096 bytes
  of it had crossed the boundary into the process doing the refusing.
  Confinement that hands over the secret when it says no is not confinement.
  The pre-probe is now metadata-only (`os.stat`, no `open`) and content is read
  only after the gate returns ALLOW. The keyword heuristic it existed for
  survives as a _post_-authorization upgrade: a world-readable file whose bytes
  say `api_key` still taints the session, because the secret is now in the task
  context regardless of what the permission bits claimed. Pinned by
  `tests/test_no_preauth_content_read.py`, which measures bytes moved on the
  denied path.
- **A CONFIDENTIAL read did not taint the session in same-process mode.**
  `broker._apply_effect()` derived session taint _before_ calling
  `store.apply_effect()`, but the restricted store registers file resources
  lazily inside `apply_effect()`. A pre-apply `store.resolve()` on a path the
  store had never seen returned `None`, the guard was false, and the taint was
  skipped — so a read of a 0o600 file left `session.tainted == False` and the
  follow-up read→send exfiltration passed FlowOK. Multi-process mode masked it,
  because taint arrives there via the subprocess `session_update`; the old suite
  exercised taint only on that path and every same-process test called
  `taint_for_send()` by hand, so neither pinned the broken one. `apply_effect()`
  now applies first and derives taint from the post-apply state. Both modes must
  agree, and `tests/test_session_taint_same_process.py` holds them to it.
- **An authorized read left no observation, so it verified as UNKNOWN.**
  `RealFileShim` recorded a dispatch marker for `read` and never recorded
  evidence afterwards — unlike `write` and `delete`. `ledger.verify()` therefore
  returned `committed_without_evidence` for _every_ legitimate read, which meant
  a real bypass and a normal read produced the same verdict. The invariant
  ("authorized without observation → UNKNOWN, never safe") held, so nothing
  looked wrong; but an audit trail that cannot confirm the commonest operation
  is not an audit trail. Evidence is now recorded in both branches, measured on
  the bytes actually delivered. Pinned by `tests/test_read_evidence.py`.
- **`stat`, `exists` and `listdir` raised after the gate had already allowed
  them.** `RestrictedResourceStore._apply_effect_inner` handled only
  write/read/send/network/delete for `File`, so the metadata operations fell
  through to `ValueError("effect type stat not applicable to File")`. In
  same-process mode the shim calls the store directly, so those calls blew up
  _after_ ALLOW, while in multi-process mode the work happens in the subprocess
  and succeeded. A mode difference in which shim calls work is a mode difference
  in what a tool can be trusted with. The store now records the audit entry and
  returns; these ops mutate nothing and are never treated as content reads, so
  they never taint. Pinned by `tests/test_metadata_ops_parity.py`.
- **A wildcard mandate covered the primary target and not its copies.**
  `_check_no_amplification()` read `"*"` in `capability.scope` as a literal
  string when validating `known_targets.additional`, but as a wildcard for the
  primary target a few lines above — so a capability scoped `{"*"}` could
  address a message and never copy or blind-copy anyone:
  `extra-target-outside-scope(bcc@corp.com not under cap-scope={'*'})`. The
  mandate said "everything" and the enforcement said "nothing extra". It also
  meant a BCC-blocking test passed for the wrong reason, measuring the mangling
  rather than confinement; that test now uses a genuinely restrictive scope, so
  the block comes from NoAmp on merit rather than from the bug. Pinned by
  `tests/test_wildcard_scope_extra_targets.py`.
- **`/etc` was confined as a subtree, so `/etc/shadow` was readable.** Landlock
  grants a subtree, so listing `/etc` as a read root also granted `shadow`,
  `gshadow` and `sudoers`. Measured in a container with ABI 4, a confined
  process read `/etc/shadow` while `_get_confinement_status()` reported
  `restricted-open` — the status string advertised a confinement layer, and the
  one file a reader would ask about was readable through it. `/etc` is no longer
  a root; `_LANDLOCK_READ_FILES` grants the individual files that are needed
  (`hosts`, `resolv.conf`, `passwd`, the CA bundle, …). A file missing from that
  list is unreadable, which fails closed.
- **`ECAC_REQUIRE_CONFINEMENT` was documented as "on in CI" but no CI step set
  it.** Every confinement test therefore ran unconfined and the suite was green
  either way — the failure mode the flag exists to prevent, committed in the act
  of documenting it. The `Test` step now sets it.
- **Outcome counting contradicted the verdict about the same effect.**
  `outcome_of()` classified an `executor.apply` observation as `committed`,
  while `verify()` called the same effect `committed_without_evidence` and
  returned UNKNOWN. `executor.apply` is recorded _before_ a real write reaches
  the filesystem — a process killed in between leaves an observation for a write
  that never happened — so the aggregate metrics reported as committed what the
  audit path reported as unknown, and the metrics are the half people read.
  `outcome_of()` now defers to `verify()`. Pinned by
  `test_outcome_counts.py::test_outcome_of_never_disagrees_with_verify`.
- **`target_for()` resolved an effect to its parent directory.**
  `authorized_targets` records both a written file and its parent, so picking
  `sorted(...)[0]` chose the directory — which always exists, so a check against
  it "succeeded" and settled the effect against a path nobody authorized.
  Ambiguity now returns `None` and the caller reports it. Found by
  `test_oracle_reconcile.py::TestWhatItMustNotTouch`.
- **Two tests reported defects that were preconditions.** The
  read-only-location test fails under uid 0, which ignores directory mode bits,
  and the git-tracking tests crashed where the `git` binary is absent. The first
  now skips under root; the second uses a shared `git_tracks` fixture that skips
  when git is unavailable and still fails an untracked file.
- **Ambiguous request binding.** `CanonicalRequest`
  (`effect_broker/model.py`) binds the full request — operation, acting
  account, sender, complete recipients, attachment digests — and hashes it
  over length-prefixed bytes, so `subject='a|b', body='c'` and
  `subject='a', body='b|c'` no longer collide and a non-UTF-8 attachment
  hashes identically in both processes. The subprocess's mirrored hashing
  copy is gone; both sides call one helper. Attachment blobs now change the
  `request_hash`.
- **Nonce collision on long paths.** `_resolve_capability_nonce`
  truncated the path to its last 40 characters, so two distinct paths
  sharing a 40-char suffix derived the same nonce and a replay of one path
  consumed the freshness of the other. The path is now length-prefixed.
- **Landlock was reported active without ever being applied.**
  `_apply_landlock_sandbox()` called `restrict_self` with the ruleset FD where
  the flags argument belongs, added no rules, and ignored the result — then
  reported `landlock` as an active confinement layer. The ruleset is now
  created with the correct `linux/landlock.h` constants (444/445/446, not 451
  for every call), a `PATH_BENEATH` rule re-opens writes only under
  `ECAC_LANDLOCK_WRITE_ROOT`, and `landlock` appears in the confinement status
  only after a selftest observes a write being denied. The selftest probes a
  path the process can write and does not read an unrelated `EACCES` (the first
  version probed `/etc` and mistook ordinary permissions for confinement).
- **Unconfined execution can now be refused.** `ECAC_REQUIRE_CONFINEMENT=1`
  makes the executor subprocess raise rather than run with no kernel mechanism,
  instead of degrading silently on hosts (e.g. macOS) that cannot confine.
- **Landlock confined writes but not reads.** `_landlock_handled_access()`
  omitted `READ_FILE`, so the kernel left reads unconfined entirely:
  `~/.ssh/id_rsa`, `~/.aws/credentials` and a signing key under `/tmp` all
  opened through the real syscall while the status still reported `landlock`.
  `READ_FILE` is now in the handled mask, with read roots limited to system
  paths, the working directory and the IPC key directory — `~` is deliberately
  unreadable. The selftest gained a two-way read probe: a canary under `$HOME`
  must fail with `EACCES` while a legitimate read still succeeds, and the canary
  is planted before the ruleset applies since afterwards `$HOME` is unwritable.
  The read roots are derived from `sys.path`/`sys.executable` rather than
  hardcoded to `/usr`, because an interpreter under `/opt` (as on the CI runner)
  could otherwise not import the stdlib.
- **Approvals were not bound to the request.** `ApprovedRequest.request_hash`
  was declared but never populated by `grant_approval()` and never checked by
  the gate, so the only binding that ran was `content_hash` — which covers
  etype, targets and content but not the sender or acting account. An approval
  granted for `alice@corp.com` authorized a send as `attacker@evil.com`, and a
  swapped attachment blob with identical subject and body passed. Both sides now
  derive the hash from one canonical definition.
- **An email approval bound no body at all.** `RealEmailShim.send()` put
  `subject` and `body_size` on the effect but never `body`, while
  `_smtp_send()` transmitted a `raw_msg` built separately. With no body,
  `compute_content_hash()` returned `sha256("")` for _every_ send, so the
  `content-hash-mismatch` branch in the gate was unreachable for email: an
  approval a human granted for "quarterly numbers are fine" authorized a wire
  transfer, and `body_size` could not tell the two apart (equal-length bodies
  collided by construction). The shim now carries the exact body text on the
  effect, and the send also binds `sender` and `acting_account`, which the
  canonical request had been reading from metadata that nothing populated.
  `tests/test_email_body_binding.py` exercises the live shim rather than
  hand-built effects — which is why the gap survived the earlier tests, whose
  fixtures supplied `body` themselves.
- **Multi-process email commits crashed after authorization.** The shim's
  effect metadata held a `frozenset` (`bcc_detected`), and
  `executor_ipc._sign_payload` `json.dumps` the whole payload: every email
  commit in multi-process mode raised `TypeError: Object of type frozenset is
not JSON serializable` — after the gate had already allowed the effect, and as
  a crash rather than a denial, so no verdict was recorded. The metadata is now
  JSON-safe, `effect_to_dict()` normalizes set/bytes values generally (not only
  the two keys it happened to know about), and the `content`→`content_b64`
  rename it documents is actually performed rather than assumed.
- **The TCB metric measured the wrong code.** `_TCB_FILES` summed
  `broker.py` and `model.py` while the architecture names the trusted core as
  four modules. `executor.py` — the sole mutation path, i.e. the code an
  attacker must defeat — was not counted, nor was `restricted_store.py`. The
  published figure was ~45% low, and understating the TCB is the direction that
  flatters the claim.
- **The TCB definition lived where CI could not see it.** It sat only in
  `docs/ARCHITECTURE.md`, and `docs/` is gitignored in this repository, so the
  test comparing metric against document **skipped** in CI. The drift above was
  invisible in the only place that runs on every change; green meant nothing.
  The canonical list is now `effect_broker/tcb.py` — tracked, with a stated role
  per module, an `assert_complete()` invoked at import, and tests that fail if
  the registry stops being tracked by git.
- **Docstrings were counted as executable code.** `_count_code_lines` dropped
  comments and blank lines but not docstrings, so prose inside string literals
  counted as logic: 1238 of the 3401 lines it summed were docstrings (+57%). It
  was the same error the comment filter had been added to fix, in the form that
  survived it. Module/class/function docstrings are now excluded by AST, with
  the count falling back to the comment-only figure if a file will not parse.
- **`python -m effect_broker.metrics` ran the wrong report.** The module had two
  `if __name__ == "__main__"` blocks; the first won, so the regression report
  the module is named for was unreachable from the command line and the
  diagnostic table printed instead. There is now one entry point:
  `print_report()` by default, `--diagnostic` for the seven metrics.
- **`tcb_lines` failed the regression gate on every legitimate fix.** It was
  listed as lower-is-better in `metrics_snapshot.py`, so a fix that adds a check
  read as a regression and deleting a module read as an improvement. It is now
  reported as `advisory` and no longer decides the exit code, while false
  positives and false negatives still fail it.
- **The metrics regression gate was never invoked.** `metrics_snapshot.py
--compare` existed but no CI step ran it, so a regression could land unnoticed.
  It is now a CI step, with its baseline in `tests/data/` — a reference file a
  fresh checkout cannot see (`docs/`) would have made the gate a no-op.
- **Latency percentiles are advisory, because they are not percentiles.** The
  scenario set has 6 entries, so `p95` and `p99` _are_ the sample maximum. Over
  8 re-snapshots of unchanged code, `p99` ranged 0.0342–0.0948 ms (2.8×) and the
  old 25% tolerance failed 1 run in 8 on noise alone; on the GitHub runner the
  same build reported p50 0.023 → 0.0407 ms (+77%). A gate that fires on noise
  teaches re-running instead of reading. Latency is still printed in every diff.
- **Send budget was oversubscribed by concurrent sends.** `send_count` was
  incremented only after a successful apply and the gate only read it, so five
  concurrent sends with `max_sends=1` all passed. The gate now reserves a
  ticket in the same critical section as the nonce; the executor commits it on
  success or releases it on failure. The reservation is in-process only —
  concurrent sends across processes are not covered.

### Added

- **Comparator mechanisms table** (`baselines.COMPARATOR_MECHANISMS`). States,
  per comparator, what is enforced and what is omitted. It exists so a
  comparative number can be read against the mechanism that produced it rather
  than against a name.

- **Metrics tripwire** (`scripts/metrics_snapshot.py`). Compares two metric
  snapshots and exits non-zero on regression, so a change that slows the gate
  path gets caught by CI instead of being noticed later.

- **Provenance transforms** (`provenance_transforms.py`). Label-algebra helpers
  for deriving output labels from inputs, with the transform identities pinned
  by tests.

- **Effect states and evidence** (`model.py`). `EffectState`,
  `ALLOWED_TRANSITIONS`, `can_transition()`, and `EffectEvidence` — the last
  makes an unbacked `committed` state unconstructible, so a commit claim must
  carry what backs it. `PostAuthorizationFailure` replaces the "security event"
  mislabel for failures that happen after an effect was authorized.

- **In-flight marker** (`ledger.py`). `record_dispatched()` / `was_dispatched()`
  record that an effect was handed to the OS or the network before it is
  observed, and `verify()` distinguishes "dispatched, never observed" from
  "never dispatched". Without it a crash mid-operation is indistinguishable from
  an effect that was never attempted. Written before the I/O at all three shim
  call sites.

- **The journal is wired into the build path.** `build(journal_path=...)`,
  `collect_outcome_counts(journal_path=...)` and
  `python -m effect_broker --journal PATH` now pass the path down to the
  ledger. Off by default, so nothing that existed before writes a file.

  Observations are journaled too, and that is the load-bearing part. Without
  them a _clean_ run recovered as 29 unknowns: authorizations survived, outcome
  records did not, and recovery reconstructed a field of dispatched-but-
  unobserved effects. A successful shutdown was indistinguishable from a kill,
  and the better the run went the worse it looked. `_replay` now restores
  observations, and `tests/test_journal_wiring.py` pins the difference.

  `reset()` appends a marker instead of truncating, and `_replay` honours it, so
  effects from a previous run cannot reappear after recovery while the record of
  what was in flight is not silently discarded.

- **The journal can now be bounded** (`ledger.py`). `_journal_max_bytes` rotates
  the live file to `<path>.1` once it outgrows the limit, retaining
  `_journal_keep` segments besides it; `from_journal()` replays the segments
  oldest-first so "later record wins" still holds. Growth was previously
  unbounded — roughly 150 bytes per effect, so ~150 MB per million effects, all
  of it re-read on every recovery. Off by default, so existing callers keep one
  file.

  A rotated segment opens with a `segment` marker, and recovery surfaces it as
  `journal_truncated`. Without that the reader would start mid-history, see
  observations whose authorizations had been dropped, and report effects nobody
  authorized — a bypass that never happened, invented by the log that exists to
  detect real ones.

  Reachable from `build(journal_max_bytes=..., journal_keep=...)`,
  `collect_outcome_counts(...)`, `from_journal(...)` and
  `python -m effect_broker --journal PATH --journal-max-bytes N --journal-keep N`.

- **The IN_FLIGHT marker now survives a real crash.** `record_dispatched()`
  fsyncs a one-line JSON record to a journal before the caller reaches the
  syscall, and `IndependentEffectLedger.from_journal()` rebuilds the ledger
  from what is left on disk. Until now the marker existed only in memory, so
  "the process died between the I/O and the bookkeeping" was a state the tests
  constructed by hand and nothing could actually reach — the docstring claimed
  the marker was persisted, and it was not.

  After a kill the verdict is `dispatched_outcome_unknown`, not
  `no_record`: the recovery knows an operation was mid-flight. A torn final
  line is dropped, since a process killed mid-write is the case being
  reconstructed, and replaying does not write back to the journal.

  Persistence is opt-in via `journal_path`; the default stays in-memory, so
  existing behaviour is unchanged.

- **A crash harness that actually kills.** `tests/test_crash_harness.py`
  SIGKILLs a child parked between the marker and the outcome, then asserts what
  the parent recovers. Five of its tests fail if journaling is switched off,
  which was checked by doing exactly that.

- **No commit is reported without evidence** (`ledger.py`, `executor.py`,
  `ipc.py`). `verify()` now returns `UNKNOWN` when an effect has an
  authorization and an observation but no `EffectEvidence` behind it. Until now
  "observed" was enough, and the observation was frequently the executor
  agreeing with itself.

  Which evidence is admissible depends on what actually holds the state, so
  `Commit.store_is_external_state` states it rather than assuming it. For the
  simulated `FileShim` and a plain `broker.commit()` the store _is_ the external
  state -- `_do_write`/`_do_send` are documented NO-OPs -- so the executor's
  record of the mutation is a real measurement and the flag defaults to `True`.
  The real shims set it `False`: there the store only bookkeeps and the bytes
  land later, in `shim_real.write()`, after `commit()` returns. Recording store
  evidence for them put `evidence` in the journal _before_ `dispatched` --
  proof preceding the operation it proves, caught by
  `test_dispatch_precedes_evidence_in_the_file`.

  The subprocess path records evidence from the IPC reply, which is the only
  measurement the parent process can obtain; without it every multi-process
  commit reported `committed_without_evidence`.

- **`LedgerBackend` can carry evidence** (`ipc.py`). `record_evidence` /
  `evidence_for` are on the interface and implemented by `LocalLedgerBackend`
  and `ProcessLedgerClient`, with `RECORD_EVIDENCE` / `EVIDENCE_FOR` requests and
  a serializer for `EffectEvidence` (`frozenset` is not JSON-encodable). They are
  not abstract: a backend that does not support evidence then honestly yields
  `committed_without_evidence` instead of failing to construct.

- **`verify()` reports over-observation before missing evidence.** An extra
  application on a nonce is a distinct finding, and answering it with "no
  evidence" hid the thing worth knowing.

### Added

- **`OS_Sandbox` comparator: kernel-enforced confinement, actually run.**
  `mode_path_allowlist.py` was renamed because it compared strings while
  claiming a sandbox; the rename left the mechanism itself unimplemented. This
  adds it. `effect_broker/baselines/mode_os_sandbox.py` applies a Landlock
  ruleset (Linux) or a seatbelt profile (macOS) and lets the kernel decide, so
  the verdict comes from an attempted operation rather than a `startswith`.

  Its result is 4/20, and the number is the point: it denies writes and reads
  under `/secrets` and permits everything else, because a file sandbox has no
  notion of recipient, provenance, replay or freshness. A comparator that
  blocked all 20 would be trivially correct and would measure a misconfigured
  fixture rather than a mechanism.

  `verified` is True only when a self-test observed both directions — a write
  inside the sandbox root succeeding **and** a write outside it refused by the
  kernel, plus a planted secret being unreadable. The inside-write observation
  is not optional: a ruleset that denies everything also satisfies the other
  two. Where the host cannot confine, `mechanism` is `"none"` and nothing is
  blocked, so the table reports an absent mechanism instead of a score.

  Three defects were found by testing rather than by review, and each now has a
  regression test that fails when it is reintroduced:
  - a read-deny covering the whole fixture root also hid the probe script the
    confined child must read to start, so every observation read as "denied"
    while nothing was being measured;
  - `/secrets` mapped onto the protected directory itself, so the write failed
    with `EISDIR` — a refusal any filesystem would produce with no sandbox at
    all, which the comparison would have credited to the kernel;
  - the refusal reason hard-coded `EACCES`, but seatbelt returns `EPERM` and
    Landlock returns `EACCES`; the reason now quotes the observed errno.

  `tests/test_os_sandbox_comparator.py` (`24` tests) covers all of the above.
  Tests needing confinement skip on a host without it, so an unconfined run is
  never mistaken for a passing one — except on macOS, where the presence of
  `sandbox-exec` makes a failed self-test a failure rather than a skip.

### Changed

- **`mode_conventional_sandbox.py` renamed to `mode_path_allowlist.py`**, and
  the comparator key `ConvSandbox` to `PathAllowlist`. The file compared strings
  on `effect.target` while claiming "seccomp + landlock/SELinux"; the kernel was
  never involved. this allows a comparator to either implement the named
  mechanism or be renamed — this is the rename, since a real one needs kernel
  enforcement (Landlock or seatbelt) and proof that a denied path fails with
  `EACCES`. Trace decisions are unchanged. The `README.md` claims that rested on
  the old name were corrected in the same commit.

- **An observation alone is no longer a commit** -- see above. This changes test
  expectations, not just code: sixteen tests recorded authorization and
  observation straight into the ledger and asserted `CONFIRMED_COMMITTED`, which
  is the contract P4-1 removes. They now record evidence via a
  `commit_evidence()` helper in `tests/conftest.py`.

  Two expectations were inverted rather than updated, because their premises
  contradict an invariant: `EffectEvidence(outcome="committed")` cannot be
  constructed without observed targets, so "wrong source + empty obs ⇒ COMMITTED"
  can never be backed, and dispatch marks intent, which was never sufficient for
  a commit. Both now assert the weaker true thing (the path refuses to
  over-claim); the strong assertion lives in `test_io_evidence.py` and
  `test_crash_harness.py`.

- **TCB size counts code, not comments.** `_count_code_lines` strips comments
  and blank lines, so the reported TCB figure reflects logic rather than
  documentation volume.

- **CI no longer skips the sealed eval.** The `Release eval gate` job used to
  carry `if: github.event_name == 'pull_request' && github.base_ref == 'main'`,
  so it reported as _skipped_ on every push to `develop`/`main` and on every PR
  targeting `develop`. It now runs on every push and every pull request, so the
  sealed evaluation is exercised continuously instead of only at release time.
  On `main` it remains the required `Release eval gate` status check.

- `gate` matrix sets `fail-fast: false`: a failing Python version no longer
  cancels its sibling, which previously surfaced as a _skipped_ required check.

- Added a `concurrency` group to `ci.yml`: a newer commit on the same ref
  cancels superseded runs.

- **Five-outcome accounting** (`committed`, `failed`, `unknown`, `denied`,
  `abandoned`), printed by both entry points. Classification uses closed
  allow-lists rather than exclusion, so an unrecognised observation source is
  reported as unexplained instead of being promoted to a commit.

### Removed

- The explicit `actions/cache` step for `~/.cache/uv` in all jobs. It duplicated
  the cache that `astral-sh/setup-uv` already manages internally (same path,
  same `uv.lock`-based key), so it only added a second, redundant cache entry.

### Fixed

- **A commit claim on the IPC path is now backed by the executor's measurement.**
  The multi-process half of the same defect fixed earlier for the local path:
  `RealFileShim` recorded an observation straight from the subprocess reply and
  claimed `committed` on the strength of "the IPC call returned". The write
  branch now records `EffectEvidence` carrying the size the _executor_ read back
  with `stat()` after writing, and a short write raises instead of reporting a
  clean commit. The delete branch confirms the target is actually gone before
  committing.

  A failure across the process boundary previously left **no** evidence at all:
  `ProcessExecutorClient` wraps subprocess errors in `RuntimeError`, so the
  errno-based handlers never fired, and the case that matters — the operation
  may have landed — read as "never attempted". Those paths now record `unknown`
  evidence before re-raising.

  `tests/test_ipc_evidence.py` drives the real multi-process path through
  `broker.create_real_file_shim()`. Reverting the executor's measurement makes
  it fail with `observed_bytes=None`, which is the point.

- **The outcome counts now agree with the verdict.** `outcome_of()` (which feeds
  the published `committed` / `unknown` tallies) consulted the observation's
  source string _before_ the executor's evidence, while `verify()` had always let
  evidence veto an optimistic observation. So an executor that labelled its
  observation `executor.apply` while its own measurement said `unknown` was
  counted as **committed** by the metrics and reported as **UNKNOWN** by the
  verdict — the published number being the optimistic half of a contradiction.
  Evidence is now consulted first in both, and `tests/test_outcome_consistency.py`
  pins the agreement rather than either function alone. Restoring the old
  ordering makes it fail with `committed=1, unknown=0`.

- **A commit claim for a file effect is now backed by the syscall.** In
  same-process mode `executor.apply` was recorded inside `broker.commit()`,
  which runs _before_ the shim opens the file — so the ledger read "applied"
  for a write that had not happened yet, and reported `CONFIRMED_COMMITTED` for
  a read whose `open()` had raised. `RealFileShim` now records `EffectEvidence`
  after the syscall: the size is read back with `stat()` rather than taken from
  the request, a delete is only committed if the target is actually gone, and
  every failure path leaves `unknown` evidence before raising. `ledger.verify()`
  lets evidence veto a bare observation, so the executor can no longer satisfy
  a commit with its own assertion.

  Scope was the same-process path only at the time; the IPC half is fixed
  separately above.

- **Mediation verdicts are checked, not inferred.** Eighteen sites wrote
  `mediation_complete=not actual_allow` — "the effect was blocked, so mediation
  must be complete". That is inverted in its effect: the more successfully the
  suite blocked, the more confidently it declared mediation complete, and the
  scenario that would expose a hole (one effect escaping while another is
  blocked) was the one nobody checked. `mediation_complete` is now `None` until
  something asks the ledger, alongside `mediation_evaluated`, and
  `__post_init__` rejects either field without the other.

- **A second `all(mediation_complete)` aggregate** in `experiment._main()` had
  the same defect as the one in `__main__.py`; both now require an explicit
  evaluation and report unevaluated results by name.

- **IPC payload fields are required.** `_require_field` makes a missing field
  fail loudly instead of deserializing to `None` and continuing with a value
  that looks legitimate.

- **Label exceptions survive the IPC boundary.** `label_exception_to_dict` /
  `dict_to_label_exception` carry the structured reason across instead of
  degrading it to a string.

- Action runtime warnings from the Node.js 20 deprecation. All actions moved to
  Node 24 lines: `actions/checkout@v7`, `actions/cache` (dropped),
  `actions/setup-python@v7`, `astral-sh/setup-uv@v10.3.3` (pinned exactly — no
  floating `v10` tag exists), `softprops/action-gh-release@v3`.

---

## [0.1.1] - 2026-11-04

### Changed

- **Branch model simplified:** dropped the long-lived `staging` branch. The
  workflow is now `feature/*` -> `develop` -> `main`, with releases identified by
  tags. The QA gate that `staging` used to provide is enforced by the new `eval`
  CI job, which runs on pull requests targeted at `main` (held-out, baseline
  comparison, and experiment assertions).
- `develop` and `main` are both protected: PR + green CI required, and `main`
  additionally requires the `Release eval gate`.

### Added

- **Workflow suite:** split CI/CD into three non-overlapping files:
  - `ci.yml` — quality gate on all PRs and pushes to `main`/`develop`, plus the
    `eval` release gate on `main`-targeted PRs.
  - `pr.yml` — PR hygiene on `pull_request_target`: conventional title check,
    changelog gate (opt out with the `skip-changelog` label), and a non-blocking
    size advisory.
  - `cd.yml` — release pipeline on `v*` tags: validates that the tag is on
    `main`, matches the `pyproject.toml` version, and is documented in the
    changelog; re-runs all gates; builds sdist + wheel and attaches them to a
    GitHub Release with notes taken from the changelog.
- `scripts/verify_traces.sh`, `scripts/verify_eval.sh` — gate assertions shared
  by `ci.yml` and `cd.yml`, so expectations cannot drift between the two.
- `scripts/pr_checks.sh` — PR title / changelog / size checks used by `pr.yml`.
- `make verify` and `make eval` targets for the shared gate scripts.

No deploy target and no PyPI publishing yet; both require an explicit decision.

---

## [0.1.0] - 2026-10-22

Initial baseline of the Effect-Complete Authority Confinement (ECAC) broker,
including project docs and the first real evaluation results.

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
- **Project docs & workflow:**
  - `CONTRIBUTING.md`: branch workflow (`develop` -> `main`, short-lived
    `feature/*`, releases via tags), quality gates, release/tagging process.
  - `CHANGELOG.md`: this file.
  - `.github/PULL_REQUEST_TEMPLATE.md`: PR template aligned with the workflow and
    security-gate review.
  - `SECURITY.md`: vulnerability reporting policy for this research kernel.
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
- `T4'` (SSRF-widening) now blocks via **NoAmp** (SSRF containment) instead of
  Auth: the trace gets a permissive task ceiling via `setup_hook`, so Auth
  passes and NoAmp's containment on the widened external target is the genuine
  primary blocker (matches `test_noamp_flowok_edge_cases.py`).

### Security

- Gate binds the check to the **primitive effect at commit time**, not the
  tool-call argument: no externally committed effect without a machine-checkable
  authority and information-flow derivation.
- **Evaluation results (real runs):**
  - Held-out: **8/8 (100%)** sealed traces blocked (SHA-256 `6e1d14c872d495bd`).
  - Baseline comparison: **ECAC 20/20 (100%)**, next-best baseline 9/20 (45%);
    kill criterion (ECAC ≥4 beyond PACT) passes.
  - Adversarial experiment: **17/18** traces blocked; M4 (benign) correctly allowed.

---

[0.1.1]: https://github.com/merma1509/ecac-for-tas/releases/tag/v0.1.1
[0.1.0]: https://github.com/merma1509/ecac-for-tas/releases/tag/v0.1.0
