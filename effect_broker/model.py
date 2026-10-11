"""Core data types: principals, resources, data values, capabilities, effects

THREE ORTHOGONAL TRUST CONCEPTS (do not conflate):

  1. PROVENANCE (source): WHERE the data came from.
     - Broker-monitored read: Data.provenance_id (+ scope_hash) points to a
       committed read effect.
     - External input: provenance_id=None → UNTRUSTED source.
     - Forged provenance: invalid ID/scope/content mismatch → rejected.

  2. integrity (trustworthiness): how much the label can be trusted.
     - UNTRUSTED: default, minimum (no upgrade possible)
     - USER:      broker's own output (trusted by construction)
     - HIGH/ADMIN: requires a valid broker-monitored provenance chain
     Verified by FlowOK via Session.verify_effect_provenance().

  3. CAPABILITY SCOPE (authorization): what operations the capability
     allows. Stored on Capability.scope, checked by NoAmp/Auth. Unrelated
     to provenance — the scope hash only BINDS a provenance entry to the
     capability that produced it (prevents cross-capability reuse).
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TypedDict

from .lattice import Confidentiality, Integrity


def compute_content_hash(content: str | bytes) -> str:
    """Compute SHA256 hash of content for immutable binding.

    Content hash provides immutable binding for message content.
    This prevents the attack where tool modifies content after approval.
    """
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def compute_scope_hash(capability: Capability) -> str:
    """Derive the capability-scope hash embedded in a provenance ID.

    The scope hash binds a provenance entry to the EXACT capability that
    authorized the read: a provenance_id issued under capability X cannot be
    replayed against data read under capability Y (even if both nonces leaked).

    Deterministic over the capability's authorization-relevant fields:
    right, target and the sorted scope set. (owner/holder/expiry are excluded
    — they do not define the authorization scope and would make the hash
    unstable under re-issue.)
    """
    material = "|".join([capability.right, capability.target, *sorted(capability.scope)])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


@dataclass
class TaintRecord:
    """Per-resource taint record: one resource (file) that was read.

    A session becomes tainted per-RESOURCE (the file that was read), not as a
    single global flag. A narrow declass clears taint only for the resources
    it explicitly covers; the session is "tainted" while ANY resource remains
    uncleared (see Session.tainted / Session.effective_taint).
    """

    reason: str
    timestamp: float = field(default_factory=time.monotonic, repr=False)
    # Nonce of the LabelException that cleared this resource (None = active)
    cleared_by: str | None = None


@dataclass
class ProvenanceEntry:
    """A committed read output, with its scope + content binding.

    The entry carries
    everything needed to verify a Data item is the unmodified output of the
    exact read that issued its provenance_id:
      - scope_hash:  the capability scope the read was authorized under
      - content_hash: SHA256 of the read content, when content is available
                      (None when the broker stores content="")
    """

    data: Data  # the read output as committed
    scope_hash: str  # capability scope this entry was issued under
    content_hash: str | None = None  # None when content not stored


@dataclass
class SessionTaintMetrics:
    """Per-broker session-taint accounting (honest measurement).

    Two DISTINCT quantities are measured and reported separately so the
    taint-rate is never mistaken for a false-denial rate:

      - taint_rate          : how OFTEN reading taints the session (cost signal).
                              Fraction of reads whose content is CONFIDENTIAL.
      - false_denial_proxy  : how OFTEN a taint block was later lifted by an
                              explicit declass (over-blocking signal).

    These are NOT the same thing. A false denial is a LEGITIMATE send that was
    blocked. Without human annotation we cannot label blocks, so we measure a
    PROXY: a send blocked by taint that the user then explicitly declassifies is
    evidence the conservative taint over-blocked. This is the highest-signal
    annotation-free signal available. It is a proxy, NOT ground truth.
    """

    total_reads: int = 0
    reads_that_tainted: int = 0             # read effects that set session taint
    sends_blocked_by_taint: int = 0         # send effects blocked via "session-taint"
    blocked_sends_later_declassed: int = 0  # a taint-blocked send, then a declass
                                            # was granted covering the same task

    @property
    def taint_rate(self) -> float:
        """How often a read taints the session. Cost signal, NOT a denial rate."""
        return self.reads_that_tainted / max(self.total_reads, 1)

    @property
    def false_denial_proxy(self) -> float:
        """Fraction of taint-blocked sends later unblocked by an explicit declass.

        High value => the conservative taint frequently over-blocks legitimate
        workflows. Annotation-free proxy, not ground truth.
        """
        return self.blocked_sends_later_declassed / max(self.sends_blocked_by_taint, 1)

    def to_dict(self) -> dict[str, object]:
        """Serialize for reporting (experiment output)."""
        return {
            "total_reads": self.total_reads,
            "reads_that_tainted": self.reads_that_tainted,
            "sends_blocked_by_taint": self.sends_blocked_by_taint,
            "blocked_sends_later_declassed": self.blocked_sends_later_declassed,
            "taint_rate": self.taint_rate,
            "false_denial_proxy": self.false_denial_proxy,
        }


class Evidence(TypedDict, total=False):
    """Machine-checkable record emitted for every commit decision."""

    allow: bool
    primary_blocker: str | None
    predicates: dict[str, str]
    boundary_stop: str | None
    approval_binding: str | None
    block_reason: str | None
    content_binding_block: bool | None


# Principals
USER = "User"  # sole root of authority
AGENT = "Agent"  # untrusted LLM proposer
TOOL = "ToolAdapter"  # untrusted third-party code
BROKER = "EffectBroker"  # trusted core, the only committer
APPROVER = "Approver"  # human escalation


# Alias for task identifiers (future-proof for typed IDs)
TaskId = str


class Domain(Enum):
    """Email domain class (dom ∈ {internal, external})

    We read email as the email domain, which naturally bundles messages and their mailboxes
    (inbox/outbox) — an email is delivered into a mailbox — plus the address's
    domain class. Mailboxes are therefore part of the email domain
    """

    INTERNAL = "internal"
    EXTERNAL = "external"


# ---- Task / Session types ----
# Task authority ceiling: every effect's authority must be a subset of ceiling(t)
# Session clock: per-task logical time, revocation set, and replay set
@dataclass(frozen=True)
class CommitGateResult:
    """Result of the four-predicate gate evaluation (commit phase 1).

    This is returned by broker.commit() BEFORE any state is applied.
    The executor uses this to decide whether to call apply_effect().
    Separating gate evaluation from state application is the key to
    independent observer verification: the observer can check that
    every applied effect corresponds to a gate pass.

    Fields:
      allow: True if ALL predicates pass AND approval binding is valid
      evidence: machine-checkable record of every predicate verdict
      effect: the committed effect (for applying by the executor)
      task: the task whose session tracks used nonces
      can_apply: True if the effect should be applied to state
    """

    allow: bool
    evidence: Evidence
    effect: Effect
    task: Task
    can_apply: bool  # True if allow AND no boundary stop


@dataclass
class Session:
    """A task's logical clock and per-task revocation/replay state + taint tracking.

    FIXED: Session.live=False now BLOCKs all commits in check_fresh().
    Closing a session explicitly revokes the task's authority ceiling.
    Once live=False, the session CANNOT be reopened — setting live=True
    after it has been False raises ValueError. This enforces that "closed"
    is terminal: the task's authority ceiling is invalidated until explicitly
    re-registered with a new session by the broker (not by directly setting live).

    TAINT TRACKING (for inter-effect composition):
      A session becomes "tainted" when it reads CONFIDENTIAL data. A tainted
      session can still send emails, but ONLY with an explicit broker-recorded
      declass exception — FlowOK blocks the send with "session-taint" reason.
      This prevents the read-secrets→send-attack without requiring taint
      tracking on data VALUES (which needs language-level support).

      The taint is session-scoped: it applies to ALL sends within the session,
      even from different effects. This is a conservative design — it may
      require explicit declass for legitimate workflows where a task reads
      confidential data and then sends a related email (e.g. HR tool reads
      payroll file and emails the summary to the employee).

      To lift taint for a legitimate workflow, the broker must record a
      declass exception via grant_label_exception() BEFORE the send commit.
      The declass must specify the complete target set (no partial declass).

      FlowOK now checks both:
        1. Provenance labels (per-effect, as before)
        2. Session taint (cross-effect, new)
    """

    session_id: str
    logical_time: float = 0.0
    revoked: set[str] = field(default_factory=set)  # revoked capability nonces
    used: set[str] = field(default_factory=set)  # replay-prevention nonce set

    # Private state
    _live: bool = True
    _ever_closed: bool = field(default=False, repr=False)

    # Taint tracking (Per-resource, derived bool for backcompat).
    # A session becomes tainted PER RESOURCE (the file that was read), not as a
    # single global flag. A narrow declass clears taint only for the resources
    # its `data_resources` covers; `tainted` stays True while ANY resource is
    # still uncleared. The derived `tainted` property preserves the old API.
    _tainted_resources: dict[str, TaintRecord] = field(default_factory=dict, repr=False)
    _taint_reason: str = field(default="", repr=False)  # legacy first-reason (derived view)

    # Send rate limiting to prevent amplification via composition.
    # Tracks number of send effects committed in this session. When the
    # count exceeds max_sends_per_session, subsequent sends are blocked.
    # This prevents the "many small sends exfiltrate data" attack pattern.
    _send_count: int = field(default=0, repr=False)
    _max_sends_per_session: int = field(default=0, repr=False)  # 0 = unlimited

    # Trusted provenance chain for integrity verification.
    # Maps provenance_id → ProvenanceEntry (data + scope_hash + content_hash).
    # Only Data whose provenance_id AND scope_hash AND name (and content hash
    # where stored) all match a committed read entry is considered TRUSTED.
    # Data from untrusted sources is UNTRUSTED.
    _read_provenance: dict[str, ProvenanceEntry] = field(default_factory=dict, repr=False)
    _provenance_counter: int = field(default=0, repr=False)  # sequence counter

    @property
    def live(self) -> bool:
        """Read-only view of the session live state."""
        return self._live

    @live.setter
    def live(self, value: bool) -> None:
        """Set the live flag. Once False, cannot be set back to True.

        Raises ValueError if attempting to reopen a closed session.
        """
        if self._ever_closed and value is True:
            raise ValueError(
                f"Session {self.session_id} has been closed and cannot be reopened. "
                "To resume this task, register a new Task with a fresh Session."
            )
        self._live = value
        if value is False:
            self._ever_closed = True

    @property
    def tainted(self) -> bool:
        """BACKCOMPAT: True if ANY resource is still (uncleared) tainted.

        Derived from the per-resource records. Kept as a property so the
        existing `session.tainted` API (FlowOK, executor sync, tests) is
        unchanged. A narrow declass leaves this True until every read
        resource is covered by its `data_resources`.
        """
        return any(r.cleared_by is None for r in self._tainted_resources.values())

    def taint_for_send(self, resource: str = "", reason: str = "") -> None:
        """Taint a SPECIFIC resource (idempotent: first reason wins).

        Per-resource taint. `resource` is the read target (file
        URI); when empty, a synthetic key is used so the call still records a
        taint (backcompat with callers that only pass a reason). After taint,
        any send is blocked by FlowOK unless a broker-recorded declass exists.
        """
        key = resource if resource else "<session>"
        if key not in self._tainted_resources:
            self._tainted_resources[key] = TaintRecord(
                reason=reason or f"read-confidential({key})",
            )
        # Keep a legacy derived reason for evidence messages.
        if not self._taint_reason:
            self._taint_reason = self._tainted_resources[key].reason

    def clear_taint(self, exception: LabelException | None = None) -> None:
        """Clear taint ONLY for resources covered by `exception`.

        Narrow declassification. `exception.data_resources` names
        the file resources whose read-taint this grant clears:
          - frozenset()  -> clears NOTHING (safe default; old whole-clear gone)
          - {"*"}        -> clears ALL taint (explicit wildcard)
          - {path, ...}  -> clears exactly those resources
        When `exception` is None, all taint is cleared (legacy behavior kept
        for internal full-clear callers).
        """
        if exception is None:
            self._tainted_resources.clear()
            self._taint_reason = ""
            return
        # Clear ONLY the resources this exception's data_resources covers.
        # Safe default (empty set) clears nothing; {"*"} clears all.
        for resource, record in self._tainted_resources.items():
            if record.cleared_by is None and exception.covers_taint_resource(resource):
                record.cleared_by = exception.nonce
        self._taint_reason = ""

    def clear_taint_all(self) -> None:
        """LEGACY whole-clear (explicit). New code should use clear_taint(exc)."""
        self._tainted_resources.clear()
        self._taint_reason = ""

    @property
    def taint_reason(self) -> str:
        """First active (uncleared) taint reason, or "" if none. For evidence."""
        for record in self._tainted_resources.values():
            if record.cleared_by is None:
                return record.reason
        return self._taint_reason

    def set_max_sends(self, max_sends: int) -> None:
        """Set the maximum number of sends allowed per session.

        Prevents amplification via composition. When max_sends is reached,
        subsequent sends are blocked by check_noamp().
        """
        self._max_sends_per_session = max_sends

    def increment_send_count(self) -> tuple[bool, str]:
        """Increment send count and check against limit."""
        if self._max_sends_per_session > 0:
            if self._send_count >= self._max_sends_per_session:
                return False, (
                    f"send-rate-limit(max={self._max_sends_per_session}, "
                    f"count={self._send_count}): "
                    f"session exceeded maximum sends per session"
                )
        self._send_count += 1
        return True, ""

    def can_send(self) -> bool:
        """Check if session can send more (without incrementing)."""
        if self._max_sends_per_session <= 0:
            return True
        return self._send_count < self._max_sends_per_session

    @property
    def send_count(self) -> int:
        """Current send count for this session (read-only)."""
        return self._send_count

    @property
    def max_sends(self) -> int:
        """Maximum sends allowed per session (read-only). 0 = unlimited."""
        return self._max_sends_per_session

    # ---- Trusted provenance chain (capability-scoped) ----
    def register_read_provenance(
        self,
        data: Data,
        cap_nonce: str,
        capability: Capability | None = None,
        content: str | bytes | None = None,
    ) -> str:
        """Register a read effect's output in the provenance chain.

        The entry is bound to the authorizing capability's scope.
          - scope_hash   = sha256(right|target|sorted(scope))[:16]  (or "<none>")
          - content_hash = sha256(content) when content is provided, else None
                          (the broker stores read content="" and passes content=None,
                          so the content check degrades to None — a legacy
                          read_output is not content-bound).

        Returns the provenance_id (e.g. "read:default:cap:001") that must be
        included in subsequent effects using this data. The broker calls this
        when a read effect commits.
        """
        self._provenance_counter += 1
        prov_id = f"read:{self.session_id}:{cap_nonce}:{self._provenance_counter}"
        scope_hash = compute_scope_hash(capability) if capability is not None else "<none>"
        content_hash = compute_content_hash(content) if content is not None else None
        # Store the committed read output with its provenance_id.
        labeled = Data(
            name=data.name,
            confidentiality=data.confidentiality,
            integrity=data.integrity,
            content=data.content,
            provenance_id=prov_id,
            scope_hash=scope_hash,
        )
        self._read_provenance[prov_id] = ProvenanceEntry(
            data=labeled, scope_hash=scope_hash, content_hash=content_hash
        )
        return prov_id

    def get_provenance(self, prov_id: str) -> Data | None:
        """Look up the committed read output by provenance_id (None if unknown)."""
        entry = self._read_provenance.get(prov_id)
        return entry.data if entry is not None else None

    def get_provenance_entry(self, prov_id: str) -> ProvenanceEntry | None:
        """Look up the full ProvenanceEntry (data + scope_hash + content_hash)."""
        return self._read_provenance.get(prov_id)

    def is_trusted_provenance(self, datum: Data) -> bool:
        """True if `datum` is the unmodified output of a committed read.

        verifies ID AND scope AND (content hash where stored).
        A datum is trusted only if:
          - its provenance_id exists in the registry, AND
          - its scope_hash matches the capability scope that issued it
            (prevents cross-capability reuse of a leaked provenance_id), AND
          - its name matches the committed read output, AND
          - if the entry recorded a content hash, the datum content matches it.
        Data without a provenance_id, or with a wrong scope/name/content, is
        UNTRUSTED (a forge cannot mint a valid scope_hash).
        """
        if datum.provenance_id is None or datum.scope_hash is None:
            return False
        entry = self._read_provenance.get(datum.provenance_id)
        if entry is None:
            return False
        if entry.scope_hash != datum.scope_hash:
            return False
        if entry.data.name != datum.name:
            return False
        if entry.content_hash is not None:
            return compute_content_hash(datum.content) == entry.content_hash
        return True

    def verify_effect_provenance(self, effect: Effect) -> tuple[bool, str]:
        """Verify high-integrity data comes from trusted, in-scope broker reads.

        Data claiming HIGH or ADMIN integrity MUST have a valid provenance_id
        AND scope_hash (and matching content where bound) pointing to a
        broker-committed read. This prevents the integrity-upgrade and
        cross-capability-reuse attacks:
          - LLM claims HIGH integrity with no/bad provenance  -> BLOCK
          - Forge reuses a leaked prov_id under a wrong scope -> BLOCK
          - Committed read output with matching scope         -> ALLOW

        USER and UNTRUSTED integrity are ALWAYS ALLOWED (minimum trust, no
        upgrade possible; USER = the broker's own read output).
        """
        for datum in effect.provenance:
            if datum.integrity < Integrity.HIGH:
                continue  # always allowed: USER/UNTRUSTED
            if not self.is_trusted_provenance(datum):
                return False, (
                    f"untrusted-provenance("
                    f"datum={datum.name}, "
                    f"integrity={datum.integrity.name}, "
                    f"prov_id={datum.provenance_id!r}, "
                    f"scope={datum.scope_hash!r}): "
                    f"HIGH+ integrity requires broker-monitored origin whose "
                    f"provenance_id, scope_hash and name all match a committed read."
                )
        return True, "trusted"


@dataclass(frozen=True)
class Capability:
    """Object-capability style capability. Issued only by monotonic attenuation

    owner         : the root principal that seeded the authority (only a root
                    may seed a new grant; everything else attenuates an existing capability)
    holder        : the principal currently holding the capability
    right         : one of read|write|send|delete|commit
    target        : the specific resource the capability authorizes
    scope         : the allowed target scope (must narrow monotonically on attenuation)
    expiry        : unix/logical time after which the capability is stale
    nonce         : unique identifier (also used for replay detection)
    task_id       : the task this capability is scoped to; None = any task
    derives_from  : nonce of the parent this was attenuated from, or None if
                    this is a root grant. Used by NoAmp to prove root-anchored, monotonic derivation
    revoked       : True if the capability has been explicitly revoked
    """

    owner: str
    holder: str
    right: str
    target: str
    scope: frozenset[str]
    expiry: float
    nonce: str
    task_id: TaskId | None = None
    derives_from: str | None = None
    revoked: bool = False


@dataclass
class Task:
    """A task carrying an authority ceiling and per-task policy bounds

    The commit rule requires authority(e) ⊆ ceiling(t) for every effect
    committed within this task. FlowOK uses the task's flow_boundary rather
    than a global lattice. The Session carries the per-task
    clock/revocation/replay model
    """

    task_id: TaskId
    owner: str  # the user this task belongs to
    ceiling: Capability  # widest authority this task may exercise
    flow_boundary: tuple[Confidentiality, Integrity] = (Confidentiality.INTERNAL, Integrity.USER)
    session: Session | None = None

    def __post_init__(self) -> None:
        # Lazily create a default session so callers can construct a Task
        # without explicitly constructing a Session
        if self.session is None:
            self.session = Session(session_id=self.task_id)


@dataclass(frozen=True)
class File:
    """A file resource (F). Sensitivity uses the confidentiality lattice"""

    path: str
    sensitivity: Confidentiality


@dataclass(frozen=True)
class Email:
    """An email resource (E): target address + domain class"""

    address: str
    domain: Domain


@dataclass
class Mailbox:
    """A mailbox resource (M): belongs to one user, holds inbox/outbox messages

    Inbox holds incoming messages; outbox holds messages this user sent. A
    `send` effect appends to the sender's outbox; a `read` effect retrieves a
    message from a mailbox. The address -> owning-user association is maintained
    by the ResourceStore (see `mailbox_for`)
    """

    user: str
    inbox: list[str] = field(default_factory=list)
    outbox: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class URL:
    """A network resource (N), identified by URI string

    The scope is a frozenset of allowed domain strings (e.g. {"internal.corp.com"})
    used by NoAmp/Auth for SSRF containment: a network effect whose URL domain
    is not within the capability's scope is rejected by the gate
    """

    uri: str
    scope: frozenset[str]


# Union of all resource kinds — R = F ∪ E ∪ M ∪ N (files, emails, mailboxes, URLs)
Resource = File | Email | Mailbox | URL


@dataclass(frozen=True)
class EffectTarget:
    """Complete identity of an effect's resource targets.

    Unlike a single `target` string, this captures ALL resources an effect
    actually touches. This is the key for full-effect-identity matching:
    the observer must verify that the authorized target set exactly matches
    the observed resource set — not just the declared primary target.

    For a simple write to a file, this is just {target}. For a send with
    BCC/CC recipients, this is {primary, bcc1, bcc2, ...}. For a send with
    attachments, it includes those too. For a read, it covers the file plus
    any side-channel writes (T14 hidden exfil).
    """

    primary: str  # the target submitted to the broker gate
    additional: frozenset[str] = frozenset()  # extra resources touched (e.g. BCC recipients)


@dataclass(frozen=True)
class ApprovedRequest:
    """An immutable authorization binding: exact (etype, targets, task_id, content_hash).

    Approvals are one-shot: they may authorize exactly the effect they were
    granted for, and NO variation. The binding covers:

    - etype:     operation type (read/write/send/delete/network)
    - targets:   complete set of resources this authorizes (including BCC)
    - task_id:   the task this approval is scoped to
    - content_hash: SHA256 hash of the effect's content (body, subject, etc.)
    - expiry:         time after which this approval is invalid

    content_hash is now part of the immutable binding. This prevents
    the attack where tool modifies the message content after approval:
      1. Tool requests send with body="Q3 budget is $50k"
      2. Human approves (content_hash stored)
      3. Tool modifies metadata: body="Wire $500k to attacker"
      4. Commit verifies SHA256(new_body) == stored.content_hash
      5. BLOCKED — content mismatch detected!

    For effects without content (read, delete), pass content_hash=None.

    Killing criterion #5: exact immutable request binding.
    Using this approval for a different etype, different targets, a different
    task, or different content is blocked by ApprovalBinding.
    """

    nonce: str  # unique one-shot token (consumed after first use)
    etype: str  # operation type this was approved for
    targets: EffectTarget  # complete authorized target set (primary + additional)
    expiry: float  # time after which this approval is invalid
    task_id: TaskId  # task scope: this approval is ONLY valid in this task
    granted_by: str  # who granted it (USER or APPROVER)
    # Content hash for immutable binding. Prevents content modification after approval.
    # None for effects without content (read, delete, etc.)
    content_hash: str | None = None


@dataclass(frozen=True)
class Data:
    """A data value carrying confidentiality and integrity labels.

    Provenance labels (confidentiality/integrity) are assigned based on
    the data's source, not derived from real dataflow in this same-process
    model. Content is NOT included in immutable request binding — that would
    break legitimate dynamic content (e.g. different message body per send
    invocation). Provenance/integrity is validated by FlowOK at commit time.

    TRUSTED PROVENANCE CHAIN:
      provenance_id links Data to the broker-monitored read effect that
      produced it. Only Data with a valid provenance_id (pointing to a
      committed read effect) is considered TRUSTED. Data from untrusted
      sources (LLM claims without provenance_id) is UNTRUSTED by default.

      The broker maintains a _read_provenance registry: read_effect_id → Data.
      When a read effect commits, its output Data is stored with provenance_id.
      Subsequent effects that use this data carry the provenance_id, and
      FlowOK verifies the chain is unbroken (the read was actually committed
      through the broker, not forged by an attacker).

      Example flow:
        1. Read /secrets → committed → broker stores read_result(secrets) with
           provenance_id="read:default:read-secrets:001"
        2. Tool claims data with integrity=USER, provenance_id="read:default:..."
        3. FlowOK checks: does broker._read_provenance contain this ID?
           YES → Data is from broker-mediated read → TRUSTED
           NO  → Data is from untrusted source → UNTRUSTED
    """

    name: str
    confidentiality: Confidentiality
    integrity: Integrity
    content: str = ""
    # Trusted provenance chain ID.
    # Format: "read:{task_id}:{capability_nonce}:{sequence}"
    # None = untrusted source (LLM claim without broker-mediated origin).
    # When set, the broker verifies this ID exists in _read_provenance.
    provenance_id: str | None = None
    # Capability-scope hash.
    # Three orthogonal concepts (do not conflate):
    #   SOURCE    (provenance_id): where this data came from — a committed read.
    #   INTEGRITY (integrity):     how much the label can be trusted.
    #   SCOPE     (scope_hash):    which capability authorized the read.
    # scope_hash binds the datum to the EXACT capability scope that issued its
    # provenance_id, so a provenance_id issued under capability X cannot be
    # replayed against data "read" under capability Y (even if the ID leaked).
    # None = legacy datum without scope binding (rejected by FlowOK provenance
    # check for HIGH+ integrity — a forge cannot mint a valid scope_hash).
    scope_hash: str | None = None


@dataclass(frozen=True)
class LabelException:
    """A validated declass/endorse grant (broker-only privilege)

    declass/endorse are privileged operations performed ONLY by the EffectBroker
    on explicit User Policy or a validated approval. The LLM may request such
    an exception, but may never perform it — only the broker records one here
    after checking policy

    - kind:              "declass" | "endorse"
    - match_target:      primary resource/effect target this applies to ("*" = any)
    - from_label:        source confidentiality/integrity label
    - to_label:          target label the flow is (re)classified to
    - granted_by:        the principal that authorized it (USER or APPROVER)
    - nonce:             unique id (single-use if tracked)
    - additional_targets: frozenset of extra targets this applies to (BCC recipients,
                          etc.). If empty, the exception applies ONLY to the
                          primary target. An empty set means no extra targets.
    - etype:             operation type this applies to ("*" = any). If None, the
                          exception applies to any etype.
    - task_id:           task this exception is scoped to. If None, valid in any task.
                          For session-taint clearing, this must match the current task.
    """

    kind: str  # "declass" | "endorse"
    match_target: str
    from_label: str
    to_label: str
    granted_by: str
    nonce: str
    additional_targets: frozenset[str] = frozenset()  # extra targets (BCC, etc.)
    etype: str | None = None  # operation type, or None for any
    task_id: TaskId | None = None  # task scope; None = any task
    # File resources whose READ TAINT this declass clears.
    # This is DISTINCT from match_target/additional_targets (the SEND targets
    # checked by matches_effect). Taint resources are the READ targets (file
    # URIs). The safe default (empty set) clears NO taint; {"*"} clears all.
    data_resources: frozenset[str] = frozenset()

    def covers_taint_resource(self, resource: str) -> bool:
        """True if this declass clears the read-taint of `resource` (a file URI).

        `resource` is the READ target that tainted the session.
        `*` is an explicit wildcard clearing all; otherwise the resource must
        be named in data_resources. The safe default (empty data_resources)
        clears nothing — the old implicit "clear everything" is removed.
        """
        return "*" in self.data_resources or resource in self.data_resources

    def matches_effect(self, effect: Effect) -> bool:
        """True if this exception applies to the given effect.

        Checks:
          - etype matches (if set)
          - from_label matches the violating datum's label
          - target set is contained in the exception's authorized target set
            (i.e., the effect's complete_targets() ⊆ authorized_targets)
            EXCEPTION: match_target="*" matches ANY target set (wildcard)

        This is the "exact effect identity" check for declass/endorse grants.
        A grant for "send to internal@corp.com" does NOT also authorize
        "send to internal@corp.com with BCC to external@attacker.com" unless
        additional_targets explicitly includes external@attacker.com.
        """
        # Check etype
        if self.etype is not None and effect.etype != self.etype:
            return False

        # Wildcard match_target="*" matches any target set
        if self.match_target == "*":
            return True

        # Build the authorized target set
        authorized_targets = frozenset({self.match_target}) | self.additional_targets

        # Check complete_targets() ⊆ authorized_targets
        effect_targets = effect.complete_targets()
        if not (effect_targets <= authorized_targets):
            return False

        # Task scope check: if task_id is set, it must match
        if self.task_id is not None:
            effect_task_id = effect.task_id or "default"
            if effect_task_id != self.task_id:
                return False

        return True


@dataclass(frozen=True)
class Effect:
    """A PREPARED (staged, non-mutating) effect.

    read|write|send|delete are prepared. They never touch external state
    on their own — only a `Commit` (invoked by the broker) does. Note: `commit`
    is NOT an etype here; it is the separate `Commit` primitive the broker performs.

    `known_targets` captures the complete set of resources this effect touches.
    For a simple write to a file this is just {target}. For a send with BCC/CC
    recipients, this is {primary, bcc1, bcc2, ...}. The EffectObserver uses
    this to verify complete effect identity — not just the declared primary target.

    `task_id` binds this effect to the task whose ceiling bounds its authority
    (authority(e) <= ceiling(t) is enforced by Auth at commit time).
    """

    etype: str  # read|write|send|delete  (prepared only)
    target: str  # primary resource target
    metadata: dict[str, object]  # extra context (BCC recipients, etc.)
    provenance: tuple[Data, ...]  # values influencing the effect
    capability_nonce: str
    delegation_chain: tuple[str, ...]  # principals in the delegation chain
    # Optional validated declass/endorse exceptions attached to this effect
    # Only the broker fills this; the LLM may only request them
    label_exceptions: tuple[LabelException, ...] = ()
    task_id: TaskId | None = None  # task whose ceiling bounds authority; validated at commit
    # Complete set of resources this effect actually touches (for effect identity matching).
    # The EffectObserver verifies: observed_resources ⊆ authorized_targets ⊆ observed_resources.
    # For send with BCC: this includes all BCC recipients. For hidden-write: includes secrets.
    known_targets: EffectTarget | None = None

    def complete_targets(self) -> frozenset[str]:
        """Canonical source: complete set of resources this effect touches

        Priority:
          1. known_targets.additional  — authoritative (set by shim or builder)
          2. metadata["extra_resources"] as list  — BCC recipients fallback
          3. metadata["bcc_*"] keys  — legacy BCC metadata
          4. metadata["extra_resources"] as str  — single string fallback

        Returns: frozenset {primary} ∪ {additional recipients}.
        All three call-sites (broker.commit, executor.execute, grant_approval)
        MUST use this method — never re-extract from metadata independently
        """
        targets: set[str] = {self.target}

        if self.known_targets is not None:
            # Authoritative: known_targets is set by the shim/executor builder
            targets |= self.known_targets.additional
        else:
            # Fallback for direct Effect construction (no known_targets):
            # extract extra targets from metadata
            extra = self.metadata.get("extra_resources", [])
            if isinstance(extra, list):
                targets |= set(extra)
            elif isinstance(extra, str):
                targets.add(extra)

            # Legacy BCC metadata keys (e.g. bcc_1, bcc_2, ...)
            for key, val in self.metadata.items():
                if key.startswith("bcc"):
                    if isinstance(val, list):
                        targets |= set(val)
                    elif isinstance(val, str):
                        targets.add(val)

        return frozenset(targets)

    def compute_content_hash(self) -> str | None:
        """Compute content hash for immutable binding.

        Returns SHA256 hash of the effect's content (body, subject, etc.)
        for verifying that content wasn't modified after approval.

        Content is derived from metadata fields: body, subject, content.
        Returns None for effects without content (read, delete, etc.).
        """
        # For send effects, hash the body + subject
        if self.etype == "send":
            body = self.metadata.get("body", "")
            subject = self.metadata.get("subject", "")
            if isinstance(body, str) and isinstance(subject, str):
                # Combine body and subject for a single content hash
                combined = f"{subject}|{body}"
                return compute_content_hash(combined)

        # For write effects, hash the content being written
        if self.etype == "write":
            # Handle both direct content (bytes/str) and base64-encoded content
            import base64
            content_raw = self.metadata.get("content", "")
            if content_raw is None or content_raw == "":
                # Also check for base64 encoded content (from IPC-safe shim)
                content_b64 = self.metadata.get("content_b64", "")
                if isinstance(content_b64, str) and content_b64:
                    content_raw = base64.b64decode(content_b64)
            if isinstance(content_raw, bytes):
                content_raw = content_raw.decode("utf-8", errors="replace")
            if isinstance(content_raw, str) and content_raw:
                return compute_content_hash(content_raw)

        # For read/delete effects, there's no mutable content to bind
        return None


@dataclass(frozen=True)
class Commit:
    """The commit primitive that changes external state.

    read/write/send/delete are PREPARED; only COMMIT changes external state,
    and only the EffectBroker may invoke it. A Commit wraps a prepared Effect;
    the broker applies it only after the four-predicate gate
    (Auth and FlowOK and NoAmp and Fresh) passes at commit time.

    `task` carries the authority ceiling and session state needed by the
    predicates. `tool_name` optionally names the MCP tool performing this effect
    — the broker's Mediator consults its ToolSpec to detect declared-vs-actual
    mismatches (T13/T14/T15 boundary failures).

    `approved_request` captures the immutable authorization binding from an
    approval grant (if this effect was approved). The EffectObserver uses
    approved_request.targets and approved_request.task_id to verify the
    effect's complete identity — preventing modifications after approval.
    """

    effect: Effect
    task: Task | None = None  # None → broker creates a permissive default Task
    tool_name: str | None = None  # MCP tool name for boundary mediation
    # Immutable authorization binding from an approval grant.
    # When set, the effect's complete identity must match this binding:
    #   - etype must match
    #   - known_targets must be ⊆ approved_request.targets
    #   - task_id must match (cross-task use is blocked)
    approved_request: ApprovedRequest | None = None
    # Content hash of the authorized payload (write content or send body).
    # The shim computes this BEFORE broker.commit() and includes it in the
    # commit so that both gate evaluation and execution verification use
    # the SAME hash. This closes the gate↔execute coupling gap in same-process
    # mode (IPC mode already had this via executor_subprocess._verify_content_binding).
    authorized_content_hash: str | None = None