"""Core data types: principals, resources, data values, capabilities, effects"""

from __future__ import annotations

import hashlib
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

    # Taint tracking: session-level taint from reading CONFIDENTIAL data.
    # Set when a read effect reads a CONFIDENTIAL file. Cleared only when
    # an explicit declass exception is recorded by the broker (not by LLM).
    _tainted: bool = field(default=False, repr=False)
    _taint_reason: str = field(default="", repr=False)  # human-readable reason

    # Send rate limiting to prevent amplification via composition.
    # Tracks number of send effects committed in this session. When the
    # count exceeds max_sends_per_session, subsequent sends are blocked.
    # This prevents the "many small sends exfiltrate data" attack pattern.
    _send_count: int = field(default=0, repr=False)
    _max_sends_per_session: int = field(default=0, repr=False)  # 0 = unlimited

    # Trusted provenance chain for integrity verification.
    # Maps read_effect_id → output Data from that read.
    # Only Data with a valid provenance_id (pointing to a committed read)
    # is considered TRUSTED. Data from untrusted sources is UNTRUSTED.
    _read_provenance: dict[str, Data] = field(default_factory=dict, repr=False)
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
        """True if this session has read CONFIDENTIAL data without declass."""
        return self._tainted

    def taint_for_send(self, reason: str = "") -> None:
        """Mark the session as tainted (confidential data was read).

        After taint, any send effect is blocked by FlowOK unless a broker-recorded
        declass exception exists. The reason describes what was read.
        """
        self._tainted = True
        if reason:
            self._taint_reason = reason

    def clear_taint(self) -> None:
        """Clear taint (only after broker records a declass exception)."""
        self._tainted = False
        self._taint_reason = ""

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

    # ---- Trusted provenance chain ----
    def register_read_provenance(self, data: Data, cap_nonce: str) -> str:
        """Register a read effect's output in the provenance chain.

        Returns the provenance_id (e.g. "read:default:cap:001") that
        must be included in subsequent effects using this data.
        The broker calls this when a read effect commits.
        """
        self._provenance_counter += 1
        prov_id = f"read:{self.session_id}:{cap_nonce}:{self._provenance_counter}"
        # Store the data with its provenance_id
        labeled = Data(
            name=data.name,
            confidentiality=data.confidentiality,
            integrity=data.integrity,
            content=data.content,
            provenance_id=prov_id,
        )
        self._read_provenance[prov_id] = labeled
        return prov_id

    def get_provenance(self, prov_id: str) -> Data | None:
        """Look up a provenanced data item by ID.

        Returns None if the provenance_id is unknown (data forged or stale).
        """
        return self._read_provenance.get(prov_id)

    def is_trusted_provenance(self, prov_id: str | None) -> bool:
        """True if prov_id is a valid, broker-committed provenance.

        Data with a valid provenance_id is TRUSTED.
        Data without provenance_id (or with unknown ID) is UNTRUSTED.
        """
        if prov_id is None:
            return False  # untrusted: no broker-mediated origin
        return prov_id in self._read_provenance

    def verify_effect_provenance(self, effect: Effect) -> tuple[bool, str]:
        """Verify high-integrity data comes from trusted broker reads.

        Data claiming HIGH or ADMIN integrity MUST have
        a valid provenance_id pointing to a broker-committed read. This prevents
        the integrity upgrade attack:
          - LLM claims data is HIGH integrity (forge) → BLOCK (no provenance)
          - Trusted read output from broker has provenance_id → ALLOW

        USER and UNTRUSTED integrity are ALWAYS ALLOWED:
          - USER: the broker's own default for read output (trusted by construction)
          - UNTRUSTED: already at minimum integrity (no upgrade possible)

        The integrity threshold is HIGH: only the most sensitive integrity levels
        require broker-monitored origin to be trusted.
        """
        for datum in effect.provenance:
            # Only check HIGH+ integrity (ADMIN, SYSTEM).
            # USER: broker's own default for read output (always trusted).
            # UNTRUSTED: already minimum integrity (no upgrade possible).
            if datum.integrity < Integrity.HIGH:
                continue  # always allowed: USER/UNTRUSTED
            if not self.is_trusted_provenance(datum.provenance_id):
                return False, (
                    f"untrusted-provenance("
                    f"datum={datum.name}, "
                    f"integrity={datum.integrity.name}, "
                    f"prov_id={datum.provenance_id!r}): "
                    f"HIGH+ integrity requires broker-monitored origin. "
                    f"Only data from committed read effects has valid provenance_id."
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




