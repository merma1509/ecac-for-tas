"""Mutable external state (R = F ∪ E ∪ M ∪ N) the broker may mutate

The pure resource *types* (File, Email, Mailbox, URL, Domain, Resource) live in
`model.py` alongside the rest of the model (P + R + Effect). This module holds
only the mutable `ResourceStore`: the "external state" that effects act upon

Only the EffectBroker may mutate resources via the commit primitive
(commit_effect); the LLM and tool code never touch this store directly
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import URL, Effect, Email, File, Mailbox, Resource


@dataclass
class ResourceStore:
    """The external state the broker may mutate. Only `commit_effect` writes here

    - files:    path -> File
    - emails:   address -> Email
    - mailboxes: user -> Mailbox
    - effects_log: append-only record of effects the broker actually committed
      (proves the "prepared vs committed" split: nothing mutates unless the
      broker's predicate gate passed)
    """

    files: dict[str, File] = field(default_factory=dict)
    emails: dict[str, Email] = field(default_factory=dict)
    mailboxes: dict[str, Mailbox] = field(default_factory=dict)
    effects_log: list[tuple[str, str]] = field(default_factory=list)

    def resolve(self, target: str) -> Resource | None:
        """Look up a resource by its target string (id)"""
        if target in self.files:
            return self.files[target]
        if target in self.emails:
            return self.emails[target]
        if target in self.mailboxes:
            return self.mailboxes[target]
        # URLs are indexed by URI string (e.g. "http://example.com")
        if target.startswith("http://") or target.startswith("https://"):
            return self._url_for(target)
        return None

    def _url_for(self, uri: str) -> URL:
        """Resolve a URI string to a URL resource, creating one if needed

        The URL's scope is inferred from the URI's domain for SSRF containment
        """
        # Parse domain from URI for scope inference
        domain = uri.split("://", 1)[1].split("/")[0] if "://" in uri else uri
        return URL(uri=uri, scope=frozenset({domain}))

    def mailbox_for(self, email: Email) -> Mailbox:
        """Resolve an email address to its owner's mailbox (address -> user)

        For the minimal model the mailbox owner is the local part of the
        address (the part before '@'); the domain class (internal/external)
        determines which mailbox space it belongs to. This is the address ->
        mailbox association the report describes
        """
        local = email.address.split("@")[0]
        return self.mailboxes.setdefault(local, Mailbox(local))

    def apply_effect(self, effect: Effect) -> None:
        """Mutate external state for a committed (allowed) effect

        Intended to be called ONLY by EffectBroker.commit_effect after the
        predicate gate passed. This is the single point where "prepared"
        effects become real side effects

        Semantics:
          - write/delete act on files
          - send delivers into the sender's OUTBOX (address -> mailbox)
          - read retrieves a message from a mailbox (target may be an address
            or a mailbox)
          - network is logged with no persistent resource
        """
        target_id = effect.target
        resource = self.resolve(target_id)
        if resource is None:
            raise KeyError(f"effect targets unknown resource: {target_id}")

        if effect.etype == "delete" and isinstance(resource, File):
            del self.files[target_id]
            self.effects_log.append(("delete", f"file:{target_id}"))
        elif effect.etype == "write" and isinstance(resource, File):
            self.effects_log.append(("write", f"file:{target_id}"))
        elif effect.etype == "read" and isinstance(resource, File):
            self.effects_log.append(("read", f"file:{target_id}"))
        elif effect.etype == "send" and isinstance(resource, Email):
            # deliver into the sender's outbox (address -> mailbox)
            self.mailbox_for(resource).outbox.append(target_id)
            self.effects_log.append(("send", f"email:{target_id}"))
        elif effect.etype in ("read", "send") and isinstance(resource, Mailbox):
            # read from / send into a mailbox directly
            self.effects_log.append((effect.etype, f"mailbox:{target_id}"))
        elif effect.etype == "read" and isinstance(resource, Email):
            # read on an email retrieves the message from its owner's mailbox
            self.effects_log.append(("read", f"inbox:{self.mailbox_for(resource).user}"))
        elif effect.etype == "network" and isinstance(resource, URL):
            # network effects are now fully supported
            # SSRF containment was checked by check_noamp before this runs
            self.effects_log.append(("network", f"url:{resource.uri}"))
        else:
            raise ValueError(
                f"effect type {effect.etype} not applicable to resource {type(resource).__name__}"
            )
