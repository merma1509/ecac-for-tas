"""Restricted mutable external state — the single mutation point.

This module replaces the public-dict ResourceStore with a controlled interface:

  - files, emails, mailboxes: read-only Mapping views
    (no direct store[key] = value; violators get TypeError)
  - effects_log, identity_log: append-only lists
  - apply_effect(): the SOLE path for state mutation

Design rationale:
  In a same-process model this is advisory (Python cannot truly prevent
  attribute replacement). In a real deployment (separate process/enclave)
  this becomes an enforced capability interface: the executor exposes ONLY
  apply_effect as its write primitive, and the observer has read-only access
  to the log views.

  The key property this enables: every external state change appears in
  effects_log and identity_log, so the observer can verify complete
  mediation. Direct store[key]=value would produce state change WITHOUT
  a log entry → observer returns UNKNOWN. This is the "unknown, not safe"
  guarantee.
"""

from __future__ import annotations

import warnings
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field

from .lattice import Confidentiality
from .model import URL, Domain, Effect, Email, File, Mailbox, Resource

# ---- SAME-PROCESS warning ----
_SAME_PROCESS_WARNED = False


def _warn_once() -> None:
    global _SAME_PROCESS_WARNED
    if not _SAME_PROCESS_WARNED:
        _SAME_PROCESS_WARNED = True
        warnings.warn(
            "SAME-PROCESS: ResourceStore lives in the same Python process as the broker. "
            "Read-only proxies prevent accidental bypass; a determined adversary can still "
            "replace attributes. Deploy in a separate process/enclave for real isolation.",
            UserWarning,
            stacklevel=2,
        )

class _FilesView(Mapping[str, File]):
    """Read-only view of files — live snapshot of the store's files dict."""

    def __init__(self, store: RestrictedResourceStore) -> None:
        self._store = store

    def __getitem__(self, key: str) -> File:
        return self._store._files._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._store._files._data)

    def __len__(self) -> int:
        return len(self._store._files._data)


class _EmailsView(Mapping[str, Email]):
    """Read-only view of emails — live snapshot of the store's emails dict."""

    def __init__(self, store: RestrictedResourceStore) -> None:
        self._store = store

    def __getitem__(self, key: str) -> Email:
        return self._store._emails._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._store._emails._data)

    def __len__(self) -> int:
        return len(self._store._emails._data)


class _MailboxesView(Mapping[str, Mailbox]):
    """Read-only view of mailboxes — live snapshot of the store's mailboxes dict."""

    def __init__(self, store: RestrictedResourceStore) -> None:
        self._store = store

    def __getitem__(self, key: str) -> Mailbox:
        return self._store._mailboxes._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._store._mailboxes._data)

    def __len__(self) -> int:
        return len(self._store._mailboxes._data)

# Store initialization helper
@dataclass
class _FilesStore:
    """Internal mutable storage for files. Accessible only via RestrictedResourceStore."""

    _data: dict[str, File] = field(default_factory=dict)


@dataclass
class _EmailsStore:
    """Internal mutable storage for emails."""

    _data: dict[str, Email] = field(default_factory=dict)


@dataclass
class _MailboxesStore:
    """Internal mutable storage for mailboxes."""

    _data: dict[str, Mailbox] = field(default_factory=dict)

# RestrictedResourceStore
@dataclass
class RestrictedResourceStore:
    """External state with controlled mutation.

    Public attributes are read-only Mapping views. State change is ONLY
    possible through apply_effect() — which records every mutation in
    effects_log and identity_log.

    Direct mutation attempts (store.files[key] = X) raise TypeError.
    This makes accidental bypass impossible and deliberate bypass explicit.

    Setup (populating initial resources before broker runs) uses private
    _unsafe_bootstrap() which should only be called during store construction.
    """

    # Read-only views — the public interface
    files: _FilesView
    emails: _EmailsView
    mailboxes: _MailboxesView
    effects_log: list[tuple[str, str]]  # append-only record of committed effects
    identity_log: list[frozenset[str]]  # complete target sets per commit

    def __init__(self) -> None:
        _warn_once()
        _files: _FilesStore = _FilesStore()
        _emails: _EmailsStore = _EmailsStore()
        _mailboxes: _MailboxesStore = _MailboxesStore()

        self._files = _files
        self._emails = _emails
        self._mailboxes = _mailboxes
        self.effects_log: list[tuple[str, str]] = []
        self.identity_log: list[frozenset[str]] = []

        # Public read-only views (pass self so they read live data)
        self.files = _FilesView(self)
        self.emails = _EmailsView(self)
        self.mailboxes = _MailboxesView(self)

    # ---- Bootstrap: populate initial resources before broker runs ----
    # These should only be called during store initialization/setup.
    # After that, all mutations go through apply_effect().

    def _unsafe_bootstrap_file(
        self, path: str, sensitivity: Confidentiality
    ) -> None:
        """BOOTSTRAP ONLY: pre-populate a file resource before broker runs."""
        self._files._data[path] = File(path, sensitivity)

    def _unsafe_bootstrap_email(self, address: str, domain: Domain) -> None:
        """BOOTSTRAP ONLY: pre-populate an email resource before broker runs."""
        self._emails._data[address] = Email(address, domain)

    def _unsafe_bootstrap_mailbox(self, user: str) -> None:
        """BOOTSTRAP ONLY: pre-populate a mailbox before broker runs."""
        self._mailboxes._data[user] = Mailbox(user)

    # ---- Single mutation point ----

    def resolve(self, target: str) -> Resource | None:
        """Look up a resource by its target string (id)"""
        if target in self._files._data:
            return self._files._data[target]
        if target in self._emails._data:
            return self._emails._data[target]
        if target in self._mailboxes._data:
            return self._mailboxes._data[target]
        if target.startswith("http://") or target.startswith("https://"):
            return self._url_for(target)
        return None

    def _url_for(self, uri: str) -> URL:
        """Resolve a URI string to a URL resource."""
        domain = uri.split("://", 1)[1].split("/")[0] if "://" in uri else uri
        return URL(uri=uri, scope=frozenset({domain}))

    def _deliver_to_targets(
        self, effect: Effect, all_targets: frozenset[str]
    ) -> None:
        """Deliver a send effect to ALL targets (primary + additional recipients).

        Email records and mailbox entries are created HERE in apply_effect,
        not deferred to the shim. This ensures every state change is logged
        in identity_log.
        """
        for addr in all_targets:
            if addr in self._emails._data:
                resource = self._emails._data[addr]
            else:
                # Infer domain from address
                if "@" in addr:
                    domain_part = addr.split("@")[1]
                    inferred_domain = (
                        Domain.INTERNAL
                        if "corp" in domain_part or "internal" in domain_part
                        else Domain.EXTERNAL
                    )
                else:
                    inferred_domain = Domain.EXTERNAL
                resource = Email(addr, inferred_domain)
                self._emails._data[addr] = resource

            # Deliver to the sender's outbox
            local = addr.split("@")[0]
            mb = self._mailboxes._data.setdefault(
                local, Mailbox(local)
            )
            body = ""
            if effect.metadata.get("body"):
                body = f": {effect.metadata['body']}"
            elif effect.metadata.get("extra_resources"):
                body = ": (see metadata for details)"
            mb.outbox.append(f"{addr}{body}")

    def mailbox_for(self, email: Email) -> Mailbox:
        """Resolve an email address to its owner's mailbox (address → user)."""
        local = email.address.split("@")[0]
        return self._mailboxes._data.setdefault(local, Mailbox(local))

    def apply_effect(self, effect: Effect) -> None:
        """Mutate external state for a committed (allowed) effect.

        THIS IS THE SOLE PATH for external state mutation. Every call
        appends to effects_log and identity_log, enabling the observer
        to verify complete mediation.

        Semantics:
          - write/delete: files
          - send: delivers to sender's outbox (address → mailbox)
          - read: logged, no persistent change
          - network: logged, no persistent change
        """
        target_id = effect.target
        resource = self.resolve(target_id)
        if resource is None:
            raise KeyError(f"effect targets unknown resource: {target_id}")

        # Build complete set of resources this effect touches
        all_targets: set[str] = {target_id}
        if effect.known_targets is not None:
            all_targets.add(target_id)
            all_targets |= effect.known_targets.additional
        else:
            bcc = effect.metadata.get("extra_resources", [])
            if isinstance(bcc, list):
                all_targets |= set(bcc)

        all_targets_frozen = frozenset(all_targets)

        if effect.etype == "delete" and isinstance(resource, File):
            del self._files._data[target_id]
            self.effects_log.append(("delete", f"file:{target_id}"))
            self.identity_log.append(all_targets_frozen)

        elif effect.etype == "write" and isinstance(resource, File):
            self.effects_log.append(("write", f"file:{target_id}"))
            self.identity_log.append(all_targets_frozen)

        elif effect.etype == "read" and isinstance(resource, File):
            self.effects_log.append(("read", f"file:{target_id}"))
            self.identity_log.append(all_targets_frozen)

        elif effect.etype == "send" and isinstance(resource, Email):
            self._deliver_to_targets(
                effect,
                frozenset({target_id})
                | (effect.known_targets.additional if effect.known_targets else frozenset()),
            )
            self.effects_log.append(("send", f"email:{target_id}"))
            self.identity_log.append(all_targets_frozen)

        elif effect.etype in ("read", "send") and isinstance(resource, Mailbox):
            self.effects_log.append((effect.etype, f"mailbox:{target_id}"))
            self.identity_log.append(all_targets_frozen)

        elif effect.etype == "read" and isinstance(resource, Email):
            self.effects_log.append(("read", f"inbox:{self.mailbox_for(resource).user}"))
            self.identity_log.append(all_targets_frozen)

        elif effect.etype == "network" and isinstance(resource, URL):
            self.effects_log.append(("network", f"url:{resource.uri}"))
            self.identity_log.append(all_targets_frozen)

        else:
            raise ValueError(
                f"effect type {effect.etype} not applicable to {type(resource).__name__}"
            )

# Backwards-compat alias (for existing code that imports ResourceStore)
ResourceStore = RestrictedResourceStore
