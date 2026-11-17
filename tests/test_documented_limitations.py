"""The documented limitations, pinned so they cannot be quietly claimed closed.

Three gaps in this repository cannot be closed by writing Python:

1. **Same-process mode.** A tool that mutates the store directly bypasses the
   executor. The ledger reports `UNKNOWN`, which is detection, not prevention.
   Only process isolation closes it.
2. **Network egress.** The isolated subprocess blocks some imports but does not
   filter syscalls, so `socket` remains usable. A compromised subprocess can
   open a connection to any host.
3. **Envelope discovery.** Hidden-recipient detection depends on an MTA that
   exposes transactions. Without one it degrades to probing addresses the
   broker already knows.

Each was previously *asserted* in prose. An assertion is not evidence: a reader
could not tell a known gap from a gap nobody had checked. These tests turn each
into an executable fact, which has two effects — the claim can be verified, and
if someone closes the gap, the test fails and the documentation must be updated
instead of silently becoming wrong.

These are deliberately tests of a *deficiency*. They pass while the deficiency
exists, and they are worded so that passing is not mistaken for success.
"""

from __future__ import annotations

import warnings

warnings.filterwarnings("ignore")


class TestNetworkEgressIsNotConfined:
    """Gap 2: no syscall filtering, so a subprocess can still reach the network."""

    def test_socket_is_not_blocked_in_the_subprocess(self) -> None:
        """`socket` must remain importable — and that is the finding, not a bug.

        The real shims need sockets (SMTP/IMAP), so blocking the module would
        break the product. The consequence is that confinement of network egress
        cannot come from the import hook at all; it would need a kernel policy
        (Landlock network rules, seccomp, or a network namespace) that this
        repository does not install.
        """
        from effect_broker import executor_subprocess as sub

        blocked_stdlib = getattr(sub, "_BLOCKED_STDLIB", frozenset())
        blocked_packages = getattr(sub, "_BLOCKED_NETWORK_PACKAGES", frozenset())

        assert "socket" not in blocked_stdlib, (
            "socket is now blocked in the subprocess. If the shims were reworked "
            "to not need it, update the isolation-scope comment in "
            "executor_subprocess.py and the P2 gap in docs/."
        )
        assert "socket" not in blocked_packages

    def test_smtplib_is_not_blocked_because_delivery_needs_it(self) -> None:
        """Evidence for *why* egress cannot be blocked by import hook alone."""
        from effect_broker import executor_subprocess as sub

        blocked_stdlib = getattr(sub, "_BLOCKED_STDLIB", frozenset())
        assert "smtplib" not in blocked_stdlib
        assert "imaplib" not in blocked_stdlib

    def test_confinement_status_names_the_mechanism_actually_installed(self) -> None:
        """The reported status must not overstate what is in effect."""
        from effect_broker.executor_subprocess import _get_confinement_status

        status = _get_confinement_status()
        # Whatever it says, it must be one of the mechanisms the code can
        # actually establish, and it must never claim network confinement.
        assert "network" not in status.lower(), (
            f"confinement status claims network confinement ({status!r}); no "
            f"network mechanism is installed"
        )


class TestSameProcessIsDetectionNotPrevention:
    """Gap 1: the ledger can report a bypass it cannot stop."""

    def test_store_is_an_in_process_object(self) -> None:
        """A direct store write succeeds without going through the executor.

        This is the structural reason P1 cannot be closed in-process: the store
        is an ordinary Python object in the same address space as the tool, so
        `store.files[...] = ...` reaches external state with no gate and no
        executor. The ledger can only report the resulting divergence.
        """
        from effect_broker.restricted_store import RestrictedResourceStore

        store = RestrictedResourceStore()
        # The write path the executor would mediate is reachable directly,
        # which is precisely what "same-process" costs.
        assert hasattr(store, "files"), (
            "store no longer exposes a mutable files view; if access now goes "
            "through a mediating object, re-check whether same-process bypass "
            "is still possible and update the P1 gap"
        )


class TestEnvelopeDiscoveryIsConditional:
    """Gap 3: hidden-recipient discovery depends on the transport."""

    def test_envelope_occurrences_name_their_source(self) -> None:
        """Envelope evidence must be labelled `smtp-envelope`.

        A verdict derived from a probe of known addresses is not the same claim
        as one derived from the MTA's own transaction record. The source label
        is what lets a reader tell them apart, so it must survive in the
        occurrence the oracle consumes.
        """
        from effect_broker.oracle import Occurrence

        fields = Occurrence.__dataclass_fields__
        assert "source" in fields, (
            "Occurrence lost its source field: a degraded (probe-based) "
            "observation would be indistinguishable from a real envelope one"
        )

    def test_mta_log_emits_the_envelope_source(self) -> None:
        """The label must be the one the documented gap refers to."""
        import inspect

        from effect_broker import mta_log

        source_text = inspect.getsource(mta_log)
        assert 'source="smtp-envelope"' in source_text or "source='smtp-envelope'" in source_text, (
            "mta_log no longer labels envelope-derived occurrences; the P5 gap "
            "statement in docs/ refers to that label"
        )
