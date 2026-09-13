"""Regression: right matching is strict — no wildcard skip.

These tests verify the Fix-2 correction:
  - An approval/capability for read does NOT authorize write
  - An approval/capability for send does NOT authorize delete
  - The blocker is Auth with "right-mismatch", NOT "session-closed" or "replay"
  - right="*" on a default ceiling no longer skips the right check

This closes the bypass: "read approval → used for write → broker wrongly ALLOWs"
"""

from __future__ import annotations

from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.model import Capability, Data, Effect, Task
from effect_broker.traces import build


def _provenance(name: str, content: str = "") -> tuple[Data, ...]:
    return (Data(name, Confidentiality.INTERNAL, Integrity.USER, content=content),)


def _make_task(task_id: str, ceiling_right: str = "*") -> Task:
    """Create a task with the specified ceiling.right."""
    ceiling = Capability(
        owner="User",
        holder="EffectBroker",
        right=ceiling_right,  # FIXED: no longer skips right check
        target="*",
        scope=frozenset({"*"}),
        expiry=float("inf"),
        nonce=f"ceil-{task_id}",
    )
    return Task(task_id=task_id, owner="User", ceiling=ceiling)


class TestStrictRightMatching:
    """FIXED: right mismatch blocks in Auth — no wildcard skip."""

    def test_read_approval_cannot_authorize_write(self) -> None:
        """An approval for read does NOT authorize write, even with wildcard ceiling."""
        broker = build()

        # Task with wildcard ceiling (formerly this skipped the right check)
        task = _make_task("default", ceiling_right="*")
        broker.register_task(task)

        # grant_approval creates a capability with right=effect.etype
        read_request = Effect(
            etype="read",
            target="file:///reports",
            metadata={},
            provenance=_provenance("request"),
            capability_nonce="r-read:Agent:EffectBroker",
            delegation_chain=(),
        )
        nonce = broker.grant_approval(read_request, expiry=100.0, task_id="default")

        # Verify: the approval capability has right="read"
        assert broker.capabilities[nonce].right == "read"

        # Try to commit a WRITE using the READ approval
        write_effect = Effect(
            etype="write",  # ← different from approval's right="read"
            target="file:///reports",
            metadata={},
            provenance=_provenance("approved"),
            capability_nonce=nonce,
            delegation_chain=(),
        )
        commit = broker._make_commit(write_effect, task_id="default")
        allow, evidence = broker.commit(commit)

        assert allow is False, (
            "read approval should NOT authorize write. Evidence: {evidence}"
        )
        assert evidence["primary_blocker"] == "Auth"
        assert "right-mismatch" in evidence["predicates"]["Auth"]
        # The capability's right="read" vs effect's etype="write"
        assert "cap_right=read" in evidence["predicates"]["Auth"]
        assert "etype=write" in evidence["predicates"]["Auth"]

    def test_send_approval_cannot_authorize_delete(self) -> None:
        """An approval for send does NOT authorize delete."""
        broker = build()
        task = _make_task("default", ceiling_right="*")
        broker.register_task(task)

        send_request = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("request"),
            capability_nonce="r-send:Agent:EffectBroker",
            delegation_chain=(),
        )
        nonce = broker.grant_approval(send_request, expiry=100.0, task_id="default")

        delete_effect = Effect(
            etype="delete",  # ← different from approval's right="send"
            target="file:///reports",
            metadata={},
            provenance=_provenance("approved"),
            capability_nonce=nonce,
            delegation_chain=(),
        )
        commit = broker._make_commit(delete_effect, task_id="default")
        allow, evidence = broker.commit(commit)

        assert allow is False
        assert evidence["primary_blocker"] == "Auth"
        assert "right-mismatch" in evidence["predicates"]["Auth"]
        assert "cap_right=send" in evidence["predicates"]["Auth"]
        assert "etype=delete" in evidence["predicates"]["Auth"]

    def test_correct_right_allows(self) -> None:
        """Exact right match: approval for write allows write."""
        broker = build()
        task = _make_task("default", ceiling_right="*")
        broker.register_task(task)

        write_request = Effect(
            etype="write",
            target="file:///reports",
            metadata={},
            provenance=_provenance("request"),
            capability_nonce="r-write:Agent:EffectBroker",
            delegation_chain=(),
        )
        nonce = broker.grant_approval(write_request, expiry=100.0, task_id="default")

        write_effect = Effect(
            etype="write",
            target="file:///reports",
            metadata={},
            provenance=_provenance("approved"),
            capability_nonce=nonce,
            delegation_chain=(),
        )
        commit = broker._make_commit(write_effect, task_id="default")
        allow, evidence = broker.commit(commit)

        assert allow is True, (
            f"Exact right match should ALLOW. Evidence: {evidence}"
        )
        assert evidence["primary_blocker"] is None

    def test_capability_right_mismatch_also_blocks(self) -> None:
        """A root-granted capability for read cannot authorize write directly."""
        broker = build()
        task = _make_task("default", ceiling_right="*")
        broker.register_task(task)

        # Root-granted read capability
        read_cap = Capability(
            owner="User",
            holder="EffectBroker",
            right="read",
            target="file:///reports",
            scope=frozenset({"internal"}),
            expiry=float("inf"),
            nonce="read-cap",
            derives_from=None,
        )
        broker.capabilities["read-cap"] = read_cap

        write_effect = Effect(
            etype="write",  # ← mismatched
            target="file:///reports",
            metadata={},
            provenance=_provenance("direct"),
            capability_nonce="read-cap",
            delegation_chain=(),
        )
        commit = broker._make_commit(write_effect, task_id="default")
        allow, evidence = broker.commit(commit)

        assert allow is False
        assert evidence["primary_blocker"] == "Auth"
        assert "right-mismatch" in evidence["predicates"]["Auth"]

    def test_wildcard_ceiling_does_not_allow_any_right(self) -> None:
        """Even with ceiling.right='*', the capability's right must match etype.

        The fix makes Auth sub-check 5 strict: capability.right == effect.etype.
        The ceiling.right wildcard means 'any right is within ceiling' but
        the capability's own right field still restricts what it can authorize.
        """
        broker = build()
        # Wildcard ceiling: covers any right in terms of ceiling dominance,
        # but the capability's right is the actual grant
        task = _make_task("default", ceiling_right="*")
        broker.register_task(task)

        # Capability grants only "read" right
        read_cap = Capability(
            owner="User",
            holder="EffectBroker",
            right="read",
            target="*",
            scope=frozenset({"*"}),
            expiry=float("inf"),
            nonce="read-any",
            derives_from=None,
        )
        broker.capabilities["read-any"] = read_cap

        # Try to write using a read-only capability
        write_effect = Effect(
            etype="write",
            target="file:///anything",
            metadata={},
            provenance=_provenance("test"),
            capability_nonce="read-any",
            delegation_chain=(),
        )
        commit = broker._make_commit(write_effect, task_id="default")
        allow, evidence = broker.commit(commit)

        assert allow is False
        assert evidence["primary_blocker"] == "Auth"
        assert "right-mismatch" in evidence["predicates"]["Auth"]

    def test_approval_allows_correct_right_with_strict_ceiling(self) -> None:
        """An approval with matching right passes even with a strict ceiling."""
        broker = build()
        # Strict ceiling: only allows "send" operations
        task = _make_task("default", ceiling_right="send")
        broker.register_task(task)

        send_request = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("request"),
            capability_nonce="r-send:Agent:EffectBroker",
            delegation_chain=(),
        )
        nonce = broker.grant_approval(send_request, expiry=100.0, task_id="default")

        send_effect = Effect(
            etype="send",
            target="internal@corp.com",
            metadata={},
            provenance=_provenance("approved"),
            capability_nonce=nonce,
            delegation_chain=(),
        )
        commit = broker._make_commit(send_effect, task_id="default")
        allow, evidence = broker.commit(commit)

        assert allow is True
        assert evidence["primary_blocker"] is None

    def test_strict_ceiling_blocks_wrong_right(self) -> None:
        """With a strict ceiling (right='read'), write is blocked by both ceiling
        AND capability right mismatch."""
        broker = build()
        task = _make_task("default", ceiling_right="read")
        broker.register_task(task)

        write_request = Effect(
            etype="write",
            target="file:///reports",
            metadata={},
            provenance=_provenance("request"),
            capability_nonce="r-write:Agent:EffectBroker",
            delegation_chain=(),
        )
        nonce = broker.grant_approval(write_request, expiry=100.0, task_id="default")

        write_effect = Effect(
            etype="write",
            target="file:///reports",
            metadata={},
            provenance=_provenance("approved"),
            capability_nonce=nonce,
            delegation_chain=(),
        )
        commit = broker._make_commit(write_effect, task_id="default")
        allow, evidence = broker.commit(commit)

        # With strict ceiling.right="read", NoAmp also blocks (right mismatch)
        assert allow is False
        # Either Auth (right-mismatch) or NoAmp (ceiling-right-mismatch) fires
        blocker = evidence["primary_blocker"]
        assert blocker in ("Auth", "NoAmp"), f"Expected Auth or NoAmp, got {blocker}"
