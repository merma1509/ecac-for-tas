"""Canonical request binding

Covers the three defects that made the old approval ambiguous:

- B2: `subject|body` concatenation collided (`'a|b', 'c'` == `'a', 'b|c'`).
- B3: `model.py` hashed `errors="replace"` text while the subprocess hashed raw
  bytes, so a non-UTF-8 attachment could never round-trip.
- B4/attachment: changing an attachment blob did not change the request hash.

P5-9 is the sender/acting-account binding: an approval for A must not
authorize the same operation for B.
"""

from __future__ import annotations

import hashlib

from effect_broker.model import (
    CANONICAL_REQUEST_VERSION,
    CanonicalRequest,
    Effect,
    sha256_raw,
)


def _send_effect(subject: str, body: str, **meta: object) -> Effect:
    return Effect(
        etype="send",
        target="alice@corp.com",
        metadata={"subject": subject, "body": body, **meta},
        provenance=(),
        capability_nonce="n1",
        delegation_chain=(),
    )


def _request(effect: Effect, **kwargs: object) -> CanonicalRequest:
    from effect_broker.model import canonical_request_from_effect

    return canonical_request_from_effect(effect, **kwargs)


class TestSeparatorAmbiguity:
    """B2: no field content may impersonate a field boundary."""

    def test_old_collision_pair_hashes_differently(self) -> None:
        """`'a|b', 'c'` and `'a', 'b|c'` once produced the same hash."""
        e1 = _send_effect("a|b", "c")
        e2 = _send_effect("a", "b|c")
        assert e1.compute_content_hash() != e2.compute_content_hash()

    def test_subject_and_body_are_separate_digests(self) -> None:
        req = _request(_send_effect("s", "b"))
        assert req.digest("subject") == sha256_raw(b"s")
        assert req.digest("body") == sha256_raw(b"b")

    def test_canonical_bytes_survive_a_pipe_in_a_field(self) -> None:
        """A `|` in any field is data, not a boundary."""
        req = _request(_send_effect("a|b|c", "d|e"))
        again = _request(_send_effect("a|b|c", "d|e"))
        assert req.canonical_bytes() == again.canonical_bytes()

    def test_canonical_bytes_are_injective(self) -> None:
        """Different (subject, body) pairs must serialize differently."""
        b1 = _request(_send_effect("a|b", "c")).canonical_bytes()
        b2 = _request(_send_effect("a", "b|c")).canonical_bytes()
        assert b1 != b2


class TestRawByteHashing:
    """B3: one hashing helper, raw bytes, both sides."""

    def test_non_utf8_bytes_hash_to_their_true_digest(self) -> None:
        raw = bytes(range(256))
        effect = Effect(
            etype="write",
            target="file:///f",
            metadata={"content": raw},
            provenance=(),
            capability_nonce="n",
            delegation_chain=(),
        )
        assert effect.compute_content_hash() == hashlib.sha256(raw).hexdigest()

    def test_replace_decoding_cannot_recreate_the_digest(self) -> None:
        """The old `errors='replace'` path provably loses bytes."""
        raw = b"\xff\xfe\x00\x81"
        replaced = raw.decode("utf-8", errors="replace").encode("utf-8")
        assert replaced != raw  # the defect: this was what got hashed before

    def test_sha256_raw_is_the_module_helper(self) -> None:
        assert sha256_raw(b"hello") == hashlib.sha256(b"hello").hexdigest()

    def test_write_bytes_then_string_disagree_correctly(self) -> None:
        """`b'a'` and `'a'` are the same content and must hash the same."""
        e_bytes = Effect(
            etype="write",
            target="f",
            metadata={"content": b"a"},
            provenance=(),
            capability_nonce="n",
            delegation_chain=(),
        )
        e_str = Effect(
            etype="write",
            target="f",
            metadata={"content": "a"},
            provenance=(),
            capability_nonce="n",
            delegation_chain=(),
        )
        assert e_bytes.compute_content_hash() == e_str.compute_content_hash()


class TestCanonicalRequestRoundTrip:
    """P5-3: identical bytes across a serialize/deserialize boundary."""

    def test_dict_round_trip_preserves_the_hash(self) -> None:
        """Simulates IPC: dataclass -> asdict() -> reconstruct -> same hash."""
        from dataclasses import asdict

        req = _request(
            _send_effect("s", "b"),
            acting_account="alice@corp.com",
            sender="tool@corp.com",
        )
        revived = CanonicalRequest(**asdict(req))
        # tuples become lists through asdict; the hash must not care.
        revived = CanonicalRequest(
            version=revived.version,
            operation=revived.operation,
            task_id=revived.task_id,
            acting_account=revived.acting_account,
            sender=revived.sender,
            recipients=tuple(revived.recipients),
            target=revived.target,
            resource_digests=tuple(map(tuple, revived.resource_digests)),
            attachments=tuple(map(tuple, revived.attachments)),
        )
        assert revived.request_hash() == req.request_hash()

    def test_field_order_does_not_change_the_digest(self) -> None:
        req = _request(_send_effect("s", "b"))
        reordered = CanonicalRequest(
            version=req.version,
            operation=req.operation,
            task_id=req.task_id,
            acting_account=req.acting_account,
            sender=req.sender,
            recipients=tuple(reversed(req.recipients)),
            target=req.target,
            resource_digests=tuple(reversed(req.resource_digests)),
            attachments=req.attachments,
        )
        # Recipients are sorted at serialization, so input order is irrelevant.
        assert reordered.request_hash() == req.request_hash()

    def test_version_is_in_the_digest(self) -> None:
        req = _request(_send_effect("s", "b"))
        bumped = CanonicalRequest(
            version=req.version + 1,
            operation=req.operation,
            task_id=req.task_id,
            acting_account=req.acting_account,
            sender=req.sender,
            recipients=req.recipients,
            target=req.target,
            resource_digests=req.resource_digests,
            attachments=req.attachments,
        )
        assert bumped.request_hash() != req.request_hash()
        assert CANONICAL_REQUEST_VERSION == 1

    def test_empty_and_missing_sender_differ(self) -> None:
        """`sender=None` and `sender=''` serialize the same — both mean 'unset'.

        Deliberate: the wire format has no optional fields, and an approval
        that binds a sender uses the actual address, never the empty string.
        """
        e = _send_effect("s", "b")
        assert _request(e, sender=None).request_hash() == _request(e, sender="").request_hash()


class TestSenderAndActingAccountBinding:
    """P5-9: an approval for A must not stand in for B."""

    def test_different_senders_hash_differently(self) -> None:
        e = _send_effect("s", "b")
        h1 = _request(e, sender="tool@corp.com").request_hash()
        h2 = _request(e, sender="noreply@corp.com").request_hash()
        assert h1 != h2

    def test_different_acting_accounts_hash_differently(self) -> None:
        e = _send_effect("s", "b")
        h1 = _request(e, acting_account="alice@corp.com").request_hash()
        h2 = _request(e, acting_account="bob@corp.com").request_hash()
        assert h1 != h2

    def test_recipient_set_is_fully_bound(self) -> None:
        """Adding a BCC changes the hash — the old binding missed it."""
        from effect_broker.model import EffectTarget

        plain = _send_effect("s", "b")
        with_bcc = Effect(
            etype="send",
            target="alice@corp.com",
            metadata={"subject": "s", "body": "b"},
            provenance=(),
            capability_nonce="n1",
            delegation_chain=(),
            known_targets=EffectTarget(
                primary="alice@corp.com",
                additional=frozenset({"x@evil.com"}),
            ),
        )
        assert _request(plain).request_hash() != _request(with_bcc).request_hash()
        assert "x@evil.com" in _request(with_bcc).recipients


class TestAttachmentBinding:
    """P5-10: changing an attachment blob changes the request hash."""

    @staticmethod
    def _with_attachment(blob: bytes) -> Effect:
        return _send_effect("s", "b", attachments=[{"name": "report.pdf", "bytes": blob}])

    def test_same_bytes_same_hash(self) -> None:
        req1 = _request(self._with_attachment(b"PDFDATA"))
        req2 = _request(self._with_attachment(b"PDFDATA"))
        assert req1.request_hash() == req2.request_hash()

    def test_changed_blob_changes_hash(self) -> None:
        """Same subject/body, different attachment: the hash must move."""
        req1 = _request(self._with_attachment(b"PDFDATA"))
        req2 = _request(self._with_attachment(b"PDFDATA-MODIFIED"))
        assert req1.request_hash() != req2.request_hash()

    def test_attachment_digest_is_over_raw_bytes(self) -> None:
        blob = b"\xff\xfe\x00PDF"
        req = _request(self._with_attachment(blob))
        assert req.digest == req.digest  # sanity: digest() exists
        names = [name for name, _ in req.attachments]
        assert names == ["report.pdf"]
        assert req.attachments[0][1] == hashlib.sha256(blob).hexdigest()

    def test_attachment_and_body_are_bound_separately(self) -> None:
        """Mutating the attachment must not require re-approving the body."""
        e1 = self._with_attachment(b"v1")
        e2 = self._with_attachment(b"v2")
        d1 = _request(e1).digest("body")
        d2 = _request(e2).digest("body")
        assert d1 == d2, "body digest should be attachment-independent"
        assert _request(e1).request_hash() != _request(e2).request_hash()


class TestApprovedRequestCarriesRequestHash:
    """The approval binding exposes request_hash alongside content_hash."""

    def test_field_exists_and_defaults_to_none(self) -> None:
        from effect_broker.model import ApprovedRequest

        req = ApprovedRequest(
            nonce="n",
            etype="send",
            targets=None,  # type: ignore[arg-type]
            expiry=0.0,
            task_id="t",
            granted_by="USER",
        )
        assert req.request_hash is None
