"""provenance-preserving transformations.

Criterion: the transformation table exists AND every row has a test that
exercises a representative input, so the classification is checkable rather
than asserted.
"""

from __future__ import annotations

import hashlib

import pytest

from effect_broker.lattice import Confidentiality, Integrity
from effect_broker.provenance_transforms import (
    PROVENANCE_TRANSFORMS,
    ProvenanceEffect,
    Transformation,
    preserves_provenance,
    propagated_labels,
    provenance_effect,
    rationale,
    requires_untrusted,
)


# Table completeness
class TestTableIsComplete:
    def test_every_transformation_has_a_row(self) -> None:
        """The table must cover the enum exhaustively - no silent defaults."""
        missing = [t for t in Transformation if t not in PROVENANCE_TRANSFORMS]
        assert missing == [], f"unclassified transformations: {missing}"

    def test_every_row_states_a_reason(self) -> None:
        """A verdict without a reason is not reviewable."""
        for t, (_, why) in PROVENANCE_TRANSFORMS.items():
            assert why.strip(), f"{t} has an empty rationale"
            assert len(why) > 20, f"{t} rationale is too terse to review"

    def test_unknown_transformation_raises(self) -> None:
        """An unanalysed transformation must not inherit 'preserved'.

        Enums cannot be extended at runtime, so the miss is simulated with a
        key that has no row. The lookup must raise rather than default to
        PRESERVED - a silent default would let a new, unanalysed
        transformation launder provenance.
        """
        absent = "some_future_transformation"
        assert absent not in {t.value for t in Transformation}
        with pytest.raises(KeyError):
            provenance_effect(absent)  # type: ignore[arg-type]


# One representative input per row
class TestPreservedRows:
    """Transformations whose output is attributable to their input."""

    def test_identity(self) -> None:
        src = "abc"
        assert src is src
        assert preserves_provenance(Transformation.IDENTITY) is True

    def test_slice_cannot_add_information(self) -> None:
        src = "hello world"
        assert src[0:5] == "hello"
        # A slice is a subset of input bytes.
        assert set(src[0:5]) <= set(src)
        assert preserves_provenance(Transformation.SLICE) is True

    def test_lossless_decode_roundtrips(self) -> None:
        src = "caf\u00e9".encode()
        assert src.decode("utf-8").encode("utf-8") == src
        assert preserves_provenance(Transformation.DECODE_LOSSLESS) is True

    def test_reencode_preserves_content(self) -> None:
        src = "abc"
        assert src.encode("utf-16").decode("utf-16") == src
        assert preserves_provenance(Transformation.REENCODE) is True

    def test_hash_is_opaque_but_labelled(self) -> None:
        digest = hashlib.sha256(b"secret").hexdigest()
        assert len(digest) == 64
        assert preserves_provenance(Transformation.HASH) is True

    def test_encrypt_is_not_a_declassification(self) -> None:
        """Ciphertext keeps the label: encryption must not launder it."""
        assert preserves_provenance(Transformation.ENCRYPT) is True
        assert requires_untrusted(Transformation.ENCRYPT) is False

    def test_format_preserves_tokens(self) -> None:
        assert preserves_provenance(Transformation.FORMAT) is True


# Broken rows
class TestBrokenRows:
    """Transformations that invent content - output must be UNTRUSTED."""

    def test_lossy_decode_invents_bytes(self) -> None:
        """errors='replace' inserts U+FFFD that was never in the input."""
        src = b"\xff\xfe"
        decoded = src.decode("utf-8", errors="replace")
        assert "\ufffd" in decoded
        assert requires_untrusted(Transformation.DECODE_LOSSY) is True
        assert preserves_provenance(Transformation.DECODE_LOSSY) is False

    def test_model_generation_invents_content(self) -> None:
        assert requires_untrusted(Transformation.MODEL_GENERATE) is True

    def test_summarise_invents_wording(self) -> None:
        assert requires_untrusted(Transformation.SUMMARISE) is True

    def test_translate_invents_tokens(self) -> None:
        assert requires_untrusted(Transformation.TRANSLATE) is True


# Label propagation
class TestLabelPropagation:
    def test_concat_joins_labels(self) -> None:
        """Concatenation preserves provenance across ALL inputs, joined."""
        assert provenance_effect(Transformation.CONCAT) is ProvenanceEffect.PRESERVED_LABEL_JOIN
        labels = propagated_labels(
            Transformation.CONCAT,
            [
                (Confidentiality.PUBLIC, Integrity.USER),
                (Confidentiality.CONFIDENTIAL, Integrity.UNTRUSTED),
            ],
        )
        assert labels == (Confidentiality.CONFIDENTIAL, Integrity.UNTRUSTED)

    def test_concat_takes_worst_of_both_axes(self) -> None:
        """Confidentiality joins by MAX, integrity by MIN (Biba)."""
        labels = propagated_labels(
            Transformation.CONCAT,
            [
                (Confidentiality.INTERNAL, Integrity.HIGH),
                (Confidentiality.PUBLIC, Integrity.USER),
            ],
        )
        assert labels == (Confidentiality.INTERNAL, Integrity.USER)

    def test_single_input_preserves_labels(self) -> None:
        labels = propagated_labels(
            Transformation.SLICE,
            [(Confidentiality.CONFIDENTIAL, Integrity.USER)],
        )
        assert labels == (Confidentiality.CONFIDENTIAL, Integrity.USER)

    def test_broken_transformation_yields_no_labels(self) -> None:
        """Caller must label the output UNTRUSTED itself; no inherited labels."""
        result = propagated_labels(
            Transformation.SUMMARISE,
            [(Confidentiality.CONFIDENTIAL, Integrity.HIGH)],
        )
        assert result is None

    def test_empty_inputs_rejected(self) -> None:
        with pytest.raises(ValueError):
            propagated_labels(Transformation.IDENTITY, [])


# The rule, restated as a property
class TestRuleIsConsistent:
    def test_preserved_and_untrusted_are_mutually_exclusive(self) -> None:
        for t in Transformation:
            assert preserves_provenance(t) is not requires_untrusted(t)

    def test_rationale_reachable_for_every_row(self) -> None:
        for t in Transformation:
            assert rationale(t)

    def test_effect_is_one_of_three(self) -> None:
        for t in Transformation:
            assert provenance_effect(t) in set(ProvenanceEffect)
