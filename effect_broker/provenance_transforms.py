"""Provenance-preserving transformations

THE RULE
────────
A transformation PRESERVES provenance iff:

  1. its output is a deterministic function of its inputs, AND
  2. every byte of the output is attributable to a byte of an input.

Anything that invents content BREAKS provenance. This is the single criterion
from which every row of the table below follows — the table is derived, not
asserted, so a new transformation can be classified without consulting a list.

WHY THIS EXISTS
───────────────
Before this module, "provenance is preserved" was neither provable nor
falsifiable: the only statement in the codebase was the prose line
"Authority cannot be widened through transformation or delegation"
(ARCHITECTURE.md). Review item 4 asks explicitly which transformations
preserve provenance; without a machine-readable answer, a tool can launder
UNTRUSTED input into a HIGH-integrity claim by "summarising" it.

WHAT THIS MODULE DOES NOT DO
────────────────────────────
It does not enforce anything. It classifies. Enforcement is
`Session.is_trusted_provenance()` (P5-6), which requires the recorded labels
to match — so a transformation that drops provenance_id yields an UNTRUSTED
datum, and one that keeps a stale provenance_id after changing content is
rejected by the content/label binding.
"""

from __future__ import annotations

from enum import Enum, StrEnum


class ProvenanceEffect(Enum):
    """How a transformation affects the provenance of its output."""

    PRESERVED = "preserved"
    """Output is attributable to input; labels carry over unchanged."""

    PRESERVED_LABEL_JOIN = "preserved-label-join"
    """Output is attributable to ALL inputs; labels are the lattice JOIN.

    Used for combining data: the result is at least as sensitive and at least
    as untrusted as the worst input. Keeping only the primary input's labels
    is the classic multi-input laundering error.
    """

    BROKEN = "broken"
    """Output contains content not attributable to any input.

    The result must be treated as UNTRUSTED (integrity UNTRUSTED, no
    provenance_id) regardless of what the inputs were.
    """


class Transformation(StrEnum):
    """Enumerable provenance-relevant transformations.

    StrEnum so the member serialises into evidence strings and JSON without
    conversion (the ledger records these verbatim).
    """

    IDENTITY = "identity"
    SLICE = "slice"
    CONCAT = "concat"
    DECODE_LOSSLESS = "decode_lossless"
    DECODE_LOSSY = "decode_lossy"
    REENCODE = "reencode"
    HASH = "hash"
    ENCRYPT = "encrypt"
    MODEL_GENERATE = "model_generate"
    SUMMARISE = "summarise"
    TRANSLATE = "translate"
    FORMAT = "format"


#: The table. Each row states the effect and — crucially — WHY, so that a
#: reviewer can check the reasoning rather than trust the verdict.
PROVENANCE_TRANSFORMS: dict[Transformation, tuple[ProvenanceEffect, str]] = {
    Transformation.IDENTITY: (
        ProvenanceEffect.PRESERVED,
        "Output is the input; nothing added, nothing removed.",
    ),
    Transformation.SLICE: (
        ProvenanceEffect.PRESERVED,
        "A substring is a subset of input bytes; it cannot add information. "
        "Note: slicing does not LOWER the label — a 3-byte slice of a "
        "CONFIDENTIAL document is still CONFIDENTIAL.",
    ),
    Transformation.CONCAT: (
        ProvenanceEffect.PRESERVED_LABEL_JOIN,
        "Every output byte comes from one of the inputs, so provenance is "
        "preserved across ALL inputs. Labels must be the join (highest "
        "confidentiality, lowest integrity), never the primary input's.",
    ),
    Transformation.DECODE_LOSSLESS: (
        ProvenanceEffect.PRESERVED,
        "utf-8/json/base64 are injective or narrower: the decoded value is a "
        "function of the input with no invented bytes.",
    ),
    Transformation.DECODE_LOSSY: (
        ProvenanceEffect.BROKEN,
        "errors='replace' substitutes bytes that were not in the input, so "
        "output is not attributable to input. This is the defect at "
        "model.py:897 vs executor_subprocess.py:154 (PLAN 5, B3).",
    ),
    Transformation.REENCODE: (
        ProvenanceEffect.PRESERVED,
        "Re-encoding preserves information content (possibly with growth); "
        "no new content is introduced.",
    ),
    Transformation.HASH: (
        ProvenanceEffect.PRESERVED,
        "A digest is an opaque datum: its content is not readable, but the "
        "label still travels with it. Releasing a hash of CONFIDENTIAL data "
        "is still subject to the CONFIDENTIAL sink boundary.",
    ),
    Transformation.ENCRYPT: (
        ProvenanceEffect.PRESERVED,
        "Ciphertext is an opaque datum bound to the plaintext; the label "
        "travels with it. Encryption is NOT a declassification.",
    ),
    Transformation.MODEL_GENERATE: (
        ProvenanceEffect.BROKEN,
        "The model invents content. No output byte is attributable to an "
        "input byte, even when prompted with one. Never inherits input labels; "
        "always UNTRUSTED.",
    ),
    Transformation.SUMMARISE: (
        ProvenanceEffect.BROKEN,
        "Summarisation selects and rewrites; the wording is generated, not "
        "copied. A summary of CONFIDENTIAL data is CONFIDENTIAL *and* "
        "UNTRUSTED — it is new content.",
    ),
    Transformation.TRANSLATE: (
        ProvenanceEffect.BROKEN,
        "Translation generates target-language tokens that appear nowhere in "
        "the input. Same verdict as summarise, for the same reason.",
    ),
    Transformation.FORMAT: (
        ProvenanceEffect.PRESERVED,
        "Whitespace/indentation changes preserve the token sequence. This row "
        "is the boundary case: if the formatter may drop or rewrite tokens, "
        "it is SUMMARISE, not FORMAT.",
    ),
}


def provenance_effect(t: Transformation) -> ProvenanceEffect:
    """Look up the provenance effect of a transformation.

    Raises KeyError for an unclassified transformation — deliberately loud.
    A silent default would let a new, unanalysed transformation inherit
    "preserved" and launder provenance.
    """
    return PROVENANCE_TRANSFORMS[t][0]


def rationale(t: Transformation) -> str:
    """Look up the stated reason for a row (for evidence strings)."""
    return PROVENANCE_TRANSFORMS[t][1]


def preserves_provenance(t: Transformation) -> bool:
    """True if the transformation keeps the output attributable to input.

    PRESERVED_LABEL_JOIN counts as preserving (the output IS attributable to
    the inputs) — but the caller must apply the join. Use
    `propagated_labels()` for that.
    """
    return provenance_effect(t) is not ProvenanceEffect.BROKEN


def requires_untrusted(t: Transformation) -> bool:
    """True if the output must be treated as UNTRUSTED new content."""
    return provenance_effect(t) is ProvenanceEffect.BROKEN


def propagated_labels(
    t: Transformation,
    inputs: list[tuple[int, int]],
) -> tuple[int, int] | None:
    """Compute the (confidentiality, integrity) labels the output must carry.

    Args:
        t: the transformation applied.
        inputs: the labels of every input, as (confidentiality, integrity)
            integer ranks (Confidentiality / Integrity are IntEnums).

    Returns:
        (confidentiality, integrity) for the output, or None when the
        transformation BREAKS provenance — in which case the caller must
        label the result UNTRUSTED itself and must NOT carry a provenance_id.

    Lattice rules:
      - confidentiality joins by MAX  (output is at least as secret as input)
      - integrity joins by MIN        (output is at most as trustworthy as the
        least trustworthy input — Biba)
    """
    if requires_untrusted(t):
        return None
    if not inputs:
        raise ValueError("propagated_labels requires at least one input label")
    join_conf = max(c for c, _ in inputs)
    join_integ = min(i for _, i in inputs)
    return join_conf, join_integ
