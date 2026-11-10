"""Occurrence identity

The old oracle collapsed repeats into a boolean: two identical writes were one
`exists=True`, a repeated send was a set of one. These tests pin the
occurrence-based counting for the four scenarios named in the plan.
"""

from __future__ import annotations

from effect_broker.oracle import Occurrence, count_occurrences


def _occ(
    effect_id: str,
    etype: str = "write",
    target: str = "x",
    payload_id: str = "p",
    observed_at: float = 10.0,
) -> Occurrence:
    return Occurrence(
        effect_id=effect_id,
        payload_id=payload_id,
        etype=etype,
        target=target,
        targets=frozenset({target}),
        observed_at=observed_at,
        source="fs-diff",
        window=(0.0, 100.0),
    )


class TestDoubleWrite:
    """`write(x); write(x)` — two occurrences, not one `True`."""

    def test_two_writes_count_as_two(self) -> None:
        occs = [_occ("e1"), _occ("e2")]
        assert count_occurrences(occs, etype="write", target="x") == 2

    def test_same_payload_id_preserved_on_both(self) -> None:
        occs = [_occ("e1", payload_id="p"), _occ("e2", payload_id="p")]
        assert count_occurrences(occs, payload_id="p") == 2

    def test_effect_ids_distinguish_them(self) -> None:
        occs = [_occ("e1"), _occ("e2")]
        assert count_occurrences(occs, payload_id="p") == len({o.effect_id for o in occs})


class TestWriteThenDelete:
    """`write(x); delete(x)` — both occurrences recorded, not 'absent'."""

    def test_both_occurrences_survive(self) -> None:
        occs = [_occ("e1", etype="write"), _occ("e2", etype="delete")]
        assert count_occurrences(occs, etype="write", target="x") == 1
        assert count_occurrences(occs, etype="delete", target="x") == 1

    def test_delete_does_not_erase_the_write(self) -> None:
        """The old `exists=False` verdict erased the write from history."""
        occs = [_occ("e1", etype="write"), _occ("e2", etype="delete")]
        writes = [o for o in occs if o.etype == "write"]
        assert len(writes) == 1, "history must keep the write"


class TestRepeatedSend:
    """`send(a); send(a)` — two occurrences, not a collapsed set of one."""

    def test_repeats_are_counted(self) -> None:
        occs = [
            _occ("s1", etype="send", target="a@x", payload_id="m1"),
            _occ("s2", etype="send", target="a@x", payload_id="m1"),
        ]
        assert count_occurrences(occs, etype="send") == 2


class TestLateDelivery:
    """An effect landing outside the window is flagged, not invisible."""

    def test_out_of_window_flagged(self) -> None:
        late = Occurrence(
            effect_id="late",
            payload_id="p",
            etype="write",
            target="x",
            targets=frozenset({"x"}),
            observed_at=150.0,
            source="fs-diff",
            window=(0.0, 100.0),
        )
        assert late.out_of_window is True

    def test_in_window_not_flagged(self) -> None:
        assert _occ("e1").out_of_window is False

    def test_boundary_is_inclusive(self) -> None:
        edge = _occ("e1", observed_at=100.0)
        assert edge.out_of_window is False


class TestUnclaimedEffects:
    """An occurrence with no broker claim is reported, not dropped."""

    def test_zero_claim_occurrences_are_visible(self) -> None:
        """Occurrence list stands alone: nothing needs a claim to be counted."""
        occs = [_occ("orphan")]  # no matching claim anywhere
        assert count_occurrences(occs, target="x") == 1


class TestCountFiltering:
    """The counter filters are conjunctions, and empty means zero."""

    def test_filters_conjoin(self) -> None:
        occs = [_occ("a", etype="write", target="x"), _occ("b", etype="send", target="x")]
        assert count_occurrences(occs, etype="write") == 1
        assert count_occurrences(occs, etype="write", target="x") == 1
        assert count_occurrences(occs, etype="send", target="x") == 1

    def test_no_match_is_zero_not_error(self) -> None:
        assert count_occurrences([_occ("a")], target="nowhere") == 0

    def test_empty_list_is_zero(self) -> None:
        assert count_occurrences([], etype="write") == 0
