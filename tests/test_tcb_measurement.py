"""What the TCB metric measures, and what it must include.

`tcb_lines` is a claim about the size of the code the security argument rests
on. Two defects made it measure something else, both in the direction that
flatters the number:

1. **The file set was wrong.** `_TCB_FILES` held `broker.py` and `model.py`
   while `docs/ARCHITECTURE.md` §2 defined the TCB as four files. `executor.py`
   — described in that document as the sole mutation path, i.e. exactly the code
   an attacker must defeat — was not counted, nor was `restricted_store.py`.
   The figure read ~45% low.

2. **Docstrings counted as code.** `_count_code_lines` dropped comments and
   blank lines but not docstrings, so prose inside string literals was counted
   as logic: 1238 of the 3401 lines it summed were docstrings. This is the same
   error the comment filter was added to fix, in the form that survived it.

Neither is visible from the number itself, which is why both are pinned here
rather than left to review.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from effect_broker.metrics import _TCB_FILES, _count_code_lines, tcb_size

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _architecture_tcb_files() -> set[str]:
    """The TCB files named in `docs/ARCHITECTURE.md` §2.

    Read from the document rather than restated here: a test that hard-codes
    the same list as the code cannot notice the two drifting apart, which is
    the failure being pinned.
    """
    doc = _REPO_ROOT / "docs" / "ARCHITECTURE.md"
    if not doc.exists():
        pytest.skip("docs/ARCHITECTURE.md is not present in this checkout")

    section = doc.read_text().split("### Components in TCB", 1)
    assert len(section) == 2, "ARCHITECTURE.md no longer has a 'Components in TCB' section"
    table = section[1].split("### Components NOT in TCB", 1)[0]

    # Rows look like: | `broker.py` — 4-predicate gate | 455 | ... |
    return {f"effect_broker/{name}" for name in re.findall(r"\|\s*`([a-z_]+\.py)`", table)}


class TestFileSet:
    def test_matches_the_documented_tcb(self) -> None:
        """The metric must count the TCB the architecture names, no more, no less."""
        documented = _architecture_tcb_files()
        assert documented, "could not parse any TCB files out of ARCHITECTURE.md"
        assert set(_TCB_FILES) == documented, (
            "the measured TCB and the documented TCB disagree:\n"
            f"  measured but not documented: {sorted(set(_TCB_FILES) - documented)}\n"
            f"  documented but not measured: {sorted(documented - set(_TCB_FILES))}"
        )

    def test_executor_is_counted(self) -> None:
        """`executor.py` is the sole mutation path — it cannot be out of scope."""
        assert "effect_broker/executor.py" in _TCB_FILES, (
            "the only path that mutates external state is not in the measured TCB"
        )

    def test_shims_and_tests_are_not_counted(self) -> None:
        """Shims are untrusted by design; counting them would inflate the TCB."""
        for untrusted in ("effect_broker/shim_email.py", "effect_broker/tests.py"):
            assert untrusted not in _TCB_FILES

    def test_every_listed_file_exists(self) -> None:
        """A renamed module would otherwise be skipped silently by tcb_size()."""
        for rel in _TCB_FILES:
            assert (_REPO_ROOT / rel).exists(), (
                f"{rel} is listed in _TCB_FILES but does not exist; tcb_size() "
                f"skips missing paths, so the metric would undercount"
            )


class TestCountedLines:
    """Which lines count as code."""

    def test_comments_and_blanks_are_excluded(self) -> None:
        text = "x = 1\n\n# a comment\n\ny = 2\n"
        assert _count_code_lines(text) == 2

    def test_a_module_docstring_is_excluded(self) -> None:
        text = '"""Prose that explains the module."""\n\nx = 1\n'
        assert _count_code_lines(text) == 1, "module docstring counted as code"

    def test_a_function_docstring_is_excluded(self) -> None:
        text = (
            "def f() -> int:\n"
            '    """Explain the function.\n'
            "\n"
            "    More prose here.\n"
            '    """\n'
            "    return 1\n"
        )
        assert _count_code_lines(text) == 2, "docstring body counted as code"

    def test_a_multiline_string_is_code_unless_it_is_a_docstring(self) -> None:
        """A literal assigned to a name is data the code uses, not documentation."""
        text = 'SQL = (\n    "SELECT 1"\n)\n'
        assert _count_code_lines(text) == 3

    def test_a_code_docstring_on_the_same_line_counts(self) -> None:
        """A one-liner body is code: the def executes."""
        text = 'def f() -> None: """Doc."""\n'
        assert _count_code_lines(text) == 1

    def test_an_empty_docstring_counts_its_line(self) -> None:
        """`""" """` parses as a literal spanning one line — exclude that line."""
        text = '""""""\nx = 1\n'
        assert _count_code_lines(text) == 1

    def test_unparseable_input_falls_back_to_comments_only(self) -> None:
        """A broken file must not crash a metrics run."""
        assert _count_code_lines("x = = 1\n") == 1


class TestTheMetricItself:
    def test_docstrings_are_not_a_large_share_of_the_tcb(self) -> None:
        """Docstrings were 36% of the reported figure; prose must not dominate."""
        code = tcb_size()
        naive = 0
        for rel in _TCB_FILES:
            path = _REPO_ROOT / rel
            if not path.exists():
                continue
            naive += sum(
                1
                for line in path.read_text().splitlines()
                if line.strip() and not line.strip().startswith("#")
            )
        assert code < naive, "no docstring was excluded at all"
        share = 1 - (code / naive)
        assert share < 0.5, (
            f"{share:.0%} of the comment-stripped TCB was docstrings — either the "
            f"filter stopped working or the code has become mostly prose"
        )

    def test_the_tcb_is_not_understated(self) -> None:
        """Sanity floor: sum the files directly and compare."""
        direct = sum(_count_code_lines((_REPO_ROOT / rel).read_text()) for rel in _TCB_FILES)
        assert tcb_size() == direct

    def test_the_tcb_is_not_a_token_number(self) -> None:
        assert tcb_size() > 1000, f"implausibly small trusted core: {tcb_size()}"
