"""What the TCB metric measures, and what it must include.

`tcb_lines` is a claim about the size of the code the security argument rests
on, so it is quoted. Three defects made it measure something else, each in the
direction that flatters the number:

1. **The file set was wrong.** The list held `broker.py` and `model.py` while
   this repository's architecture named four modules. `executor.py` — the sole
   mutation path, i.e. exactly the code an attacker must defeat — was not
   counted, nor was `restricted_store.py`. The figure read ~45% low.

2. **Docstrings counted as code.** `_count_code_lines` dropped comments and
   blank lines but not docstrings, so prose inside string literals counted as
   logic: 1238 of the 3401 lines it summed. The same error the comment filter
   was added to fix, in the form that survived it.

3. **The definition lived where CI cannot see it.** It sat only in
   `docs/ARCHITECTURE.md`, and `docs/` is not tracked by git, so the consistency
   test skipped in CI and the drift in (1) was invisible in the only place that
   runs on every change. The canonical list is now `effect_broker/tcb.py`.

None of this is visible from the number itself, which is why it is pinned here.
"""

from __future__ import annotations

import ast
from pathlib import Path

from effect_broker.metrics import _TCB_FILES, _count_code_lines, tcb_breakdown, tcb_size
from effect_broker.tcb import TCB_FILES, TCB_MODULES, assert_complete

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _imports(rel_path: str) -> set[str]:
    """Module names imported by a source file, as written in the source."""
    tree = ast.parse((_REPO_ROOT / rel_path).read_text())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


class TestTheDefinitionIsTracked:
    def test_the_registry_is_tracked_by_git(self, git_tracks) -> None:
        """`docs/` is ignored, so a definition living only there is not in CI.

        This is the defect that let the file set drift unobserved: the test that
        compared the metric against the document skipped, and green meant
        nothing.
        """
        assert git_tracks("effect_broker/tcb.py"), (
            "effect_broker/tcb.py is not tracked by git, so CI cannot see the TCB "
            "definition and could not notice it changing"
        )
    def test_the_file_set_comes_from_the_registry(self) -> None:
        """`metrics._TCB_FILES` must not be a second, independently edited copy."""
        assert _TCB_FILES == TCB_FILES

    def test_the_registry_asserts_itself(self) -> None:
        """A listed module that disappears must fail loudly, not shrink the count."""
        assert_complete()


class TestComposition:
    """What is in the TCB, and why — as executable claims, not comments."""

    def test_executor_is_counted(self) -> None:
        """`executor.py` is the sole mutation path — it cannot be out of scope."""
        assert "effect_broker/executor.py" in TCB_FILES, (
            "the only path that mutates external state is not in the measured TCB"
        )

    def test_the_security_relevant_modules_are_all_included(self) -> None:
        """Guard against the *next* module: anything the gate decides with belongs.

        The concrete form of "a defect here can swap accept and reject". If a
        module is added and the gate calls into it, a reviewer must decide
        explicitly whether it joins the TCB.
        """
        expected_minimum = {
            "effect_broker/broker.py",
            "effect_broker/model.py",
            "effect_broker/executor.py",
        }
        assert expected_minimum <= set(TCB_FILES), (
            f"missing from the TCB: {sorted(expected_minimum - set(TCB_FILES))}"
        )

    def test_observation_and_advice_are_excluded(self) -> None:
        """`ledger.py` records and `mediation.py` advises; neither decides.

        Counting them would inflate the TCB with code the allow/deny argument
        does not rest on.
        """
        for excluded, reason in (
            ("effect_broker/ledger.py", "audit observer"),
            ("effect_broker/mediation.py", "advisory boundary check"),
        ):
            assert excluded not in TCB_FILES, f"{excluded} ({reason}) must stay out"

    def test_shims_baselines_and_tests_are_excluded(self) -> None:
        """Comparators exist to be scored, not trusted."""
        for untrusted in (
            "effect_broker/shim_email.py",
            "tests/test_tcb_measurement.py",
        ):
            assert untrusted not in TCB_FILES

    def test_every_module_has_a_stated_role(self) -> None:
        """A file with no role is a file nobody argued for."""
        assert len(TCB_MODULES) == len(TCB_FILES)
        for path, role in TCB_MODULES:
            assert role.strip(), f"{path} is in the TCB with no stated role"

    def test_every_listed_file_exists(self) -> None:
        """A renamed module would otherwise be skipped silently by tcb_size()."""
        for rel in TCB_FILES:
            assert (_REPO_ROOT / rel).exists(), (
                f"{rel} is listed but does not exist; the line count skips missing "
                f"paths, so the metric would undercount without failing"
            )


class TestInterdependency:
    """The TCB must not quietly reach into untrusted code for a decision.

    A gate that consults a shim or the evaluation harness for its verdict is not
    gated by the listed code, however the line count reads.
    """

    def test_the_gate_does_not_import_untrusted_modules(self) -> None:
        untrusted = {
            "effect_broker.shim_email",
            "effect_broker.shim_real",
            "effect_broker.baselines",
            "effect_broker.metrics",
            "effect_broker.traces",
        }
        for rel in TCB_FILES:
            leaked = _imports(rel) & untrusted
            assert not leaked, f"{rel} imports untrusted {sorted(leaked)} for its decision"


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
        """An empty docstring parses as a literal spanning one line — exclude it."""
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
        for rel in TCB_FILES:
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

    def test_the_total_is_the_sum_of_the_parts(self) -> None:
        """The breakdown must reconcile with the reported figure."""
        breakdown = tcb_breakdown()
        assert set(breakdown) == {Path(rel).name for rel in TCB_FILES}
        assert sum(breakdown.values()) == tcb_size()

    def test_every_module_contributes_code(self) -> None:
        """A zero means the file was skipped, not that it is empty."""
        for name, count in tcb_breakdown().items():
            assert count > 0, f"{name} contributes 0 lines — was it skipped?"

    def test_the_tcb_is_not_a_token_number(self) -> None:
        assert tcb_size() > 1000, f"implausibly small trusted core: {tcb_size()}"
