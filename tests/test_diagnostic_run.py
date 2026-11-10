"""Diagnostic run reports all seven metrics

The requirement is that every metric in the Part E table is present in the
output, including the trusted boundary — a table missing one of them reads as
"not measured" rather than "zero".
"""

from __future__ import annotations

import json
import subprocess
import sys

from effect_broker.metrics import diagnostic_report, trusted_boundary

SEVEN_KEYS = (
    "unauthorized_effects",
    "legitimate_completion",
    "false_denials",
    "unknown_outcomes",
    "approvals",
    "overhead",
    "trusted_boundary",
)


class TestAllSevenMetricsPresent:
    def test_every_metric_key_exists(self) -> None:
        report = diagnostic_report()
        missing = [k for k in SEVEN_KEYS if k not in report]
        assert not missing, f"missing Part E metrics: {missing}"

    def test_metrics_are_zero_not_absent(self) -> None:
        """A zero must be a 0, not a missing key."""
        report = diagnostic_report()
        assert report["unauthorized_effects"] is not None
        assert report["unknown_outcomes"] is not None
        assert isinstance(report["unknown_outcomes"], int)

    def test_false_denials_is_breakdown_by_predicate(self) -> None:
        assert isinstance(diagnostic_report()["false_denials"], dict)

    def test_approvals_has_three_states(self) -> None:
        approvals = diagnostic_report()["approvals"]
        assert isinstance(approvals, dict)
        assert set(approvals) == {"granted", "used", "expired_unused"}

    def test_overhead_omits_unmeasured_syscalls(self) -> None:
        """Syscall counts are not portable; the honest value is null."""
        overhead = diagnostic_report()["overhead"]
        assert isinstance(overhead, dict)
        assert overhead["syscalls"] is None
        assert "wall_clock_p50_ms" in overhead


class TestTrustedBoundary:
    def test_boundary_is_non_empty_and_named(self) -> None:
        boundary = trusted_boundary()
        assert boundary, "trusted boundary must be an explicit list"
        # Each entry names a file, so the boundary is checkable, not prose.
        assert all("/" in entry for entry in boundary)

    def test_boundary_names_the_shim_and_broker(self) -> None:
        joined = " ".join(trusted_boundary())
        assert "shim_real.py" in joined
        assert "broker.py" in joined

    def test_report_carries_the_boundary(self) -> None:
        assert diagnostic_report()["trusted_boundary"] == trusted_boundary()


class TestOutputForms:
    def test_report_is_json_serializable(self) -> None:
        """The script promises JSON; the report must survive dumps."""
        json.dumps(diagnostic_report())

    def test_script_json_mode_emits_all_seven(self) -> None:
        proc = subprocess.run(
            [sys.executable, "scripts/diagnostic_run.py", "--json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        missing = [k for k in SEVEN_KEYS if k not in payload]
        assert not missing, f"script output lacks: {missing}"

    def test_script_text_mode_names_the_boundary(self) -> None:
        proc = subprocess.run(
            [sys.executable, "scripts/diagnostic_run.py"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        assert "Trusted boundary" in proc.stdout
        assert "UNKNOWN outcomes" in proc.stdout
