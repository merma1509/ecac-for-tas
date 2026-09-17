"""Pytest configuration: suppress the same-process isolation advisory in tests.

The ResourceStore's SAME-PROCESS warning is legitimate production safety advice
(informing the deployer that real isolation requires a separate process/enclave).
It fires once per Python process (guarded by _warn_once()).

In test context, every test imports ResourceStore and the warning is noise.
We suppress it here so test output stays clean — it remains visible when
running traces directly (python run_traces.py) in production mode.
"""

from __future__ import annotations

# Suppress BEFORE any test imports — this must be at module level, before
# pytest loads test modules (which import ResourceStore and trigger the warning).
import warnings

warnings.filterwarnings(
    "ignore",
    message="SAME-PROCESS: ResourceStore lives in the same Python process",
    category=UserWarning,
)