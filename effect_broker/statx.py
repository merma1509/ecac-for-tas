"""Shared os.statx constants and label-derivation (single source of truth).

Every process that classifies a file from OS metadata (broker,
shim, executor subprocess) must read the SAME bits. Previously each process
hard-coded its own `1 << 0` / `1 << 1` and its own permission-bit rules, so
the ENCRYPTED/IMMUTABLE bits and the mode→Confidentiality mapping could
diverge silently. This module is the single definition used by all of them.

Resolution order (first match wins) mirrors broker.derive_file_provenance():
  1. statx attribute bits  — ENCRYPTED (bit 0), IMMUTABLE (bit 1)
  2. permission bits       — owner-only / group / world readable
  3. keyword fallback      — for new files not yet on disk
"""

from __future__ import annotations

import os
from enum import IntEnum

from .lattice import Confidentiality, Integrity


# Linux kernel constants from <linux/stat.h>, with cross-platform fallback.
# os.STATX_* exists only on Linux with a recent enough Python; elsewhere we
# use the explicit values so the code still runs (and degrades to stat()).
STATX_ALL: int = getattr(os, "STATX_ALL", 0x00000FFF)
STATX_ATTR_ENCRYPTED: int = getattr(os, "STATX_ATTR_ENCRYPTED", 1 << 0)  # fscrypt
STATX_ATTR_IMMUTABLE: int = getattr(os, "STATX_ATTR_IMMUTABLE", 1 << 1)  # chattr +i


def statx_available() -> bool:
    """True if this platform's os module exposes os.statx()."""
    return hasattr(os, "statx")


def try_statx_attributes(path: str) -> int | None:
    """Return stx_attributes for `path`, or None when statx is unavailable.

    Callers fall through to permission bits (or keywords) when None is
    returned. This is the ONLY place that touches os.statx directly.
    """
    if not statx_available():
        return None
    try:
        stx = os.statx(path, flags=STATX_ALL)  # type: ignore[attr-defined]
        return int(stx.stx_attributes)
    except (OSError, AttributeError):
        return None


def derive_confidentiality_from_mode(mode_int: int) -> Confidentiality:
    """Map Unix permission bits to a Confidentiality level.

      owner-only            (mode & 0o007 == 0)  → CONFIDENTIAL
      group/world readable  (mode & 0o070 != 0)  → INTERNAL (if group)
      world-readable        (mode & 0o004 != 0)  → PUBLIC

    This is the single authoritative mode→Confidentiality mapping. It is the
    same rule the executor subprocess used to hard-code.
    """
    if mode_int & 0o007 == 0:
        return Confidentiality.CONFIDENTIAL  # owner-only
    if mode_int & 0o070 != 0:
        return Confidentiality.INTERNAL  # group-readable
    if mode_int & 0o004 != 0:
        return Confidentiality.PUBLIC  # world-readable
    return Confidentiality.PUBLIC


def derive_confidentiality_mode_str(mode_int: int) -> str:
    """String form of derive_confidentiality_from_mode for the subprocess.

    The executor subprocess derives a plain-string confidentiality label from
    the REAL permission bits (it does not import the lattice enums). This is
    the single place that rule lives — forking callers must call HERE rather
    than re-implement `mode & 0o007` themselves
    """
    return derive_confidentiality_from_mode(mode_int).name


def try_statx_label(path: str) -> Confidentiality | None:
    """Derive a Confidentiality from OS-level statx attribute bits, if any.

    Returns CONFIDENTIAL when the file carries ENCRYPTED, or IMMUTABLE with
    owner-only mode; INTERNAL for IMMUTABLE with broader access. Returns None
    when no such attribute is set (caller should fall back to permission bits).

    Only trusts the bits defined here — never a tool-supplied label.
    """
    attrs = try_statx_attributes(path)
    if attrs is None:
        return None

    if attrs & STATX_ATTR_ENCRYPTED:
        return Confidentiality.CONFIDENTIAL
    if attrs & STATX_ATTR_IMMUTABLE:
        try:
            mode = os.stat(path).st_mode & 0o777
        except OSError:
            return None
        if mode & 0o077:
            return Confidentiality.INTERNAL
        return Confidentiality.CONFIDENTIAL
    return None


def permission_label(path: str) -> Confidentiality | None:
    """Derive Confidentiality from real permission bits, or None if absent."""
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        return None
    return derive_confidentiality_from_mode(mode)


def derive_provenance(
    path: str,
    keyword_table: list[tuple[str, Confidentiality]] | None = None,
) -> tuple[Confidentiality, Integrity]:
    """Full derivation: statx bits → permission bits → keyword → deny-most.

    This is the canonical (Confidentiality, Integrity) derivation used by
    every process. Integrity is USER for OS-derived content (the OS is a
    trusted source); UNTRUSTED is only ever applied to unsanitized external
    input elsewhere, never here.
    """
    # Step 1: OS-level attribute bits
    label = try_statx_label(path)
    if label is not None:
        return label, Integrity.USER

    # Step 2: permission bits
    mode_label = permission_label(path)
    if mode_label is not None:
        return mode_label, Integrity.USER

    # Step 3: keyword fallback (new files not yet on disk)
    if keyword_table:
        lower = path.lower()
        for keyword, conf in keyword_table:
            if keyword.lower() in lower:
                return conf, Integrity.USER

    # Step 4: deny-most default
    return Confidentiality.INTERNAL, Integrity.USER
