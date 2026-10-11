"""Conventional OS-sandbox baseline (seccomp/landlock/SELinux-style).

This baseline models the protection a conventional OS sandbox gives the tool
process: syscall filtering (seccomp) + path confinement (landlock/SELinux).
It answers "is this syscall/path allowed?" but has NONE of the following:

  - No capability system          (no derivation / attenuation / scope)
  - No IFC / dataflow tracking     (no provenance, no session taint)
  - No BCC / extra-target scoping  (a send is a send once the socket is open)
  - No freshness / replay check    (no nonce lifetime)
  - No ledger / independent observer

What it DOES provide (and therefore where it is SUFFICIENT on its own):
  - Blocks syscalls outside the allowlist (e.g. no execve of arbitrary tools).
  - Blocks file writes outside the allowed sandbox root (landlock/SELinux).
  - Blocks network egress to hosts outside the allowlist (cgroup/netfilter).

Where ECAC adds value over a conventional sandbox (the comparison point):
  - read(CONFIDENTIAL) -> send exfiltration (session taint, not path).
  - capability-scope bypass (a file inside the sandbox dir but outside the
    capability's granted scope).
  - BCC / hidden-recipient scoping (the sandbox cannot see email recipients).
  - nonce replay / approval binding (the sandbox is stateless per syscall).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from effect_broker.model import Effect

# Path confinement: only this root is writable (landlock/SELinux style).
_WRITABLE_ROOTS = ("file:///sandbox/",)
# Network egress allowlist: only these hosts may be reached.
_ALLOWED_HOSTS = {"internal.corp.com"}
# Syscalls implied by each effect type that a seccomp policy would permit.
# (read/write are allowed; the confinement is on PATH/HOST, not syscall name.)


def _host_of(target: str) -> str | None:
    """Extract the host from an http(s):// target, else None."""
    if "://" not in target:
        return None
    after = target.split("://", 1)[1]
    path_start = after.find("/")
    host = after[:path_start] if path_start >= 0 else after
    return host.split(":")[0].lower()


class ConventionalSandboxBroker:
    """Standard OS sandbox (seccomp + landlock + capability bounding).

    Decides purely on the resource's PATH/HOST against a static confinement
    policy. No state is tracked across effects, so it cannot see dataflow,
    hidden email recipients, or replay — the exact gaps ECAC's predicates close.
    """

    def commit_effect(self, effect: Effect, task_id: str = "default") -> tuple[bool, dict]:
        # 1) Network egress: allow only allowlisted hosts (cgroup/netfilter).
        if effect.etype == "network":
            host = _host_of(effect.target)
            if host is not None and host not in _ALLOWED_HOSTS:
                return False, {
                    "blocker": "ConventionalSandbox",
                    "reason": f"network-egress-blocked(host={host})",
                    "policy": "ConventionalSandbox",
                }
            return True, {
                "blocker": None,
                "reason": "network-egress-allowed",
                "policy": "ConventionalSandbox",
            }

        # 2) File write: allow only within the writable sandbox root (landlock).
        if effect.etype == "write":
            if effect.target.startswith(_WRITABLE_ROOTS):
                return True, {
                    "blocker": None,
                    "reason": "write-within-sandbox-root",
                    "policy": "ConventionalSandbox",
                }
            return False, {
                "blocker": "ConventionalSandbox",
                "reason": "write-outside-sandbox-root",
                "policy": "ConventionalSandbox",
            }

        # 3) read / delete / send: the sandbox cannot see dataflow or email
        #    recipients. Once the file is readable / the SMTP socket is open,
        #    the OS sandbox permits the syscall. This is the gap ECAC closes.
        #    - read: allowed (path confinement only; no taint tracking)
        #    - send: allowed (recipients invisible to the OS sandbox)
        #    - delete: allowed if the path is within the sandbox root
        if effect.etype == "send":
            return True, {
                "blocker": None,
                "reason": "send-permitted(smtp-socket-open,recipients-invisible)",
                "policy": "ConventionalSandbox",
            }
        if effect.etype in ("read", "delete"):
            if effect.etype == "delete" and not effect.target.startswith(_WRITABLE_ROOTS):
                return False, {
                    "blocker": "ConventionalSandbox",
                    "reason": "delete-outside-sandbox-root",
                    "policy": "ConventionalSandbox",
                }
            return True, {
                "blocker": None,
                "reason": f"{effect.etype}-within-path-confine",
                "policy": "ConventionalSandbox",
            }

        # Unknown effect type: fail closed.
        return False, {
            "blocker": "ConventionalSandbox",
            "reason": f"unknown-effect-type({effect.etype})",
            "policy": "ConventionalSandbox",
        }
