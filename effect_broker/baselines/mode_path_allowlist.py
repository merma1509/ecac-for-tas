"""Path/host allowlist baseline — NOT a sandbox comparator.

This file used to be called `mode_conventional_sandbox.py` and claimed to model
"seccomp + landlock/SELinux". It did not. It performs string comparisons on
`effect.target`: a write is allowed if it starts with one of `_WRITABLE_ROOTS`,
a network effect is allowed if `_host_of()` matches one of `_ALLOWED_HOSTS`.
There is no syscall filter, no path confinement enforced by the kernel, and no
landlock rule anywhere — the kernel is never involved.

That mattered because a comparative number measured against it measures
nothing: ECAC was being compared against a stub wearing the name of a real
mechanism. this gives two acceptable outcomes per baseline — implement
the named mechanism, or rename the file. This is the rename.

**What this baseline IS:** a path/host allowlist, the kind of check a proxy or
a policy file performs. It is a legitimate weak baseline and it is useful as
one: it blocks out-of-root writes and disallowed egress, and it is blind to
dataflow, recipients and freshness. That blindness is real, not simulated.

**What it is NOT:** a conventional OS sandbox. Do not cite it as one. A real
sandbox comparator needs Landlock (Linux) or a seatbelt profile (macOS) actually
enforced by the kernel, plus evidence that a denied path fails with `EACCES`.

Every decision this module made before the
rename is retained, so the trace outcomes are unchanged: only the name and the
claims change.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from effect_broker.model import Effect

#: Paths this allowlist permits writing/deleting under.
_WRITABLE_ROOTS = ("file:///sandbox/",)
#: Hosts this allowlist permits reaching.
_ALLOWED_HOSTS = {"internal.corp.com"}

#: What this baseline actually enforces. Quoted in the comparator table so the
#: claim and the code cannot drift apart.
MECHANISMS: tuple[str, ...] = (
    "target-path prefix allowlist (string compare, in-process)",
    "target-host allowlist (string compare, in-process)",
)

#: What this baseline deliberately does NOT do. Listed so the omission is
#: documented rather than discovered.
NOT_IMPLEMENTED: tuple[str, ...] = (
    "syscall filtering (seccomp) — no kernel enforcement",
    "path confinement (Landlock/SELinux/seatbelt) — string compare only",
    "capability system",
    "IFC / dataflow tracking / session taint",
    "recipient (BCC) scoping — a send is a send once the socket is open",
    "freshness / replay check — stateless per effect",
    "ledger / independent observation",
)


def _host_of(target: str) -> str | None:
    """Extract the host from an http(s):// target, else None."""
    if "://" not in target:
        return None
    after = target.split("://", 1)[1]
    path_start = after.find("/")
    host = after[:path_start] if path_start >= 0 else after
    return host.split(":")[0].lower()


class PathAllowlistBroker:
    """Path/host allowlist. Weak by construction; honest about why.

    Decides purely on the resource's PATH/HOST against a static allowlist. No
    state is tracked across effects, so it cannot see dataflow, hidden email
    recipients, or replay.
    """

    def commit_effect(self, effect: Effect, task_id: str = "default") -> tuple[bool, dict]:
        # 1) Network egress: allow only allowlisted hosts.
        if effect.etype == "network":
            host = _host_of(effect.target)
            if host is not None and host not in _ALLOWED_HOSTS:
                return False, {
                    "blocker": "PathAllowlist",
                    "reason": f"network-egress-blocked(host={host})",
                    "policy": "PathAllowlist",
                }
            return True, {
                "blocker": None,
                "reason": "network-egress-allowed",
                "policy": "PathAllowlist",
            }

        # 2) File write: allow only under the writable roots.
        if effect.etype == "write":
            if effect.target.startswith(_WRITABLE_ROOTS):
                return True, {
                    "blocker": None,
                    "reason": "write-within-allowlist-root",
                    "policy": "PathAllowlist",
                }
            return False, {
                "blocker": "PathAllowlist",
                "reason": "write-outside-allowlist-root",
                "policy": "PathAllowlist",
            }

        # 3) read / delete / send: an allowlist cannot see dataflow or email
        #    recipients. Once the file is readable or the SMTP socket is open,
        #    the allowlist permits it. This is the gap ECAC closes.
        if effect.etype == "send":
            return True, {
                "blocker": None,
                "reason": "send-permitted(allowlist-cannot-see-recipients)",
                "policy": "PathAllowlist",
            }
        if effect.etype in ("read", "delete"):
            if effect.etype == "delete" and not effect.target.startswith(_WRITABLE_ROOTS):
                return False, {
                    "blocker": "PathAllowlist",
                    "reason": "delete-outside-allowlist-root",
                    "policy": "PathAllowlist",
                }
            return True, {
                "blocker": None,
                "reason": f"{effect.etype}-within-path-allowlist",
                "policy": "PathAllowlist",
            }

        # Unknown effect type: fail closed.
        return False, {
            "blocker": "PathAllowlist",
            "reason": f"unknown-effect-type({effect.etype})",
            "policy": "PathAllowlist",
        }
