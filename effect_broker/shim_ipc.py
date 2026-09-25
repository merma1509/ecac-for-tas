"""IPC-based shim: routes real file/SMTP operations to the executor subprocess.

This shim is used in multi-process mode. All real I/O (file read/write,
SMTP send) happens in the isolated subprocess, not in the broker process.
The broker only does gate evaluation; actual operations go through IPC.

Usage (multi-process mode):
    broker = EffectBroker(mode="multi-process")
    shim = IpcShim(broker._executor._client)
    shim.write("path", content)  # executed in subprocess
"""

from __future__ import annotations

import base64
import pathlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .lattice import Confidentiality, Integrity
from .model import Data, Effect, EffectTarget

if TYPE_CHECKING:
    from .executor_ipc import ProcessExecutorClient


@dataclass
class IpcOp:
    """Record of an IPC operation to the subprocess."""

    operation: str  # read | write | delete | send
    path_or_target: str
    result: dict
    blocked: bool = False


@dataclass
class IpcShim:
    """IPC-based shim: routes operations to the isolated executor subprocess.

    This ensures ALL real I/O happens in the subprocess, providing actual
    isolation of file/SMTP operations from the broker process.
    """

    client: ProcessExecutorClient  # IPC client connected to subprocess
    tool_name: str = "ipc-tool"
    ops: list[IpcOp] = field(default_factory=list)

    # ---- Public tool-facing API (mirrors RealFileShim + RealEmailShim) ----
    def read(self, path: str) -> bytes:
        """Read a real file via subprocess IPC."""
        # client.real_file_read raises RuntimeError on failure
        result = self.client.real_file_read(path)
        # result is {"content": base64_str, "path": str}
        content = base64.b64decode(result["content"])
        self.ops.append(IpcOp("read", path, result))
        return content

    def write(self, path: str, content: bytes) -> None:
        """Write content to a real file via subprocess IPC."""
        # client.real_file_write raises RuntimeError on failure
        result = self.client.real_file_write(path, content)
        self.ops.append(IpcOp("write", path, result))

    def delete(self, path: str) -> None:
        """Delete a real file via subprocess IPC."""
        # client.real_file_delete raises RuntimeError on failure
        result = self.client.real_file_delete(path)
        self.ops.append(IpcOp("delete", path, result))

    def stat(self, path: str) -> dict:
        """Get file metadata via subprocess IPC."""
        # client.real_file_stat raises RuntimeError on failure
        result = self.client.real_file_stat(path)
        self.ops.append(IpcOp("stat", path, result))
        return result.get("stat", {})

    def listdir(self, path: str) -> list[str]:
        """List directory via subprocess IPC."""
        # client.real_file_listdir raises RuntimeError on failure
        result = self.client.real_file_listdir(path)
        self.ops.append(IpcOp("listdir", path, result))
        return result.get("entries", [])

    def send(self, sender: str, recipients: list[str], body: str) -> list[str]:
        """Send real email via subprocess IPC.

        RSET probe happens in subprocess - BCC recipients are detected
        before any message is queued.

        Returns: list of successfully delivered recipients
        Raises: SecurityError if BCC detected, OSError if send fails
        """
        # client.real_smtp_send raises RuntimeError on failure
        result = self.client.real_smtp_send(sender, recipients, body)
        # result is {"delivered": [...], "bcc_detected": [...]}
        bcc = result.get("bcc_detected", [])
        if bcc:
            raise SecurityError(f"BCC detected: {bcc}")
        delivered = result.get("delivered", [])
        self.ops.append(IpcOp("send", sender, result))
        return delivered

    def get_ops(self) -> list[IpcOp]:
        """Return operation log."""
        return list(self.ops)


class SecurityError(Exception):
    """Raised when operation is blocked (e.g., BCC detected)."""
    pass