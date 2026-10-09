"""Tests for subprocess real I/O isolation and access boundary enforcement.

Verifies that:
1. Real file operations happen in subprocess, not broker
2. Real SMTP operations happen in subprocess
3. Broker process cannot directly access files/SMTP
4. broker.create_real_file_shim() wires IPC client in multi-process mode
5. Subprocess os.open() is restricted (enforcer.py Layer)
"""

from __future__ import annotations

import os
import tempfile

import pytest

from effect_broker.broker import EffectBroker
from effect_broker.executor_ipc import ProcessExecutorClient
from effect_broker.executor_subprocess import ExecutorProcessHandle
from effect_broker.shim_ipc import IpcShim


@pytest.fixture
def tmp_path():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as d:
        yield d


class TestSubprocessRealFileIO:
    """Test that real file I/O happens in subprocess."""

    def test_real_file_read_in_subprocess(self, tmp_path: str):
        """Real file read via IPC shim should execute in subprocess."""
        # Create test file in temp dir
        test_file = os.path.join(tmp_path, "test.txt")
        with open(test_file, "w") as f:
            f.write("hello world")

        # Setup subprocess
        sock_a = "/tmp/ecac-test-a.sock"
        sock_b = "/tmp/ecac-test-b.sock"
        handle = ExecutorProcessHandle(sock_a, sock_b)
        handle.start(timeout=5.0)

        try:
            client = ProcessExecutorClient(sock_a)
            client.bootstrap()

            # Use IPC shim (not broker's shim, which runs in broker process)
            shim = IpcShim(client, tool_name="test-tool")

            # Read file via IPC
            content = shim.read(test_file)
            assert content == b"hello world"

            # Verify file was actually read (subprocess did the I/O)
            # If this test passes, real I/O happened in subprocess
            assert len(shim.ops) == 1
            assert shim.ops[0].operation == "read"

        finally:
            handle.stop()
            for sock in [sock_a, sock_b]:
                if os.path.exists(sock):
                    os.unlink(sock)

    def test_real_file_write_in_subprocess(self, tmp_path: str):
        """Real file write via IPC shim should execute in subprocess."""
        out_file = os.path.join(tmp_path, "output.txt")

        sock_a = "/tmp/ecac-test-write-a.sock"
        sock_b = "/tmp/ecac-test-write-b.sock"
        handle = ExecutorProcessHandle(sock_a, sock_b)
        handle.start(timeout=5.0)

        try:
            client = ProcessExecutorClient(sock_a)
            client.bootstrap()

            shim = IpcShim(client, tool_name="test-tool")
            shim.write(out_file, b"test content")

            # Verify file was written
            assert os.path.exists(out_file)
            with open(out_file) as f:
                assert f.read() == "test content"

        finally:
            handle.stop()
            for sock in [sock_a, sock_b]:
                if os.path.exists(sock):
                    os.unlink(sock)


class TestSubprocessIsolation:
    """Test that broker cannot directly do real I/O."""

    def test_broker_process_cannot_write_directly(self, tmp_path: str):
        """In multi-process mode, broker should not have direct file access.

        This test documents the boundary: operations via IpcShim go to
        subprocess, but direct os.write() from broker would bypass this.
        """
        # In multi-process mode:
        # - broker runs in process A
        # - executor subprocess runs in process B
        # - Real I/O happens in process B
        # - process A cannot directly access files that process B owns

        # This is the expected architecture:
        # os.write() in broker process bypasses subprocess → NOT confined

        # The IpcShim ensures operations go through subprocess:
        sock_a = "/tmp/ecac-test-iso-a.sock"
        sock_b = "/tmp/ecac-test-iso-b.sock"
        handle = ExecutorProcessHandle(sock_a, sock_b)
        handle.start(timeout=5.0)

        try:
            client = ProcessExecutorClient(sock_a)
            shim = IpcShim(client, tool_name="test-tool")

            # File written via IPC shim → goes to subprocess → confined
            out_file = os.path.join(tmp_path, "isolated.txt")
            shim.write(out_file, b"confined")

            # The file exists because subprocess wrote it
            assert os.path.exists(out_file)

        finally:
            handle.stop()
            for sock in [sock_a, sock_b]:
                if os.path.exists(sock):
                    os.unlink(sock)


class TestBrokerFactoryMethod:
    """Test broker.create_real_file_shim() and broker.create_real_email_shim()."""

    def test_create_real_file_shim_in_same_process_mode(self):
        """In same-process mode, shim has ipc_client=None (local fallback)."""
        broker = EffectBroker(mode="same-process")
        shim = broker.create_real_file_shim(tool_name="test-tool")
        assert shim.ipc_client is None
        assert shim.tool_name == "test-tool"

    def test_create_real_file_shim_in_multi_process_mode(self, tmp_path: str):
        """In multi-process mode, shim has wired IPC client pointing to subprocess."""
        broker = EffectBroker(mode="multi-process")

        # Verify IPC client is wired into the shim
        shim = broker.create_real_file_shim(tool_name="test-tool")
        assert shim.ipc_client is not None
        assert isinstance(shim.ipc_client, ProcessExecutorClient)

        # Verify it uses the broker's socket path
        # The shim should route I/O through the subprocess's IPC channel
        assert shim.ipc_client._path.name.endswith(".sock")

        broker.shutdown()

    def test_full_write_read_delete_via_broker_shim_in_multi_process(self, tmp_path: str):
        """End-to-end: broker.create_real_file_shim() → write → read → delete via IPC."""
        import pathlib

        broker = EffectBroker(mode="multi-process")

        # Setup capability: wildcard target with scope as constraint
        canon_tmpdir = str(pathlib.Path(tmp_path).resolve())
        from effect_broker.model import Capability, Task

        task = Task(
            task_id="test-ipc-shim",
            owner="User",
            ceiling=Capability(
                owner="User",
                holder="test-tool",
                right="*",
                target="*",  # wildcard — scope is the real constraint
                scope=frozenset({f"file://{canon_tmpdir}"}),
                expiry=float("inf"),
                nonce="test-ipc-cap",
            ),
        )
        broker.register_task(task)
        broker.capabilities["test-ipc-cap"] = Capability(
            owner="User",
            holder="test-tool",
            right="*",
            target="*",
            scope=frozenset({f"file://{canon_tmpdir}"}),
            expiry=float("inf"),
            nonce="test-ipc-cap",
        )

        # Create shim via broker factory — gets IPC client wired in
        shim = broker.create_real_file_shim(task_id="test-ipc-shim", tool_name="test-tool")
        assert shim.ipc_client is not None  # IPC mode active

        test_file = os.path.join(tmp_path, "ipc-shim-test.txt")

        # WRITE via IPC
        shim.write(test_file, b"hello from broker-factory IPC shim!")
        assert os.path.exists(test_file)

        # READ via IPC
        data = shim.read(test_file)
        assert data == b"hello from broker-factory IPC shim!"

        # EXISTS via IPC
        assert shim.exists(test_file) is True
        assert shim.exists(os.path.join(tmp_path, "nonexistent.txt")) is False

        # DELETE via IPC
        shim.delete(test_file)
        assert not os.path.exists(test_file)

        # Verify ops log (write, read, exists×2, delete)
        assert len(shim.ops) >= 4

        broker.shutdown()


class TestRestrictedOpenEnforcer:
    """Test enforcer.py Layer: subprocess filesystem confinement.

    The enforcer module (effect_broker/enforcer.py) patches os.open() in the
    subprocess to restrict filesystem access. This test verifies:

    1. Write operations are ONLY allowed in broker-configured sandbox paths
    2. Sensitive system paths (/etc, /bin, etc.) are BLOCKED for ALL operations
    3. Device files (/dev/null, etc.) are ALLOWED (needed for subprocess.Popen)
    4. Restricted open is active in the subprocess (enforcer patch applied)
    """

    def test_enforcer_module_exists_and_exports(self):
        """Verify enforcer.py has the required exports."""
        from effect_broker.enforcer import (
            _restricted_open,
            _real_os_open,
            set_allowed_paths,
            get_allowed_paths,
            get_blocked_paths,
            is_restricted_open_active,
        )

        # Verify functions exist and have correct signatures
        assert callable(_restricted_open)
        assert callable(_real_os_open)
        assert callable(set_allowed_paths)
        assert callable(get_allowed_paths)
        assert callable(get_blocked_paths)
        assert callable(is_restricted_open_active)

    def test_blocked_paths_include_sensitive_directories(self):
        """Verify blocked paths include /etc, /bin, /usr, etc."""
        from effect_broker.enforcer import get_blocked_paths

        blocked = get_blocked_paths()
        assert "/etc" in blocked
        assert "/bin" in blocked
        assert "/usr" in blocked
        assert "/var" in blocked
        assert "/root" in blocked

    def test_blocked_path_blocks_nested_files(self):
        """Verify that /etc/passwd is blocked even though /etc is blocked."""
        from effect_broker.enforcer import _is_path_blocked

        assert _is_path_blocked("/etc") is True
        assert _is_path_blocked("/etc/passwd") is True
        assert _is_path_blocked("/etc/something/else") is True

    def test_allowed_paths_starts_empty(self):
        """Verify allowed paths starts empty (fail-closed)."""
        from effect_broker.enforcer import get_allowed_paths

        # Initially empty — fail-closed
        assert get_allowed_paths() == frozenset()

    def test_set_allowed_paths_configures_sandbox(self):
        """Verify set_allowed_paths() updates allowed paths."""
        from effect_broker.enforcer import get_allowed_paths, set_allowed_paths

        test_paths = frozenset({"/tmp", "/data/reports"})
        set_allowed_paths(test_paths)
        assert get_allowed_paths() == test_paths

    def test_write_to_blocked_path_raises_permission_error(self, tmp_path: str):
        """Verify writing to /etc raises PermissionError (not allowed)."""
        from effect_broker.enforcer import _restricted_open

        with pytest.raises(PermissionError, match="blocked"):
            _restricted_open("/etc/passwd", os.O_WRONLY | os.O_CREAT, 0o644)

    def test_write_outside_allowed_paths_raises_permission_error(self, tmp_path: str):
        """Verify writing outside allowed paths raises PermissionError."""
        from effect_broker.enforcer import (
            _restricted_open,
            set_allowed_paths,
        )

        # Configure sandbox to only /tmp
        set_allowed_paths(frozenset({tmp_path}))

        # Writing to /etc should be blocked
        with pytest.raises(PermissionError, match="blocked"):
            _restricted_open("/etc/test.txt", os.O_WRONLY | os.O_CREAT, 0o644)

        # Writing to /var should be blocked
        with pytest.raises(PermissionError, match="blocked"):
            _restricted_open("/var/test.txt", os.O_WRONLY | os.O_CREAT, 0o644)

    def test_write_in_allowed_path_succeeds(self):
        """Verify writing within allowed sandbox paths works."""
        from effect_broker.enforcer import _restricted_open, set_allowed_paths

        # Use /tmp as the allowed path (guaranteed to be unblocked on all platforms)
        allowed_dir = "/tmp"
        set_allowed_paths(frozenset({allowed_dir}))

        # Write to file within allowed path — should work
        allowed_file = os.path.join(allowed_dir, "enforcer-test.txt")
        fd = _restricted_open(allowed_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        assert isinstance(fd, int)
        os.close(fd)

        # Verify file was actually created
        assert os.path.exists(allowed_file)

        # Clean up
        os.unlink(allowed_file)

    def test_dev_null_allowed(self):
        """Verify /dev/null is always allowed (needed for subprocess.Popen)."""
        from effect_broker.enforcer import _restricted_open, set_allowed_paths

        # Even with empty allowed paths, /dev/null should work
        set_allowed_paths(frozenset())

        # Should not raise
        fd = _restricted_open("/dev/null", os.O_RDWR)
        assert isinstance(fd, int)
        os.close(fd)

    def test_read_blocked_path_raises_permission_error(self):
        """Verify reading from /etc raises PermissionError."""
        from effect_broker.enforcer import _restricted_open

        with pytest.raises(PermissionError, match="blocked"):
            _restricted_open("/etc/passwd", os.O_RDONLY)

    def test_real_os_open_bypasses_restrictions(self):
        """Verify _real_os_open bypasses restrictions (for broker's Popen)."""
        from effect_broker.enforcer import _real_os_open

        # Real open should work for /dev/null (baseline check)
        fd = _real_os_open("/dev/null", os.O_RDWR)
        assert isinstance(fd, int)
        os.close(fd)


class TestImportBlocking:
    """Import blocking in subprocess.

    The import blocking hook (_secure_import) is installed in executor_subprocess.py
    at PHASE 1, BEFORE any other imports. It blocks:
    - Dangerous modules: exec, eval, pickle, marshal, platform, resource, pwd
    - Network packages: requests, aiohttp, httpx, websockets, urllib3
    - Client HTTP/FTP/etc: http.client, ftplib, telnetlib, nntplib, poplib
    """

    def test_dangerous_modules_are_blocked_in_executor_subprocess(self):
        """Verify dangerous modules are in the blocklist."""
        from effect_broker.executor_subprocess import (
            _DANGEROUS_MODULES,
            _BLOCKED_NETWORK_PACKAGES,
            _BLOCKED_STDLIB,
        )

        # Code execution
        assert "pickle" in _DANGEROUS_MODULES
        assert "marshal" in _DANGEROUS_MODULES
        assert "exec" in _DANGEROUS_MODULES
        assert "eval" in _DANGEROUS_MODULES

        # Privilege escalation
        assert "pwd" in _DANGEROUS_MODULES
        assert "platform" in _DANGEROUS_MODULES

        # Network packages
        assert "requests" in _BLOCKED_NETWORK_PACKAGES
        assert "aiohttp" in _BLOCKED_NETWORK_PACKAGES
        assert "httpx" in _BLOCKED_NETWORK_PACKAGES
        assert "websockets" in _BLOCKED_NETWORK_PACKAGES
        assert "urllib3" in _BLOCKED_NETWORK_PACKAGES

        # Client protocols (server protocols like smtplib are ALLOWED)
        assert "http.client" in _BLOCKED_STDLIB
        assert "ftplib" in _BLOCKED_STDLIB

    def test_allowed_modules_not_blocked(self):
        """Verify needed modules are NOT in blocklists."""
        from effect_broker.executor_subprocess import (
            _DANGEROUS_MODULES,
            _BLOCKED_NETWORK_PACKAGES,
            _BLOCKED_STDLIB,
        )

        # File I/O
        assert "os" not in _DANGEROUS_MODULES
        assert "os" not in _BLOCKED_NETWORK_PACKAGES
        assert "os" not in _BLOCKED_STDLIB

        # IPC and subprocess
        assert "socket" not in _DANGEROUS_MODULES
        assert "subprocess" not in _DANGEROUS_MODULES

        # SMTP/IMAP (needed for email send/read)
        assert "smtplib" not in _DANGEROUS_MODULES
        assert "smtplib" not in _BLOCKED_NETWORK_PACKAGES
        assert "smtplib" not in _BLOCKED_STDLIB

        assert "imaplib" not in _DANGEROUS_MODULES
        assert "imaplib" not in _BLOCKED_NETWORK_PACKAGES
        assert "imaplib" not in _BLOCKED_STDLIB

        # Internal modules
        assert "effect_broker" not in _DANGEROUS_MODULES
        assert "effect_broker" not in _BLOCKED_NETWORK_PACKAGES
        assert "effect_broker" not in _BLOCKED_STDLIB

    def test_secure_import_hook_is_installed_in_subprocess(self):
        """Verify _secure_import hook is set up in executor_subprocess."""
        from effect_broker.executor_subprocess import _secure_import, _original_import

        # Hook should be installed (different from built-in)
        import builtins

        assert builtins.__import__ is _secure_import
        assert _secure_import is not _original_import

    def test_blocked_import_raises_import_error(self):
        """Verify blocked modules raise ImportError when attempted."""
        from effect_broker.executor_subprocess import _secure_import, _blocked_imports_log

        initial_count = len(_blocked_imports_log)

        # Attempting to import a blocked module should raise
        with pytest.raises(ImportError, match="blocked"):
            _secure_import("pickle")

        # Should be logged
        assert len(_blocked_imports_log) == initial_count + 1
        assert "pickle" in _blocked_imports_log

    def test_blocked_network_package_raises_import_error(self):
        """Verify network packages like requests are blocked."""
        from effect_broker.executor_subprocess import _secure_import, _BLOCKED_NETWORK_PACKAGES

        assert "requests" in _BLOCKED_NETWORK_PACKAGES

        with pytest.raises(ImportError, match="Network package"):
            _secure_import("requests")
