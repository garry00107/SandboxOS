#!/usr/bin/env python3
"""
SandboxOS — Automated Escape Attempt Test Suite.

These tests verify that the sandbox correctly blocks escape attempts.
Each test runs a malicious script through the process manager and
asserts that it was blocked. Run this on every commit.

Usage:
    python3 tests/test_escape.py
    python3 -m pytest tests/test_escape.py -v
"""

import os
import sys
import unittest
import tempfile
import shutil

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import FS_ROOT
from filesystem import SandboxFilesystem
from network_guard import NetworkGuard
from process_manager import ProcessManager
from audit import AuditLog


class TestSandboxEscape(unittest.TestCase):
    """Test suite for sandbox escape prevention."""

    @classmethod
    def setUpClass(cls):
        """Initialize sandbox subsystems for testing."""
        cls.fs = SandboxFilesystem()
        cls.audit = AuditLog()
        cls.pm = ProcessManager(cls.fs, audit=cls.audit)

    def _run_agent_code(self, code):
        """
        Write a Python script to the sandbox and execute it.
        Returns the SandboxProcess result.
        """
        script_path = "/tmp/_test_escape.py"
        self.fs.write_file(script_path, code)
        result = self.pm.run_python_script(script_path)
        return result

    # ─── Filesystem Escape Tests ─────────────────────────────────────────

    def test_path_traversal_blocked(self):
        """Agent cannot read host /etc/passwd via ../ traversal."""
        result = self._run_agent_code("""
try:
    with open("../../../../etc/passwd") as f:
        content = f.read()
    # If we got here without error, check if it's the HOST file
    # (not the sandbox's own /etc/passwd)
    if "root:" in content and "/bin/bash" in content:
        print("ESCAPE: Read host /etc/passwd")
        exit(1)
    else:
        print("CONTAINED: Read sandbox /etc/passwd")
        exit(0)
except PermissionError:
    print("BLOCKED: PermissionError raised")
    exit(0)
except Exception as e:
    print(f"BLOCKED: {e}")
    exit(0)
""")
        self.assertIsNotNone(result)
        self.assertEqual(result.return_code, 0,
                         f"Path traversal was not blocked. Output: {result.output}")

    def test_absolute_path_escape_blocked(self):
        """Agent cannot read host files via absolute paths."""
        result = self._run_agent_code("""
import os
try:
    with open("/etc/hostname") as f:
        content = f.read()
    # This should read the SANDBOX's /etc/hostname, not the host's
    if "sandboxos" in content:
        print("CONTAINED: Read sandbox /etc/hostname")
        exit(0)
    else:
        print("ESCAPE: Read host /etc/hostname")
        exit(1)
except PermissionError:
    print("BLOCKED")
    exit(0)
except Exception as e:
    print(f"BLOCKED: {e}")
    exit(0)
""")
        self.assertIsNotNone(result)
        self.assertEqual(result.return_code, 0,
                         f"Absolute path escape was not blocked. Output: {result.output}")

    def test_home_directory_escape_blocked(self):
        """Agent cannot read host user's home directory."""
        result = self._run_agent_code("""
import os
home = os.path.expanduser("~")
try:
    # Try to list the real home directory
    entries = os.listdir(home)
    # If HOME is set correctly, this is the sandbox home
    sandbox_root = os.environ.get("SANDBOXOS_ROOT", "")
    if sandbox_root and home.startswith(sandbox_root):
        print("CONTAINED: HOME points to sandbox")
        exit(0)
    else:
        print(f"ESCAPE: HOME is {home}, entries: {entries[:5]}")
        exit(1)
except PermissionError:
    print("BLOCKED")
    exit(0)
""")
        self.assertIsNotNone(result)
        self.assertEqual(result.return_code, 0,
                         f"Home directory escape not blocked. Output: {result.output}")

    # ─── Import Restriction Tests ────────────────────────────────────────

    def test_socket_import_blocked(self):
        """Agent cannot import socket module."""
        result = self._run_agent_code("""
try:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("ESCAPE: socket imported successfully")
    exit(1)
except ImportError:
    print("BLOCKED: socket import denied")
    exit(0)
""")
        self.assertIsNotNone(result)
        self.assertEqual(result.return_code, 0,
                         f"Socket import was not blocked. Output: {result.output}")

    def test_subprocess_import_blocked(self):
        """Agent cannot import subprocess module."""
        result = self._run_agent_code("""
try:
    import subprocess
    result = subprocess.run(["id"], capture_output=True)
    print(f"ESCAPE: subprocess worked, output: {result.stdout}")
    exit(1)
except ImportError:
    print("BLOCKED: subprocess import denied")
    exit(0)
""")
        self.assertIsNotNone(result)
        self.assertEqual(result.return_code, 0,
                         f"Subprocess import was not blocked. Output: {result.output}")

    def test_http_import_blocked(self):
        """Agent cannot import http/urllib modules."""
        result = self._run_agent_code("""
blocked = 0
for mod in ["http.client", "urllib.request", "requests", "httpx"]:
    try:
        __import__(mod)
        print(f"ESCAPE: {mod} imported successfully")
        exit(1)
    except ImportError:
        blocked += 1
        
print(f"BLOCKED: {blocked}/4 network modules blocked")
exit(0)
""")
        self.assertIsNotNone(result)
        self.assertEqual(result.return_code, 0,
                         f"HTTP module import was not blocked. Output: {result.output}")

    def test_shutil_import_blocked(self):
        """Agent cannot import shutil (prevents bulk host file operations)."""
        result = self._run_agent_code("""
try:
    import shutil
    print("ESCAPE: shutil imported")
    exit(1)
except ImportError:
    print("BLOCKED: shutil import denied")
    exit(0)
""")
        self.assertIsNotNone(result)
        self.assertEqual(result.return_code, 0,
                         f"Shutil import was not blocked. Output: {result.output}")

    def test_ctypes_import_blocked(self):
        """Agent cannot import ctypes (prevents native syscall escape)."""
        result = self._run_agent_code("""
try:
    import ctypes
    print("ESCAPE: ctypes imported")
    exit(1)
except ImportError:
    print("BLOCKED: ctypes import denied")
    exit(0)
""")
        self.assertIsNotNone(result)
        self.assertEqual(result.return_code, 0,
                         f"Ctypes import was not blocked. Output: {result.output}")

    # ─── System Call Tests ───────────────────────────────────────────────

    def test_os_system_blocked(self):
        """Agent cannot use os.system()."""
        result = self._run_agent_code("""
import os
try:
    os.system("echo hacked > /tmp/pwned")
    print("ESCAPE: os.system() worked")
    exit(1)
except PermissionError:
    print("BLOCKED: os.system() denied")
    exit(0)
""")
        self.assertIsNotNone(result)
        self.assertEqual(result.return_code, 0,
                         f"os.system() was not blocked. Output: {result.output}")

    def test_os_exec_blocked(self):
        """Agent cannot use os.exec*() family."""
        result = self._run_agent_code("""
import os
try:
    os.execvp("sh", ["sh", "-c", "echo hacked"])
    print("ESCAPE: os.execvp() worked")
    exit(1)
except PermissionError:
    print("BLOCKED: os.execvp() denied")
    exit(0)
except Exception as e:
    print(f"BLOCKED: {type(e).__name__}: {e}")
    exit(0)
""")
        self.assertIsNotNone(result)
        self.assertEqual(result.return_code, 0,
                         f"os.exec*() was not blocked. Output: {result.output}")

    def test_chdir_escape_blocked(self):
        """Agent cannot chdir outside the sandbox."""
        result = self._run_agent_code("""
import os
try:
    os.chdir("/")
    # If chdir works, it should be the sandbox root, not host root
    cwd = os.getcwd()
    sandbox_root = os.environ.get("SANDBOXOS_ROOT", "")
    if sandbox_root and cwd.startswith(sandbox_root):
        print("CONTAINED: chdir stayed in sandbox")
        exit(0)
    # Check if this is actually the host root
    if os.path.exists("/Applications") or os.path.exists("/boot"):
        print(f"ESCAPE: chdir to host root. cwd={cwd}")
        exit(1)
    print("CONTAINED: restricted filesystem")
    exit(0)
except PermissionError:
    print("BLOCKED: chdir denied")
    exit(0)
""")
        self.assertIsNotNone(result)
        self.assertEqual(result.return_code, 0,
                         f"chdir escape was not blocked. Output: {result.output}")

    # ─── Filesystem Operation Tests ──────────────────────────────────────

    def test_filesystem_path_resolution(self):
        """SandboxFilesystem.resolve() blocks escape paths."""
        escape_paths = [
            "../../../../etc/passwd",
            "/../../etc/passwd",
            "../../../../../../../tmp",
            "~/../../../../etc/shadow",
        ]
        for path in escape_paths:
            try:
                real = self.fs.resolve(path)
                # Even if resolve succeeds, it must stay inside sandbox root
                self.assertTrue(
                    real.startswith(self.fs.root),
                    f"Path '{path}' resolved to '{real}' which is OUTSIDE sandbox root"
                )
            except PermissionError:
                pass  # Correctly blocked

    def test_filesystem_symlink_escape(self):
        """Symlinks pointing outside the sandbox are blocked."""
        # Create a symlink inside sandbox pointing to host /etc
        try:
            link_path = os.path.join(self.fs.root, "tmp", "_test_symlink")
            if os.path.exists(link_path):
                os.remove(link_path)
            os.symlink("/etc/passwd", link_path)

            # Try to resolve it — should be blocked
            try:
                real = self.fs.resolve("/tmp/_test_symlink")
                self.assertTrue(
                    real.startswith(self.fs.root),
                    "Symlink escape: resolved to outside sandbox"
                )
            except PermissionError:
                pass  # Correctly blocked
        finally:
            try:
                os.remove(link_path)
            except OSError:
                pass

    def test_write_outside_sandbox_blocked(self):
        """Agent cannot write files outside the sandbox."""
        result = self._run_agent_code("""
try:
    with open("/tmp/sandboxos_escape_test", "w") as f:
        f.write("escaped")
    print("ESCAPE: wrote to host /tmp")
    exit(1)
except PermissionError:
    print("BLOCKED: write outside sandbox denied")
    exit(0)
except Exception as e:
    print(f"BLOCKED: {e}")
    exit(0)
""")
        self.assertIsNotNone(result)
        # Also verify the file doesn't exist on host
        self.assertFalse(
            os.path.exists("/tmp/sandboxos_escape_test"),
            "Agent wrote a file to host /tmp!"
        )

    # ─── Audit Log Tests ─────────────────────────────────────────────────

    def test_audit_log_records_processes(self):
        """Audit log records process executions."""
        initial_count = len(self.audit.get_events(category="process"))
        self._run_agent_code("print('audit test')")
        final_count = len(self.audit.get_events(category="process"))
        self.assertGreater(final_count, initial_count,
                           "Audit log did not record process execution")


class TestFilesystemOperations(unittest.TestCase):
    """Test basic filesystem operations stay sandboxed."""

    @classmethod
    def setUpClass(cls):
        cls.fs = SandboxFilesystem()

    def test_root_is_within_sandbox(self):
        """Filesystem root is inside ~/.sandboxos."""
        self.assertTrue(self.fs.root.endswith("sandboxos/root"))

    def test_cwd_starts_at_root(self):
        """Initial CWD is /."""
        self.assertEqual(self.fs.cwd, "/")

    def test_mkdir_and_exists(self):
        """Can create and detect directories."""
        self.fs.mkdir("/tmp/_test_dir")
        self.assertTrue(self.fs.exists("/tmp/_test_dir"))
        self.fs.rm("/tmp/_test_dir")

    def test_write_and_read(self):
        """Can write and read files within sandbox."""
        self.fs.write_file("/tmp/_test_file.txt", "hello sandbox\n")
        content = self.fs.cat("/tmp/_test_file.txt")
        self.assertEqual(content, "hello sandbox\n")
        self.fs.rm("/tmp/_test_file.txt")

    def test_cannot_delete_root(self):
        """Cannot delete the sandbox root directory."""
        result = self.fs.rm("/", recursive=True)
        self.assertFalse(result)
        self.assertTrue(os.path.exists(self.fs.root))


if __name__ == "__main__":
    print("\n🛡️  SandboxOS Escape Attempt Test Suite")
    print("━" * 50)
    print()

    unittest.main(verbosity=2)
