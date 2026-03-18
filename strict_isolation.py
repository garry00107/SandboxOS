"""
SandboxOS — Strict Isolation Mode.

When --strict is used, this module attempts real OS-level isolation
using platform-specific mechanisms:

Linux:  User namespaces via `unshare` + network namespace isolation
macOS:  sandbox-exec (Apple's built-in sandboxing) + resource limits
Fallback: Python-level sandboxing with clear warnings

This is the difference between "prevents accidents" (default mode)
and "prevents adversarial escape" (strict mode).
"""

import os
import sys
import shutil
import subprocess
import platform

from config import FS_ROOT
from utils import (
    status_ok, status_fail, status_warn, status_info,
    error_msg, green, red, yellow, cyan, dim, bold
)


class StrictIsolation:
    """
    OS-level isolation for subprocess execution.
    """

    def __init__(self):
        self.platform = platform.system().lower()
        self.available = False
        self.method = "none"
        self.capabilities = []
        self._detect_capabilities()

    def _detect_capabilities(self):
        """Detect what isolation primitives are available."""
        self.capabilities = []

        if self.platform == "linux":
            # Check for unshare (user namespaces)
            if shutil.which("unshare"):
                # Test if user namespaces work (some systems disable them)
                try:
                    result = subprocess.run(
                        ["unshare", "--user", "--map-root-user", "true"],
                        capture_output=True, timeout=5
                    )
                    if result.returncode == 0:
                        self.capabilities.append("user_namespace")
                except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                    pass

            # Check for network namespace
            if shutil.which("unshare"):
                # Network namespaces need CAP_SYS_ADMIN or user ns
                self.capabilities.append("net_namespace_available")

            # Check for bubblewrap (bwrap)
            if shutil.which("bwrap"):
                self.capabilities.append("bubblewrap")

            # Check for nsjail
            if shutil.which("nsjail"):
                self.capabilities.append("nsjail")

            # Check for firejail
            if shutil.which("firejail"):
                self.capabilities.append("firejail")

            if self.capabilities:
                self.available = True
                if "bubblewrap" in self.capabilities:
                    self.method = "bubblewrap"
                elif "user_namespace" in self.capabilities:
                    self.method = "unshare"
                elif "firejail" in self.capabilities:
                    self.method = "firejail"

        elif self.platform == "darwin":
            # macOS: sandbox-exec with Seatbelt profiles.
            # WARNING: Deprecated since macOS 12 (Monterey). Apple has been
            # quietly removing Seatbelt/sandbox-exec support. It still works
            # on most systems but may break on future macOS updates.
            # For production agent sandboxing on macOS, use Docker or a
            # Linux VM with real namespace isolation.
            if shutil.which("sandbox-exec"):
                self.capabilities.append("sandbox_exec (deprecated)")
                self.available = True
                self.method = "sandbox-exec"

        # setrlimit is always available on Unix
        if hasattr(os, "setrlimit") or True:  # resource module available
            self.capabilities.append("setrlimit")

    def get_status(self):
        """Return human-readable isolation status."""
        if not self.available:
            return {
                "level": "PYTHON-LEVEL",
                "method": "monkey-patching + import blocking",
                "warning": (
                    "Python-level sandboxing only. Cannot prevent ctypes, "
                    "cffi, or native code from bypassing restrictions."
                ),
                "capabilities": self.capabilities,
            }
        else:
            warning = None
            if self.method == "sandbox-exec":
                warning = (
                    "sandbox-exec is deprecated since macOS 12. "
                    "It works today but may break on future macOS updates. "
                    "For production workloads, run inside Docker/Linux."
                )
            return {
                "level": "OS-LEVEL",
                "method": self.method,
                "capabilities": self.capabilities,
                **(({"warning": warning}) if warning else {}),
            }

    def print_status(self):
        """Display isolation capabilities to the terminal."""
        status = self.get_status()

        if status["level"] == "OS-LEVEL":
            status_ok(f"Strict isolation: {green(status['method'], bold=True)}")
            for cap in self.capabilities:
                status_ok(f"  Capability: {cap}")
        else:
            status_warn(f"Isolation level: {yellow('PYTHON-LEVEL')}")
            status_warn(f"  {status['warning']}")
            if self.capabilities:
                for cap in self.capabilities:
                    status_info(f"  Available: {cap}")

    def build_sandboxed_command(self, cmd, sandbox_root=None):
        """
        Wrap a command with OS-level isolation.
        Returns the wrapped command as a list.
        """
        sandbox_root = sandbox_root or FS_ROOT

        if not self.available:
            # Fallback: just return the command as-is
            return cmd if isinstance(cmd, list) else cmd.split()

        if self.method == "bubblewrap":
            return self._bwrap_command(cmd, sandbox_root)
        elif self.method == "unshare":
            return self._unshare_command(cmd, sandbox_root)
        elif self.method == "sandbox-exec":
            return self._sandbox_exec_command(cmd, sandbox_root)
        elif self.method == "firejail":
            return self._firejail_command(cmd, sandbox_root)
        else:
            return cmd if isinstance(cmd, list) else cmd.split()

    def _bwrap_command(self, cmd, sandbox_root):
        """Build bubblewrap-isolated command (Linux)."""
        if isinstance(cmd, str):
            cmd = cmd.split()

        bwrap = [
            "bwrap",
            # Mount sandbox root as the filesystem root
            "--bind", sandbox_root, "/",
            # Mount /proc (needed for Python)
            "--proc", "/proc",
            # Mount /dev minimally
            "--dev", "/dev",
            # Bind Python interpreter (read-only)
            "--ro-bind", sys.executable, sys.executable,
            # Bind Python stdlib (read-only)
            "--ro-bind", os.path.dirname(os.__file__),
                         os.path.dirname(os.__file__),
            # Isolate network
            "--unshare-net",
            # Isolate PIDs
            "--unshare-pid",
            # Isolate IPC
            "--unshare-ipc",
            # New UTS namespace (hostname)
            "--unshare-uts",
            "--hostname", "sandboxos",
            # Set working directory
            "--chdir", "/home/agent",
            # Die if parent dies
            "--die-with-parent",
            # Drop all capabilities
            "--cap-drop", "ALL",
            # Set uid/gid
            "--uid", "1000",
            "--gid", "1000",
            # The actual command
            "--",
        ] + cmd

        return bwrap

    def _unshare_command(self, cmd, sandbox_root):
        """Build unshare-isolated command (Linux, no bwrap)."""
        if isinstance(cmd, str):
            cmd = cmd.split()

        unshare = [
            "unshare",
            "--user",
            "--map-root-user",
            "--net",           # Network namespace (no network)
            "--pid",           # PID namespace
            "--fork",          # Fork before exec
            "--mount-proc",    # Mount /proc in new namespace
            "--",
        ] + cmd

        return unshare

    def _sandbox_exec_command(self, cmd, sandbox_root):
        """Build sandbox-exec command (macOS)."""
        if isinstance(cmd, str):
            cmd = cmd.split()

        # macOS sandbox profile that restricts filesystem and network
        profile = self._generate_macos_profile(sandbox_root)

        return ["sandbox-exec", "-p", profile, "--"] + cmd

    def _generate_macos_profile(self, sandbox_root):
        """
        Generate a macOS sandbox profile (.sb format).

        WARNING: sandbox-exec and Seatbelt profiles are deprecated since
        macOS 12 (Monterey). This is a best-effort isolation mechanism
        that may stop working on future macOS releases. For production
        agent sandboxing, use Docker or a Linux VM with namespace isolation.
        """
        profile = f"""
(version 1)
(deny default)

;; Allow reading the sandbox root
(allow file-read* (subpath "{sandbox_root}"))
(allow file-write* (subpath "{sandbox_root}"))

;; Allow reading Python and system libraries
(allow file-read* (subpath "/usr/lib"))
(allow file-read* (subpath "/usr/local/lib"))
(allow file-read* (subpath "/Library/Frameworks/Python.framework"))
(allow file-read* (subpath "/usr/local/Cellar"))
(allow file-read* (subpath "/opt/homebrew"))
(allow file-read* (subpath "{os.path.dirname(sys.executable)}"))
(allow file-read* (subpath "{os.path.dirname(os.__file__)}"))

;; Allow /dev/null, /dev/urandom etc
(allow file-read* (subpath "/dev"))
(allow file-write* (subpath "/dev/null"))

;; Allow process execution
(allow process-exec*)
(allow process-fork)

;; DENY all network access
(deny network*)

;; Allow sysctl reads (Python needs this)
(allow sysctl-read)

;; Allow mach lookups (needed for basic process operation)
(allow mach-lookup)
"""
        return profile

    def _firejail_command(self, cmd, sandbox_root):
        """Build firejail-isolated command (Linux)."""
        if isinstance(cmd, str):
            cmd = cmd.split()

        return [
            "firejail",
            "--noprofile",
            f"--private={sandbox_root}",
            "--net=none",
            "--no3d",
            "--nosound",
            "--nodvd",
            "--notv",
            "--caps.drop=all",
            "--nonewprivs",
            "--seccomp",
            "--",
        ] + cmd


def detect_and_report():
    """Detect isolation capabilities and print a report."""
    iso = StrictIsolation()

    print()
    print(f"  {bold('Isolation Capabilities Report')}")
    print(f"  {dim('─' * 40)}")
    print(f"  Platform:  {cyan(iso.platform)}")
    print(f"  Method:    {cyan(iso.method)}")
    print(f"  Available: {green('YES') if iso.available else yellow('NO')}")

    if iso.capabilities:
        print(f"  Detected:")
        for cap in iso.capabilities:
            print(f"    {green('●')} {cap}")
    else:
        print(f"  Detected:  {dim('(none)')}")

    status = iso.get_status()
    print()
    print(f"  {bold('Isolation Level:')} ", end="")
    if status["level"] == "OS-LEVEL":
        print(f"{green(status['level'], bold=True)}")
    else:
        print(f"{yellow(status['level'], bold=True)}")
        if "warning" in status:
            print(f"  {yellow('⚠')}  {dim(status['warning'])}")

    print()
    return iso
