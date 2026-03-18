"""
SandboxOS — Process Manager.

Manages execution of scripts and commands within the sandbox.
Restricts what can be run, enforces timeouts, and tracks processes.
Now with kernel-enforced resource limits and OS-level isolation support.
"""

import os
import sys
import time
import signal
import subprocess
import threading

from config import (
    FS_ROOT, WHITELISTED_COMMANDS, BLOCKED_PYTHON_MODULES,
    MAX_PROCESS_TIMEOUT, MAX_CONCURRENT_PROCESSES, MAX_OUTPUT_SIZE
)
from utils import error_msg, sandbox_violation, green, red, yellow, dim
from resource_quotas import get_quota_preexec


class SandboxProcess:
    """Represents a tracked process inside the sandbox."""

    def __init__(self, pid, command, start_time):
        self.pid = pid
        self.command = command
        self.start_time = start_time
        self.end_time = None
        self.status = "running"
        self.return_code = None
        self.output = ""
        self.error = ""


class ProcessManager:
    """
    Manages subprocess execution within the sandbox environment.
    Now with kernel-enforced resource limits and audit logging.
    """

    def __init__(self, filesystem, audit=None, strict_isolation=None):
        self.filesystem = filesystem
        self.audit = audit
        self.strict = strict_isolation
        self.processes = {}
        self._next_pid = 1000
        self._lock = threading.Lock()

    def _get_restricted_env(self):
        """Build a restricted environment for subprocess execution."""
        env = {
            "HOME": os.path.join(FS_ROOT, "home", "agent"),
            "USER": "agent",
            "LOGNAME": "agent",
            "SHELL": "/bin/sh",
            "TERM": "xterm-256color",
            "LANG": "en_US.UTF-8",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "TMPDIR": os.path.join(FS_ROOT, "tmp"),
            "SANDBOXOS": "1",
            "SANDBOXOS_ROOT": FS_ROOT,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        return env

    def _generate_import_blocker(self):
        """Generate Python code that blocks importing restricted modules."""
        blocked = ", ".join(f'"{m}"' for m in BLOCKED_PYTHON_MODULES)
        return f'''
import builtins
_original_import = builtins.__import__
_blocked_modules = [{blocked}]

def _sandboxed_import(name, *args, **kwargs):
    for blocked in _blocked_modules:
        if name == blocked or name.startswith(blocked + "."):
            raise ImportError(
                f"🛡️  SandboxOS: import '{{name}}' is BLOCKED. "
                f"This module is restricted in the sandbox environment."
            )
    return _original_import(name, *args, **kwargs)

builtins.__import__ = _sandboxed_import

# Also block os.system and os.exec*
import os as _os
def _blocked_system(cmd):
    raise PermissionError("🛡️  SandboxOS: os.system() is BLOCKED.")
_os.system = _blocked_system

for _fn_name in ["execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe"]:
    if hasattr(_os, _fn_name):
        setattr(_os, _fn_name, lambda *a, **k: (_ for _ in ()).throw(
            PermissionError(f"🛡️  SandboxOS: os.{{_fn_name}}() is BLOCKED.")))

# Block os.chdir to outside sandbox
_original_chdir = _os.chdir
def _sandboxed_chdir(path):
    real = _os.path.realpath(path)
    sandbox_root = _os.environ.get("SANDBOXOS_ROOT", "")
    if sandbox_root and not real.startswith(sandbox_root):
        raise PermissionError("🛡️  SandboxOS: Cannot chdir outside sandbox.")
    return _original_chdir(path)
_os.chdir = _sandboxed_chdir

# Block open() outside sandbox
_original_open = builtins.open
def _sandboxed_open(file, *args, **kwargs):
    if isinstance(file, str):
        real = _os.path.realpath(file)
        sandbox_root = _os.environ.get("SANDBOXOS_ROOT", "")
        if sandbox_root and not real.startswith(sandbox_root):
            raise PermissionError(f"🛡️  SandboxOS: Cannot access '{{file}}' — outside sandbox.")
    return _original_open(file, *args, **kwargs)
builtins.open = _sandboxed_open
'''

    def is_whitelisted(self, command):
        """Check if a command is in the whitelist."""
        base_cmd = os.path.basename(command.split()[0]) if command else ""
        return base_cmd in WHITELISTED_COMMANDS

    def run_python_script(self, virtual_path, args=None, timeout=None):
        """
        Run a Python script within the sandbox with import restrictions.
        """
        timeout = timeout or MAX_PROCESS_TIMEOUT

        # Resolve the script path
        try:
            real_path = self.filesystem.resolve(virtual_path)
        except PermissionError as e:
            sandbox_violation(str(e))
            return None

        if not os.path.exists(real_path):
            error_msg(f"'{virtual_path}': No such file")
            return None

        if not real_path.endswith(".py"):
            error_msg(f"'{virtual_path}': Not a Python file")
            return None

        # Check concurrent process limit
        running = sum(1 for p in self.processes.values() if p.status == "running")
        if running >= MAX_CONCURRENT_PROCESSES:
            error_msg(f"Too many concurrent processes (max {MAX_CONCURRENT_PROCESSES})")
            return None

        # Build the command with import blocker
        blocker_code = self._generate_import_blocker()
        wrapper = f'{blocker_code}\n\nexec(open("{real_path}").read())\n'

        # Write wrapper to temp file
        wrapper_path = os.path.join(FS_ROOT, "tmp", f"_sandbox_run_{self._next_pid}.py")
        with open(wrapper_path, "w") as f:
            f.write(wrapper)

        env = self._get_restricted_env()
        env["PYTHONPATH"] = FS_ROOT

        # Track the process
        pid = self._next_pid
        self._next_pid += 1
        proc_info = SandboxProcess(pid, f"python3 {virtual_path}", time.time())

        cmd = [sys.executable, wrapper_path]
        if args:
            cmd.extend(args)

        # Apply strict OS-level isolation if available
        if self.strict and self.strict.available:
            cmd = self.strict.build_sandboxed_command(cmd)

        # Kernel-enforced resource limits via setrlimit
        preexec = get_quota_preexec()

        # Audit log
        if self.audit:
            self.audit.process_exec(f"python3 {virtual_path}", pid=pid)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                cwd=os.path.join(FS_ROOT, "home", "agent"),
                preexec_fn=preexec,
            )

            proc_info.output = result.stdout[:MAX_OUTPUT_SIZE]
            proc_info.error = result.stderr[:MAX_OUTPUT_SIZE]
            proc_info.return_code = result.returncode
            proc_info.status = "completed"
            proc_info.end_time = time.time()

        except subprocess.TimeoutExpired:
            proc_info.status = "killed (timeout)"
            proc_info.error = f"Process killed: exceeded {timeout}s timeout"
            proc_info.end_time = time.time()

        except Exception as e:
            proc_info.status = "error"
            proc_info.error = str(e)
            proc_info.end_time = time.time()

        finally:
            # Clean up wrapper
            try:
                os.remove(wrapper_path)
            except OSError:
                pass

        with self._lock:
            self.processes[pid] = proc_info

        return proc_info

    def run_command(self, command, timeout=None):
        """
        Run a whitelisted shell command within the sandbox.
        """
        timeout = timeout or MAX_PROCESS_TIMEOUT

        if not command.strip():
            return None

        parts = command.strip().split()
        base_cmd = parts[0]

        if not self.is_whitelisted(base_cmd):
            error_msg(f"'{base_cmd}': Command not allowed in sandbox")
            return None

        # Check concurrent process limit
        running = sum(1 for p in self.processes.values() if p.status == "running")
        if running >= MAX_CONCURRENT_PROCESSES:
            error_msg(f"Too many concurrent processes (max {MAX_CONCURRENT_PROCESSES})")
            return None

        env = self._get_restricted_env()

        pid = self._next_pid
        self._next_pid += 1
        proc_info = SandboxProcess(pid, command, time.time())

        try:
            # Resolve any file arguments to real paths
            resolved_parts = [base_cmd]
            for arg in parts[1:]:
                if not arg.startswith("-"):
                    try:
                        real = self.filesystem.resolve(arg)
                        resolved_parts.append(real)
                    except PermissionError:
                        sandbox_violation(f"Cannot access '{arg}'")
                        proc_info.status = "blocked"
                        proc_info.error = f"Path '{arg}' escapes sandbox"
                        proc_info.end_time = time.time()
                        with self._lock:
                            self.processes[pid] = proc_info
                        return proc_info
                else:
                    resolved_parts.append(arg)

            # Kernel-enforced resource limits
            preexec = get_quota_preexec()

            # Audit log
            if self.audit:
                self.audit.process_exec(command, pid=pid)

            result = subprocess.run(
                resolved_parts,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                cwd=os.path.join(FS_ROOT, "home", "agent"),
                preexec_fn=preexec,
            )

            proc_info.output = result.stdout[:MAX_OUTPUT_SIZE]
            proc_info.error = result.stderr[:MAX_OUTPUT_SIZE]
            proc_info.return_code = result.returncode
            proc_info.status = "completed"
            proc_info.end_time = time.time()

        except subprocess.TimeoutExpired:
            proc_info.status = "killed (timeout)"
            proc_info.error = f"Process killed: exceeded {timeout}s timeout"
            proc_info.end_time = time.time()

        except FileNotFoundError:
            proc_info.status = "error"
            proc_info.error = f"Command not found: {base_cmd}"
            proc_info.end_time = time.time()

        except Exception as e:
            proc_info.status = "error"
            proc_info.error = str(e)
            proc_info.end_time = time.time()

        with self._lock:
            self.processes[pid] = proc_info

        return proc_info

    def list_processes(self):
        """Return list of all tracked processes."""
        return list(self.processes.values())

    def kill_process(self, pid):
        """Kill a running process by PID."""
        if pid not in self.processes:
            error_msg(f"No process with PID {pid}")
            return False

        proc = self.processes[pid]
        if proc.status != "running":
            error_msg(f"Process {pid} is not running (status: {proc.status})")
            return False

        proc.status = "killed"
        proc.end_time = time.time()
        return True

    def get_process(self, pid):
        """Get a process by PID."""
        return self.processes.get(pid)
