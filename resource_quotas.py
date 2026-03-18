"""
SandboxOS — Resource Quotas.

Enforces memory, CPU time, file size, and process limits on child
processes using os.setrlimit(). These are real kernel-enforced limits
that cannot be bypassed from Python userspace.
"""

import os
import sys
import resource


# Default resource limits for agent processes
DEFAULT_QUOTAS = {
    # Max virtual memory per process (256 MB)
    "memory_mb": 256,

    # Max CPU time in seconds (30s)
    "cpu_time_s": 30,

    # Max file size a process can create (10 MB)
    "max_file_size_mb": 10,

    # Max number of open file descriptors (64)
    "max_open_files": 64,

    # Max number of child processes.
    # Set to 0 to completely block forking. This prevents:
    #   - Fork bombs (agent spawning infinite processes)
    #   - os.fork() + os.execve() escape (launching arbitrary binaries)
    #   - multiprocessing module abuse
    # Note: The parent process (SandboxOS) is already running when this
    # limit is applied via preexec_fn, so it only affects the child.
    # The child Python interpreter starts first (before setrlimit runs
    # in preexec_fn), then these limits constrain it.
    # On macOS, RLIMIT_NPROC may not be available — we catch this gracefully.
    "max_processes": 0,

    # Max stack size (8 MB)
    "stack_size_mb": 8,
}


def get_quota_preexec(quotas=None):
    """
    Return a preexec_fn for subprocess.Popen/run that applies
    resource limits before the child process executes.

    These limits are enforced by the kernel — they cannot be
    bypassed by ctypes, cffi, or any Python-level trick.

    Usage:
        subprocess.run(cmd, preexec_fn=get_quota_preexec())
    """
    q = {**DEFAULT_QUOTAS, **(quotas or {})}

    def apply_limits():
        """Applied in the child process before exec."""

        # ─── CPU time limit ──────────────────────────────────────────
        # Kernel sends SIGXCPU then SIGKILL when exceeded
        cpu_soft = q["cpu_time_s"]
        cpu_hard = q["cpu_time_s"] + 5  # 5s grace for cleanup
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_soft, cpu_hard))
        except (ValueError, OSError):
            pass

        # ─── Virtual memory limit ────────────────────────────────────
        # Prevents memory bomb attacks
        mem_bytes = q["memory_mb"] * 1024 * 1024
        try:
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        except (ValueError, OSError):
            pass

        # ─── Max file size ───────────────────────────────────────────
        # Prevents disk-filling attacks
        file_bytes = q["max_file_size_mb"] * 1024 * 1024
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
        except (ValueError, OSError):
            pass

        # ─── Max open files ──────────────────────────────────────────
        # Prevents file descriptor exhaustion
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE,
                               (q["max_open_files"], q["max_open_files"]))
        except (ValueError, OSError):
            pass

        # ─── Max child processes ─────────────────────────────────────
        # 0 = no forking (prevents fork bombs and process escape)
        try:
            resource.setrlimit(resource.RLIMIT_NPROC,
                               (q["max_processes"], q["max_processes"]))
        except (ValueError, OSError, AttributeError):
            # RLIMIT_NPROC not available on all platforms
            pass

        # ─── Stack size ──────────────────────────────────────────────
        stack_bytes = q["stack_size_mb"] * 1024 * 1024
        try:
            resource.setrlimit(resource.RLIMIT_STACK, (stack_bytes, stack_bytes))
        except (ValueError, OSError):
            pass

    return apply_limits


def get_current_usage():
    """
    Get current resource usage of this process.
    Returns a dict with human-readable values.
    """
    usage = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)

    return {
        "self": {
            "user_time": f"{usage.ru_utime:.3f}s",
            "system_time": f"{usage.ru_stime:.3f}s",
            "max_rss_mb": f"{usage.ru_maxrss / 1024:.1f}MB" if sys.platform == "linux"
                          else f"{usage.ru_maxrss / (1024 * 1024):.1f}MB",
            "page_faults": usage.ru_majflt,
            "block_reads": usage.ru_inblock,
            "block_writes": usage.ru_oublock,
            "voluntary_ctx_switches": usage.ru_nvcsw,
            "involuntary_ctx_switches": usage.ru_nivcsw,
        },
        "children": {
            "user_time": f"{children.ru_utime:.3f}s",
            "system_time": f"{children.ru_stime:.3f}s",
            "max_rss_mb": f"{children.ru_maxrss / 1024:.1f}MB" if sys.platform == "linux"
                          else f"{children.ru_maxrss / (1024 * 1024):.1f}MB",
        },
    }


def get_limits_display():
    """
    Get current resource limits as a display-friendly dict.
    """
    limit_map = {
        "CPU Time": resource.RLIMIT_CPU,
        "Virtual Memory": resource.RLIMIT_AS,
        "File Size": resource.RLIMIT_FSIZE,
        "Open Files": resource.RLIMIT_NOFILE,
        "Stack Size": resource.RLIMIT_STACK,
    }

    # NPROC not on all platforms
    if hasattr(resource, "RLIMIT_NPROC"):
        limit_map["Processes"] = resource.RLIMIT_NPROC

    results = {}
    for name, rlimit in limit_map.items():
        try:
            soft, hard = resource.getrlimit(rlimit)
            if soft == resource.RLIM_INFINITY:
                results[name] = "unlimited"
            elif "Memory" in name or "File" in name or "Stack" in name:
                results[name] = f"{soft / (1024 * 1024):.0f}MB"
            elif "Time" in name:
                results[name] = f"{soft}s"
            else:
                results[name] = str(soft)
        except (ValueError, OSError):
            results[name] = "N/A"

    return results


def format_quotas(quotas=None):
    """Format quota settings for display."""
    q = {**DEFAULT_QUOTAS, **(quotas or {})}
    return {
        "CPU Time": f"{q['cpu_time_s']}s",
        "Memory": f"{q['memory_mb']}MB",
        "Max File Size": f"{q['max_file_size_mb']}MB",
        "Open Files": str(q['max_open_files']),
        "Child Processes": str(q['max_processes']),
        "Stack Size": f"{q['stack_size_mb']}MB",
    }
