"""
SandboxOS — Audit Log.

Records every filesystem operation, process launch, network attempt,
and security violation with timestamps. This is the ground truth
for what happened inside the sandbox — table stakes for any
security boundary.
"""

import os
import time
import json
import datetime
import threading

from config import FS_ROOT


class AuditEvent:
    """Single audit log entry."""

    __slots__ = ("timestamp", "category", "action", "target", "result", "detail", "pid")

    def __init__(self, category, action, target="", result="ok", detail="", pid=None):
        self.timestamp = datetime.datetime.now().isoformat()
        self.category = category       # fs, process, network, security, agent, shell
        self.action = action           # read, write, delete, mkdir, exec, import, connect, etc.
        self.target = target           # path, command, module name, URL, etc.
        self.result = result           # ok, blocked, error
        self.detail = detail           # extra context
        self.pid = pid                 # process id if relevant

    def to_dict(self):
        d = {
            "ts": self.timestamp,
            "cat": self.category,
            "act": self.action,
            "tgt": self.target,
            "res": self.result,
        }
        if self.detail:
            d["det"] = self.detail
        if self.pid is not None:
            d["pid"] = self.pid
        return d

    def to_line(self):
        """Format as a single human-readable log line."""
        icon = {
            "ok": "✓",
            "blocked": "✗",
            "error": "!",
        }.get(self.result, "?")

        pid_str = f" [PID {self.pid}]" if self.pid else ""
        detail_str = f" — {self.detail}" if self.detail else ""
        return (
            f"[{self.timestamp}] {icon} "
            f"{self.category}/{self.action}: {self.target}"
            f"{pid_str}{detail_str}"
        )


class AuditLog:
    """
    Thread-safe audit log for SandboxOS.
    Stores events in memory and persists to disk.
    """

    def __init__(self, log_dir=None):
        self._events = []
        self._lock = threading.Lock()
        self._log_dir = log_dir or os.path.join(FS_ROOT, "var", "log")
        self._log_file = os.path.join(self._log_dir, "audit.log")
        self._json_file = os.path.join(self._log_dir, "audit.json")
        self._counters = {
            "fs_read": 0,
            "fs_write": 0,
            "fs_delete": 0,
            "process_exec": 0,
            "network_blocked": 0,
            "security_violation": 0,
            "agent_run": 0,
        }
        os.makedirs(self._log_dir, exist_ok=True)

    def log(self, category, action, target="", result="ok", detail="", pid=None):
        """Record an audit event."""
        event = AuditEvent(category, action, target, result, detail, pid)

        with self._lock:
            self._events.append(event)

            # Update counters
            key = f"{category}_{action}"
            if key in self._counters:
                self._counters[key] += 1
            elif result == "blocked":
                if category == "network":
                    self._counters["network_blocked"] += 1
                elif category == "security":
                    self._counters["security_violation"] += 1

            # Persist to disk (append)
            try:
                with open(self._log_file, "a") as f:
                    f.write(event.to_line() + "\n")
            except OSError:
                pass

        return event

    # ─── Convenience Methods ─────────────────────────────────────────────

    def fs_read(self, path, result="ok", detail=""):
        return self.log("fs", "read", path, result, detail)

    def fs_write(self, path, result="ok", detail=""):
        return self.log("fs", "write", path, result, detail)

    def fs_delete(self, path, result="ok", detail=""):
        return self.log("fs", "delete", path, result, detail)

    def fs_mkdir(self, path, result="ok", detail=""):
        return self.log("fs", "mkdir", path, result, detail)

    def fs_listdir(self, path, result="ok"):
        return self.log("fs", "listdir", path, result)

    def fs_chmod(self, path, mode, result="ok"):
        return self.log("fs", "chmod", path, result, f"mode={mode}")

    def process_exec(self, command, pid=None, result="ok", detail=""):
        return self.log("process", "exec", command, result, detail, pid)

    def process_kill(self, pid, result="ok"):
        return self.log("process", "kill", str(pid), result)

    def network_attempt(self, target, result="blocked", detail=""):
        return self.log("network", "connect", target, result, detail)

    def security_violation(self, action, target, detail=""):
        return self.log("security", action, target, "blocked", detail)

    def agent_start(self, name, script, pid=None):
        return self.log("agent", "run", script, "ok", f"name={name}", pid)

    def agent_complete(self, name, exit_code, elapsed):
        result = "ok" if exit_code == 0 else "error"
        return self.log("agent", "complete", name, result,
                        f"exit={exit_code} elapsed={elapsed:.2f}s")

    def import_blocked(self, module_name, pid=None):
        return self.log("security", "import", module_name, "blocked",
                        "restricted module", pid)

    def path_escape(self, path, detail=""):
        return self.log("security", "path_escape", path, "blocked", detail)

    def shell_command(self, command):
        return self.log("shell", "command", command, "ok")

    # ─── Query & Display ─────────────────────────────────────────────────

    def get_events(self, category=None, result=None, last_n=None):
        """Query events with optional filters."""
        with self._lock:
            events = list(self._events)

        if category:
            events = [e for e in events if e.category == category]
        if result:
            events = [e for e in events if e.result == result]
        if last_n:
            events = events[-last_n:]

        return events

    def get_counters(self):
        """Return event counters."""
        with self._lock:
            return dict(self._counters)

    def get_security_events(self, last_n=50):
        """Get all security violations and blocked attempts."""
        return self.get_events(result="blocked", last_n=last_n)

    def get_summary(self):
        """Get a summary dict of all audit activity."""
        with self._lock:
            total = len(self._events)
            blocked = sum(1 for e in self._events if e.result == "blocked")
            categories = {}
            for e in self._events:
                categories[e.category] = categories.get(e.category, 0) + 1

        return {
            "total_events": total,
            "blocked_events": blocked,
            "categories": categories,
            "counters": self.get_counters(),
        }

    def export_json(self):
        """Export full audit log as JSON to the sandbox."""
        with self._lock:
            data = [e.to_dict() for e in self._events]

        try:
            with open(self._json_file, "w") as f:
                json.dump(data, f, indent=2)
            return self._json_file
        except OSError:
            return None

    def clear(self):
        """Clear all events (for testing)."""
        with self._lock:
            self._events.clear()
            for key in self._counters:
                self._counters[key] = 0
