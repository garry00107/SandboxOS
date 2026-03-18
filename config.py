"""
SandboxOS — Configuration constants and defaults.
"""

import os


# ─── Paths ───────────────────────────────────────────────────────────────────

# The host directory that becomes the sandbox "disk"
SANDBOX_ROOT = os.path.expanduser("~/.sandboxos")

# Virtual filesystem root inside the sandbox
FS_ROOT = os.path.join(SANDBOX_ROOT, "root")

# ─── Default Directory Structure ─────────────────────────────────────────────

DEFAULT_DIRS = [
    "/home",
    "/home/agent",
    "/home/agent/workspace",
    "/home/agent/scripts",
    "/tmp",
    "/var",
    "/var/log",
    "/etc",
    "/bin",
    "/usr",
    "/usr/local",
    "/usr/local/bin",
]

# ─── Filesystem Limits ───────────────────────────────────────────────────────

MAX_FILE_SIZE = 10 * 1024 * 1024   # 10 MB
MAX_FILES = 10000                   # Maximum number of files in sandbox
MAX_PATH_DEPTH = 50                 # Maximum directory nesting depth
MAX_FILENAME_LENGTH = 255           # Maximum filename length

# ─── Process Manager ─────────────────────────────────────────────────────────

MAX_PROCESS_TIMEOUT = 30            # seconds
MAX_CONCURRENT_PROCESSES = 5
MAX_OUTPUT_SIZE = 1 * 1024 * 1024   # 1 MB output capture limit

# Whitelisted commands that can be executed inside the sandbox
WHITELISTED_COMMANDS = [
    "python3",
    "python",
    "cat",
    "echo",
    "grep",
    "sort",
    "wc",
    "head",
    "tail",
    "awk",
    "sed",
    "tr",
    "cut",
    "uniq",
    "diff",
    "tee",
    "xargs",
    "true",
    "false",
]

# Blocked Python modules (AI agents cannot import these)
BLOCKED_PYTHON_MODULES = [
    "socket",
    "http",
    "urllib",
    "requests",
    "httpx",
    "aiohttp",
    "ftplib",
    "smtplib",
    "imaplib",
    "poplib",
    "telnetlib",
    "xmlrpc",
    "ssl",
    "webbrowser",
    "ctypes",
    "subprocess",  # agents use our API, not raw subprocess
    "shutil",      # prevents bulk host file ops
    "multiprocessing",
    "threading",   # prevents spawning uncontrolled threads
]

# ─── Network ─────────────────────────────────────────────────────────────────

NETWORK_ENABLED = False             # Master switch for network access

# ─── Shell ───────────────────────────────────────────────────────────────────

SHELL_PROMPT_USER = "agent"
SHELL_PROMPT_HOST = "sandboxos"
SHELL_HISTORY_SIZE = 1000
DEFAULT_HOME = "/home/agent"

# ─── OS Info ─────────────────────────────────────────────────────────────────

OS_NAME = "SandboxOS"
OS_VERSION = "1.1.0"
OS_CODENAME = "Ironclad"
OS_KERNEL = "sandbox-kernel 1.1.0"
OS_ARCH = "virtual/amd64"

# ─── Colors / Theme ─────────────────────────────────────────────────────────

THEME = {
    "primary": "\033[38;5;39m",       # Bright blue
    "secondary": "\033[38;5;208m",    # Orange
    "accent": "\033[38;5;156m",       # Light green
    "danger": "\033[38;5;196m",       # Red
    "warning": "\033[38;5;220m",      # Yellow
    "muted": "\033[38;5;240m",        # Dark gray
    "success": "\033[38;5;82m",       # Green
    "reset": "\033[0m",
}
