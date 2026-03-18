# SandboxOS

Sandboxed terminal OS for running AI agents safely. Zero dependencies — Python stdlib only.

```bash
python3 main.py
```

## Security Model

Be honest about what each layer protects against:

| Layer | Mechanism | Protects Against | Bypassable? |
|-------|-----------|-----------------|-------------|
| **Filesystem** | `realpath()` + prefix check | `../` traversal, symlink escape | No (within Python) |
| **Network** | Monkey-patches `socket`, `urllib`, `requests` | Accidental HTTP/data exfiltration | Yes — via `ctypes`/libc |
| **Imports** | `builtins.__import__` hook blocks 19 modules | `subprocess`, `shutil`, `ctypes`, etc. | Yes — via compiled extensions |
| **System Calls** | `os.system()`, `os.exec*()`, `open()` patched | Shell escape, arbitrary binaries | Yes — via native code |
| **Resource Quotas** | Kernel `setrlimit()` — CPU, mem, fds, forks | Fork bombs, memory bombs, disk fill | **No** — kernel-enforced |
| **Strict Mode** | `bubblewrap`/`unshare` (Linux), `sandbox-exec` (macOS) | Adversarial escape via native code | Significantly harder |

**Default mode** prevents accidents. **Strict mode** (`--strict`) provides OS-level isolation.

> **⚠️ macOS:** `sandbox-exec` is deprecated since macOS 12. For production, use Docker or Linux.

## Quick Start

```bash
python3 main.py              # Full boot
python3 main.py --no-boot    # Skip animation
python3 main.py --strict     # OS-level isolation
python3 main.py --reset      # Wipe sandbox
python3 main.py --allow-net  # Enable network (use with caution)
```

## AI Agent (Gemini Flash 2.0)

SandboxOS includes a built-in AI coding agent powered by Google Gemini. The agent can create files, run Python scripts, and iterate on code — all sandboxed.

```bash
# Install the dependency
pip install google-genai

# Set your API key (free at https://aistudio.google.com/apikey)
export GEMINI_API_KEY=your_key_here

# Inside SandboxOS:
agent chat
```

The agent has 6 tools: `read_file`, `write_file`, `create_directory`, `list_directory`, `run_python`, `delete_file`. All operations go through the sandboxed filesystem — the agent cannot touch the host system. Scripts it writes and runs are subject to the full security stack: import blocking, setrlimit quotas, and audit logging.

**Example task:** *"Create a calculator module with add, subtract, multiply, divide. Write unit tests. Run them and fix any failures."*


1. **Path containment** — all file operations resolve to the sandbox root, `../` traversal is caught
2. **Import blocking** — 19 dangerous Python modules are intercepted at import time
3. **Network isolation** — `socket`, `urllib`, `http.client`, `requests`, `httpx`, `aiohttp` monkey-patched
4. **Resource quotas** — kernel-enforced CPU (30s), memory (256MB), fds (64), forks (0), file size (10MB)
5. **Audit logging** — every command, process launch, and security violation is recorded

```bash
# Inside SandboxOS:
agent example                                        # Create example agent
agent run /home/agent/scripts/example_agent.py       # Run it
security                                             # View security status
quotas                                               # View resource limits
audit summary                                        # View audit log
```

## Limitations

- **Python-level sandboxing is not adversarial-proof.** `ctypes`, `cffi`, and compiled C extensions can bypass monkey-patched modules and import hooks. This is inherent to running code in the same Python process.
- **Strict mode requires Linux for meaningful OS-level isolation.** On macOS, `sandbox-exec` is deprecated (since macOS 12) and the fallback is Python-level only. For production agent workloads, run inside a Linux container.
- **`--strict` mode is the answer** — bubblewrap/unshare on Linux provide real namespace + seccomp isolation.
- **`RLIMIT_NPROC=0`** blocks all forking. Agent scripts that legitimately need multiprocessing won't work (by design).

## Running Tests

```bash
python3 tests/test_escape.py            # 20 escape-attempt tests, ~0.3s
python3 -m pytest tests/test_escape.py -v
```

Tests cover: path traversal (3), import restrictions (5 — socket, subprocess, http, shutil, ctypes), system call blocking (3 — os.system, os.exec, chdir), filesystem escape (3 — symlinks, writes, path resolution), audit logging (1), and filesystem ops (5).

## Shell Commands

| Category | Commands |
|----------|----------|
| **Files** | `ls` `cd` `pwd` `cat` `head` `tail` `touch` `mkdir` `rm` `cp` `mv` `tree` `find` `wc` `chmod` `stat` `write` `grep` |
| **System** | `echo` `clear` `env` `export` `whoami` `hostname` `uname` `date` `neofetch` `df` `du` `which` |
| **Process** | `ps` `kill` `exec` |
| **Agent** | `agent run` `agent list` `agent log` `agent example` `agent output` |
| **Security** | `security` `quotas` `audit` |

Supports pipes (`|`), redirection (`>`, `>>`), `$VAR` expansion, tab completion, history.

## Resource Quotas

Applied to every child process via `setrlimit()` — kernel-enforced, not bypassable:

| Resource | Limit | Purpose |
|----------|-------|---------|
| CPU Time | 30s + 5s grace | Prevents infinite loops |
| Memory | 256 MB | Prevents memory bombs |
| File Size | 10 MB/file | Prevents disk filling |
| Open Files | 64 fds | Prevents fd exhaustion |
| Child Processes | **0** | Blocks fork bombs, `os.fork()` escape |
| Stack | 8 MB | Prevents stack overflow |

## Architecture

```
main.py               Entry point, CLI, subsystem init
├── filesystem.py     Sandboxed VFS, path resolution
├── network_guard.py  Monkey-patches networking
├── process_manager.py  setrlimit + import blocking + strict isolation
├── agent_api.py      Agent runner, logging
├── shell.py          33 commands, pipes, redirection
├── boot.py           Boot animation, neofetch
├── audit.py          Audit log
├── resource_quotas.py  setrlimit quotas
├── strict_isolation.py  OS-level isolation
├── config.py         Constants, blocked modules
└── utils.py          ANSI helpers
```

## License

MIT
