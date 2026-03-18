"""
SandboxOS — AI Agent API.

Provides a high-level interface for AI agents to interact with the sandbox.
Agents can read/write files, list directories, and execute scripts — all
within the security boundary of the sandbox.
"""

import os
import time
import datetime

from config import FS_ROOT
from utils import (
    error_msg, green, yellow, cyan, blue, red, dim, bold,
    status_ok, status_info, print_table, horizontal_line
)


class AgentRunner:
    """
    High-level API for AI agents running inside SandboxOS.
    """

    def __init__(self, filesystem, process_manager):
        self.filesystem = filesystem
        self.process_manager = process_manager
        self.agents = {}
        self._next_agent_id = 1
        self._log_path = "/var/log/agent.log"

    def _log(self, message):
        """Append a log entry to the agent log file."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}\n"
        self.filesystem.write_file(self._log_path, entry, append=True)

    def run_script(self, virtual_path, args=None, agent_name=None):
        """
        Execute a Python script as an AI agent within the sandbox.
        """
        agent_id = self._next_agent_id
        self._next_agent_id += 1

        name = agent_name or f"agent-{agent_id}"
        self._log(f"Starting agent '{name}' — script: {virtual_path}")

        print(f"\n{cyan('▶', bold=True)} Starting agent {bold(name)}...")
        print(f"  Script: {dim(virtual_path)}")

        # Check if script exists
        if not self.filesystem.exists(virtual_path):
            error_msg(f"Script not found: {virtual_path}")
            self._log(f"Agent '{name}' FAILED — script not found: {virtual_path}")
            return None

        start_time = time.time()

        # Run the script through the process manager
        result = self.process_manager.run_python_script(virtual_path, args=args)

        elapsed = time.time() - start_time

        if result is None:
            self._log(f"Agent '{name}' FAILED — could not start")
            return None

        # Store agent info
        agent_info = {
            "id": agent_id,
            "name": name,
            "script": virtual_path,
            "pid": result.pid,
            "status": result.status,
            "return_code": result.return_code,
            "elapsed": elapsed,
            "output": result.output,
            "error": result.error,
        }
        self.agents[agent_id] = agent_info

        # Display results
        print()
        if result.output:
            print(dim("─── output ─" + "─" * 48))
            print(result.output.rstrip())
            print(dim("─" * 60))

        if result.error:
            print(f"\n{red('stderr:', bold=True)}")
            print(red(result.error.rstrip()))

        print()
        if result.return_code == 0:
            print(f"  {green('✓', bold=True)} Agent {bold(name)} completed successfully "
                  f"{dim(f'({elapsed:.2f}s)')}")
            self._log(f"Agent '{name}' completed successfully ({elapsed:.2f}s)")
        else:
            print(f"  {red('✗', bold=True)} Agent {bold(name)} exited with code {result.return_code} "
                  f"{dim(f'({elapsed:.2f}s)')}")
            self._log(f"Agent '{name}' failed with code {result.return_code} ({elapsed:.2f}s)")

        return agent_info

    def list_agents(self):
        """Display all agent executions."""
        if not self.agents:
            print(dim("  No agents have been run yet."))
            return

        headers = ["ID", "Name", "Script", "Status", "Exit", "Time"]
        rows = []
        for aid, info in self.agents.items():
            status_icon = green("✓") if info["return_code"] == 0 else red("✗")
            rows.append([
                str(info["id"]),
                info["name"],
                info["script"],
                f"{status_icon} {info['status']}",
                str(info["return_code"] if info["return_code"] is not None else "-"),
                f"{info['elapsed']:.2f}s",
            ])

        print_table(headers, rows)

    def show_log(self, lines=20):
        """Display the agent execution log."""
        content = self.filesystem.cat(self._log_path)
        if content is None or not content.strip():
            print(dim("  Agent log is empty."))
            return

        log_lines = content.strip().splitlines()
        display = log_lines[-lines:]

        print(f"\n  {bold('Agent Log')} {dim(f'(last {len(display)} entries)')}")
        horizontal_line()
        for line in display:
            # Color-code log entries
            if "FAILED" in line or "failed" in line:
                print(f"  {red(line)}")
            elif "completed successfully" in line:
                print(f"  {green(line)}")
            else:
                print(f"  {line}")
        horizontal_line()

    def get_agent_output(self, agent_id):
        """Get the output of a specific agent run."""
        if agent_id not in self.agents:
            error_msg(f"No agent with ID {agent_id}")
            return None
        return self.agents[agent_id]

    def create_example_agent(self):
        """Create an example agent script in the sandbox."""
        example = '''"""
Example SandboxOS Agent Script
This script demonstrates what an AI agent can do inside the sandbox.
"""

import os

print("🤖 Hello from SandboxOS Agent!")
print(f"   Working directory: {os.getcwd()}")
print(f"   Home: {os.environ.get('HOME', 'unknown')}")
print(f"   User: {os.environ.get('USER', 'unknown')}")
print()

# File operations work within the sandbox
print("📁 Creating files...")
with open("agent_output.txt", "w") as f:
    f.write("This file was created by an AI agent inside SandboxOS.\\n")
    f.write("The agent cannot access files outside the sandbox.\\n")
print("   Created: agent_output.txt")

# Reading files within sandbox
print("\\n📄 Reading /etc/os-release...")
try:
    sandbox_root = os.environ.get("SANDBOXOS_ROOT", "")
    with open(os.path.join(sandbox_root, "etc", "os-release")) as f:
        print(f.read())
except Exception as e:
    print(f"   Error: {e}")

# Demonstrate blocked operations
print("🛡️  Testing security boundaries...")

# Test 1: Try to access host filesystem
print("\\n   Test 1: Accessing host filesystem...")
try:
    with open("/etc/passwd") as f:
        print("   ❌ SECURITY BREACH: Could read host /etc/passwd!")
except PermissionError as e:
    print(f"   ✅ Blocked: {e}")

# Test 2: Try to import socket
print("\\n   Test 2: Importing socket module...")
try:
    import socket
    print("   ❌ SECURITY BREACH: Could import socket!")
except ImportError as e:
    print(f"   ✅ Blocked: {e}")

# Test 3: Try to import subprocess
print("\\n   Test 3: Importing subprocess module...")
try:
    import subprocess
    print("   ❌ SECURITY BREACH: Could import subprocess!")
except ImportError as e:
    print(f"   ✅ Blocked: {e}")

# Test 4: Try os.system
print("\\n   Test 4: Using os.system()...")
try:
    os.system("echo hacked")
    print("   ❌ SECURITY BREACH: os.system() worked!")
except PermissionError as e:
    print(f"   ✅ Blocked: {e}")

print("\\n✅ All security checks passed!")
print("🤖 Agent execution complete.")
'''
        path = "/home/agent/scripts/example_agent.py"
        if self.filesystem.write_file(path, example):
            print(f"  {green('✓')} Created example agent: {cyan(path)}")
            print(f"  Run it with: {bold('agent run /home/agent/scripts/example_agent.py')}")
            return True
        return False
