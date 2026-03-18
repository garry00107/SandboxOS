"""
SandboxOS — Gemini AI Agent.

A filesystem coding agent powered by Google Gemini Flash 2.0.
Runs inside SandboxOS with full access to the sandboxed filesystem
and Python execution, but cannot escape the sandbox.

The agent can: read/write files, create directories, run Python scripts,
list directory contents, and delete files. All operations go through
the sandbox filesystem — it cannot touch the host system.

Requires: pip install google-genai
Set GEMINI_API_KEY environment variable before launching.
"""

import os
import sys
import json
import time
import traceback

# Try to import the Gemini SDK (new google-genai package)
try:
    from google import genai
    from google.genai import types
    HAS_GEMINI = True
except ImportError:
    HAS_GEMINI = False


# ─── Tool Functions ──────────────────────────────────────────────────────────

def _build_tools():
    """Build tool declarations for Gemini function calling."""
    read_file = types.FunctionDeclaration(
        name="read_file",
        description="Read the contents of a file at the given path inside the sandbox.",
        parameters=types.Schema(
            type="OBJECT",
            properties={
                "path": types.Schema(
                    type="STRING",
                    description="Absolute path to the file (e.g. /home/agent/main.py)",
                ),
            },
            required=["path"],
        ),
    )

    write_file = types.FunctionDeclaration(
        name="write_file",
        description="Write content to a file. Creates the file if it doesn't exist, overwrites if it does.",
        parameters=types.Schema(
            type="OBJECT",
            properties={
                "path": types.Schema(
                    type="STRING",
                    description="Absolute path for the file (e.g. /home/agent/project/main.py)",
                ),
                "content": types.Schema(
                    type="STRING",
                    description="The complete file content to write",
                ),
            },
            required=["path", "content"],
        ),
    )

    list_directory = types.FunctionDeclaration(
        name="list_directory",
        description="List the contents of a directory, showing files and subdirectories.",
        parameters=types.Schema(
            type="OBJECT",
            properties={
                "path": types.Schema(
                    type="STRING",
                    description="Directory path to list (e.g. /home/agent/project)",
                ),
            },
            required=["path"],
        ),
    )

    create_directory = types.FunctionDeclaration(
        name="create_directory",
        description="Create a directory (and parent directories if needed).",
        parameters=types.Schema(
            type="OBJECT",
            properties={
                "path": types.Schema(
                    type="STRING",
                    description="Directory path to create (e.g. /home/agent/project/src)",
                ),
            },
            required=["path"],
        ),
    )

    run_python = types.FunctionDeclaration(
        name="run_python",
        description="Execute a Python script that exists in the sandbox and return its output. The script must already be written to a file via write_file.",
        parameters=types.Schema(
            type="OBJECT",
            properties={
                "script_path": types.Schema(
                    type="STRING",
                    description="Path to the .py file to execute (e.g. /home/agent/project/test_calc.py)",
                ),
            },
            required=["script_path"],
        ),
    )

    delete_file = types.FunctionDeclaration(
        name="delete_file",
        description="Delete a file or empty directory.",
        parameters=types.Schema(
            type="OBJECT",
            properties={
                "path": types.Schema(
                    type="STRING",
                    description="Path to the file or directory to delete",
                ),
            },
            required=["path"],
        ),
    )

    return types.Tool(function_declarations=[
        read_file, write_file, list_directory,
        create_directory, run_python, delete_file,
    ])


# ─── Tool Executor ───────────────────────────────────────────────────────────

class ToolExecutor:
    """Executes tool calls against the sandboxed filesystem and process manager."""

    def __init__(self, filesystem, process_manager, audit=None):
        self.fs = filesystem
        self.pm = process_manager
        self.audit = audit

    def execute(self, tool_name, args):
        """Execute a tool and return the result string."""
        try:
            if tool_name == "read_file":
                return self._read_file(args["path"])
            elif tool_name == "write_file":
                return self._write_file(args["path"], args["content"])
            elif tool_name == "list_directory":
                return self._list_directory(args["path"])
            elif tool_name == "create_directory":
                return self._create_directory(args["path"])
            elif tool_name == "run_python":
                return self._run_python(args["script_path"])
            elif tool_name == "delete_file":
                return self._delete_file(args["path"])
            else:
                return f"Error: Unknown tool '{tool_name}'"
        except PermissionError as e:
            return f"🛡️ SANDBOX BLOCKED: {e}"
        except Exception as e:
            return f"Error: {type(e).__name__}: {e}"

    def _read_file(self, path):
        content = self.fs.cat(path)
        if content is None:
            return f"Error: Cannot read '{path}' — file not found or permission denied"
        return content

    def _write_file(self, path, content):
        parent = os.path.dirname(path)
        if parent and parent != "/":
            self.fs.mkdir(parent, parents=True)
        if self.fs.write_file(path, content):
            size = len(content.encode("utf-8"))
            return f"✓ Written {size} bytes to {path}"
        return f"Error: Failed to write to '{path}'"

    def _list_directory(self, path):
        try:
            real = self.fs.resolve(path)
        except PermissionError as e:
            return f"🛡️ SANDBOX BLOCKED: {e}"

        if not os.path.isdir(real):
            return f"Error: '{path}' is not a directory"

        entries = []
        try:
            for name in sorted(os.listdir(real)):
                full = os.path.join(real, name)
                if os.path.isdir(full):
                    entries.append(f"  📁 {name}/")
                else:
                    size = os.path.getsize(full)
                    entries.append(f"  📄 {name} ({size}B)")
        except OSError as e:
            return f"Error listing directory: {e}"

        if not entries:
            return f"{path}/ (empty)"
        return f"{path}/\n" + "\n".join(entries)

    def _create_directory(self, path):
        if self.fs.mkdir(path, parents=True):
            return f"✓ Created directory {path}"
        return f"Error: Failed to create '{path}'"

    def _run_python(self, script_path):
        result = self.pm.run_python_script(script_path)
        if result is None:
            return f"Error: Failed to run '{script_path}'"

        output_parts = []
        if result.output:
            output_parts.append(f"stdout:\n{result.output}")
        if result.error:
            output_parts.append(f"stderr:\n{result.error}")

        status = f"Exit code: {result.return_code}"
        elapsed = ""
        if result.end_time and result.start_time:
            elapsed = f" ({result.end_time - result.start_time:.2f}s)"

        return f"{status}{elapsed}\n" + "\n".join(output_parts) if output_parts else status + elapsed

    def _delete_file(self, path):
        if self.fs.rm(path):
            return f"✓ Deleted {path}"
        return f"Error: Failed to delete '{path}'"


# ─── Agent Loop ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a coding assistant running inside SandboxOS — a secure, sandboxed environment.

Your capabilities:
- Read and write files anywhere under /home/agent/
- Create directories
- Run Python scripts (they execute in a sandboxed subprocess with restricted imports)
- List directory contents

Your constraints:
- You CANNOT access files outside /home/agent/ (the sandbox blocks this)
- You CANNOT use networking (socket, requests, urllib are all blocked)
- You CANNOT import subprocess, shutil, ctypes, or threading in scripts you write
- Scripts have a 30-second timeout and 256MB memory limit

When given a task:
1. Plan what files you need to create
2. Write the files using the write_file tool
3. Run tests or scripts to verify your work
4. Fix any issues you find
5. Summarize what you built

Be efficient — create files, run them, iterate. Show your work."""


class GeminiAgent:
    """
    Interactive AI agent powered by Gemini Flash 2.0.
    Executes tool calls against the sandboxed filesystem.
    """

    def __init__(self, filesystem, process_manager, audit=None):
        self.fs = filesystem
        self.pm = process_manager
        self.audit = audit
        self.executor = ToolExecutor(filesystem, process_manager, audit)
        self.client = None
        self.chat = None
        self._total_tool_calls = 0

    def initialize(self, api_key=None):
        """Initialize the Gemini model and chat session."""
        if not HAS_GEMINI:
            return False, (
                "google-genai not installed.\n"
                "Run: pip install google-genai"
            )

        key = api_key or os.environ.get("GEMINI_API_KEY")
        if not key:
            return False, (
                "GEMINI_API_KEY not set.\n"
                "Get a free key at https://aistudio.google.com/apikey\n"
                "Then: export GEMINI_API_KEY=your_key_here"
            )

        try:
            self.client = genai.Client(api_key=key)
            self.chat = self.client.chats.create(
                model="gemini-2.0-flash",
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    tools=[_build_tools()],
                ),
            )
            return True, "Gemini Flash 2.0 initialized"
        except Exception as e:
            return False, f"Failed to initialize Gemini: {e}"

    def process_message(self, user_message, print_fn=print):
        """
        Send a message and handle the full tool-use loop.
        Returns when the model produces a final text response.
        """
        if not self.chat:
            print_fn("  Error: Agent not initialized")
            return

        try:
            response = self.chat.send_message(user_message)
        except Exception as e:
            print_fn(f"  API Error: {e}")
            return

        # Tool-use loop — keep going until the model returns text
        max_iterations = 20
        iteration = 0

        while iteration < max_iterations:
            iteration += 1

            # Check if the response has function calls
            function_calls = []
            if response.candidates:
                for part in response.candidates[0].content.parts:
                    if part.function_call:
                        function_calls.append(part.function_call)

            if not function_calls:
                # No tool calls — extract and print the text response
                if response.text:
                    print_fn(response.text)
                return

            # Execute each function call
            tool_responses = []
            for fc in function_calls:
                tool_name = fc.name
                args = dict(fc.args) if fc.args else {}

                self._total_tool_calls += 1
                print_fn(f"  ⚙️  {tool_name}({_format_args(args)})")

                # Audit
                if self.audit:
                    self.audit.log("agent", "tool_call", tool_name, "ok",
                                   json.dumps(args)[:200])

                result = self.executor.execute(tool_name, args)

                # Print condensed result
                result_preview = result[:200] + "..." if len(result) > 200 else result
                if result.startswith("✓"):
                    print_fn(f"  {result_preview}")
                elif result.startswith("🛡️"):
                    print_fn(f"  {result_preview}")
                elif result.startswith("Error"):
                    print_fn(f"  ❌ {result_preview}")

                tool_responses.append(
                    types.Part.from_function_response(
                        name=tool_name,
                        response={"result": result},
                    )
                )

            # Send tool results back to the model
            try:
                response = self.chat.send_message(tool_responses)
            except Exception as e:
                print_fn(f"  API Error: {e}")
                return

        print_fn("  ⚠️  Max tool iterations reached (20). Stopping.")


def _format_args(args):
    """Format tool call arguments for display."""
    parts = []
    for k, v in args.items():
        if k == "content":
            lines = str(v).count("\n") + 1
            parts.append(f"content=<{lines} lines>")
        else:
            val = str(v)
            if len(val) > 50:
                val = val[:47] + "..."
            parts.append(f"{k}={val}")
    return ", ".join(parts)


# ─── Interactive Chat Loop ───────────────────────────────────────────────────

def run_interactive(filesystem, process_manager, audit=None, api_key=None):
    """
    Run the interactive agent chat session.
    Called from the shell when the user types 'agent chat'.
    """
    from utils import green, cyan, yellow, red, dim, bold, horizontal_line

    print()
    print(f"  {bold('🤖 SandboxOS AI Agent')}")
    print(f"  {dim('Powered by Gemini Flash 2.0')}")
    horizontal_line()

    agent = GeminiAgent(filesystem, process_manager, audit)
    ok, msg = agent.initialize(api_key)

    if not ok:
        print(f"  {red('✗')} {msg}")
        print()
        return

    print(f"  {green('✓')} {msg}")
    print(f"  {dim('Type your task or question. Type `quit` to exit.')}")
    print()

    while True:
        try:
            user_input = input(f"  {cyan('you', bold=True)}{dim(':')} ")
        except (KeyboardInterrupt, EOFError):
            print(f"\n  {dim('Agent session ended.')}\n")
            break

        if not user_input.strip():
            continue

        if user_input.strip().lower() in ("quit", "exit", "q"):
            print(f"\n  {dim('Agent session ended.')}")
            if agent._total_tool_calls > 0:
                print(f"  {dim(f'Total tool calls: {agent._total_tool_calls}')}")
            print()
            break

        print()
        print(f"  {green('agent', bold=True)}{dim(':')}")

        def indented_print(text):
            for line in str(text).splitlines():
                print(f"  {line}")

        agent.process_message(user_input, print_fn=indented_print)
        print()
