"""
SandboxOS — Interactive Shell.

The main REPL (Read-Eval-Print Loop) that provides a command-line
interface within the sandboxed environment. Supports built-in commands,
pipes, output redirection, and environment variables.
"""

import os
import sys
import time
import shlex
import datetime
import readline

from config import (
    OS_NAME, OS_VERSION, OS_CODENAME, OS_KERNEL,
    SHELL_PROMPT_USER, SHELL_PROMPT_HOST, SHELL_HISTORY_SIZE,
    DEFAULT_HOME, WHITELISTED_COMMANDS, FS_ROOT, THEME
)
from utils import (
    Colors, colorize, green, cyan, blue, magenta, yellow, red, dim, bold,
    error_msg, sandbox_violation, print_table, horizontal_line,
    format_size, clear_screen
)


class SandboxShell:
    """
    Interactive shell for SandboxOS.
    """

    def __init__(self, filesystem, process_manager, network_guard, agent_runner,
                 audit=None, strict_isolation=None):
        self.fs = filesystem
        self.pm = process_manager
        self.net = network_guard
        self.agent = agent_runner
        self.audit = audit
        self.strict = strict_isolation
        self.running = True
        self.env = {
            "HOME": DEFAULT_HOME,
            "USER": SHELL_PROMPT_USER,
            "HOSTNAME": SHELL_PROMPT_HOST,
            "SHELL": "/bin/sandboxsh",
            "TERM": "xterm-256color",
            "LANG": "en_US.UTF-8",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "PS1": "\\u@\\h:\\w$ ",
            "SANDBOXOS": "1",
            "SANDBOXOS_VERSION": OS_VERSION,
        }
        self.history = []
        self._setup_readline()

        # Navigate to home
        self.fs.cd(DEFAULT_HOME)

    def _setup_readline(self):
        """Configure readline for tab completion and history."""
        readline.set_history_length(SHELL_HISTORY_SIZE)

        # Tab completion
        commands = list(self._get_builtins().keys())
        commands.sort()

        def completer(text, state):
            options = [c for c in commands if c.startswith(text)]
            # Also complete file paths
            try:
                cwd_real = self.fs.resolve(self.fs.cwd)
                for entry in os.listdir(cwd_real):
                    if entry.startswith(text):
                        full = os.path.join(cwd_real, entry)
                        suffix = "/" if os.path.isdir(full) else ""
                        options.append(entry + suffix)
            except (PermissionError, OSError):
                pass
            if state < len(options):
                return options[state]
            return None

        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")

    def _get_builtins(self):
        """Return dict of built-in command handlers."""
        return {
            "ls": self._cmd_ls,
            "cd": self._cmd_cd,
            "pwd": self._cmd_pwd,
            "cat": self._cmd_cat,
            "echo": self._cmd_echo,
            "mkdir": self._cmd_mkdir,
            "touch": self._cmd_touch,
            "rm": self._cmd_rm,
            "cp": self._cmd_cp,
            "mv": self._cmd_mv,
            "tree": self._cmd_tree,
            "find": self._cmd_find,
            "head": self._cmd_head,
            "tail": self._cmd_tail,
            "wc": self._cmd_wc,
            "chmod": self._cmd_chmod,
            "stat": self._cmd_stat,
            "clear": self._cmd_clear,
            "env": self._cmd_env,
            "export": self._cmd_export,
            "unset": self._cmd_unset,
            "history": self._cmd_history,
            "help": self._cmd_help,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "whoami": self._cmd_whoami,
            "date": self._cmd_date,
            "hostname": self._cmd_hostname,
            "uname": self._cmd_uname,
            "ps": self._cmd_ps,
            "kill": self._cmd_kill,
            "neofetch": self._cmd_neofetch,
            "agent": self._cmd_agent,
            "exec": self._cmd_exec,
            "grep": self._cmd_grep,
            "df": self._cmd_df,
            "du": self._cmd_du,
            "which": self._cmd_which,
            "type": self._cmd_type,
            "alias": self._cmd_alias,
            "write": self._cmd_write,
            "audit": self._cmd_audit,
            "security": self._cmd_security,
            "quotas": self._cmd_quotas,
        }

    def get_prompt(self):
        """Generate the shell prompt string."""
        cwd = self.fs.cwd
        home = self.env.get("HOME", DEFAULT_HOME)

        # Replace home with ~
        if cwd == home:
            display_cwd = "~"
        elif cwd.startswith(home + "/"):
            display_cwd = "~" + cwd[len(home):]
        else:
            display_cwd = cwd

        user = self.env.get("USER", "agent")
        host = self.env.get("HOSTNAME", "sandboxos")

        prompt = (
            f"{THEME['primary']}{bold(user)}"
            f"{Colors.RESET}@"
            f"{THEME['secondary']}{bold(host)}"
            f"{Colors.RESET}:"
            f"{THEME['accent']}{bold(display_cwd)}"
            f"{Colors.RESET}$ "
        )
        return prompt

    def run(self):
        """Main shell loop."""
        while self.running:
            try:
                prompt = self.get_prompt()
                line = input(prompt)

                if not line.strip():
                    continue

                self.history.append(line.strip())
                # Log to audit
                if self.audit:
                    self.audit.shell_command(line.strip())
                self._execute(line.strip())

            except KeyboardInterrupt:
                print("^C")
                continue
            except EOFError:
                print()
                self._cmd_exit([])
                break

    def _execute(self, line):
        """Parse and execute a command line."""
        # Handle output redirection
        redirect_file = None
        redirect_append = False

        if ">>" in line:
            parts = line.split(">>", 1)
            line = parts[0].strip()
            redirect_file = parts[1].strip()
            redirect_append = True
        elif ">" in line and not line.startswith(">"): 
            parts = line.split(">", 1)
            line = parts[0].strip()
            redirect_file = parts[1].strip()

        # Handle pipes
        if "|" in line:
            self._execute_pipe(line, redirect_file, redirect_append)
            return

        # Parse command
        try:
            args = shlex.split(line)
        except ValueError as e:
            error_msg(f"Parse error: {e}")
            return

        if not args:
            return

        # Expand environment variables
        args = [self._expand_vars(a) for a in args]

        cmd = args[0]
        cmd_args = args[1:]

        # Capture output if redirecting
        if redirect_file:
            import io
            old_stdout = sys.stdout
            sys.stdout = buffer = io.StringIO()
            try:
                self._dispatch(cmd, cmd_args)
            finally:
                sys.stdout = old_stdout
            output = buffer.getvalue()
            self.fs.write_file(redirect_file, output, append=redirect_append)
            return

        self._dispatch(cmd, cmd_args)

    def _dispatch(self, cmd, args):
        """Dispatch a command to its handler."""
        builtins = self._get_builtins()

        if cmd in builtins:
            builtins[cmd](args)
        elif self.pm.is_whitelisted(cmd):
            # Run through process manager
            full_cmd = cmd + " " + " ".join(args) if args else cmd
            result = self.pm.run_command(full_cmd)
            if result and result.output:
                print(result.output, end="")
            if result and result.error:
                print(result.error, end="", file=sys.stderr)
        else:
            error_msg(f"'{cmd}': command not found. Type 'help' for available commands.")

    def _execute_pipe(self, line, redirect_file=None, redirect_append=False):
        """Execute a pipeline of commands."""
        import io

        segments = [s.strip() for s in line.split("|")]

        current_input = ""
        for i, segment in enumerate(segments):
            try:
                args = shlex.split(segment)
            except ValueError as e:
                error_msg(f"Parse error in pipe segment: {e}")
                return

            if not args:
                continue

            args = [self._expand_vars(a) for a in args]
            cmd = args[0]
            cmd_args = args[1:]

            # Capture output
            old_stdout = sys.stdout
            old_stdin = sys.stdin

            if current_input:
                sys.stdin = io.StringIO(current_input)

            sys.stdout = buffer = io.StringIO()

            try:
                self._dispatch(cmd, cmd_args)
            finally:
                sys.stdout = old_stdout
                sys.stdin = old_stdin

            current_input = buffer.getvalue()

        # Final output
        if redirect_file:
            self.fs.write_file(redirect_file, current_input, append=redirect_append)
        else:
            print(current_input, end="")

    def _expand_vars(self, text):
        """Expand $VAR and ${VAR} in text."""
        import re

        def replace_var(match):
            var_name = match.group(1) or match.group(2)
            return self.env.get(var_name, "")

        text = re.sub(r'\$\{(\w+)\}', replace_var, text)
        text = re.sub(r'\$(\w+)', replace_var, text)
        return text

    # ─── Built-in Command Handlers ──────────────────────────────────────────

    def _cmd_ls(self, args):
        """List directory contents."""
        show_hidden = "-a" in args or "--all" in args
        long_format = "-l" in args or "--long" in args

        path_args = [a for a in args if not a.startswith("-")]
        path = path_args[0] if path_args else "."

        self.fs.listdir(path, show_hidden=show_hidden, long_format=long_format)

    def _cmd_cd(self, args):
        """Change directory."""
        path = args[0] if args else ""
        if path == "-":
            path = self.env.get("OLDPWD", DEFAULT_HOME)

        old_cwd = self.fs.cwd
        if self.fs.cd(path):
            self.env["OLDPWD"] = old_cwd
            self.env["PWD"] = self.fs.cwd

    def _cmd_pwd(self, args):
        """Print working directory."""
        print(self.fs.cwd)

    def _cmd_cat(self, args):
        """Display file contents."""
        if not args:
            error_msg("cat: missing file operand")
            return
        for path in args:
            content = self.fs.cat(path)
            if content is not None:
                print(content, end="" if content.endswith("\n") else "\n")

    def _cmd_echo(self, args):
        """Echo text to stdout."""
        text = " ".join(args)
        # Handle escape sequences
        text = text.replace("\\n", "\n").replace("\\t", "\t")
        print(text)

    def _cmd_mkdir(self, args):
        """Create directory."""
        parents = "-p" in args
        paths = [a for a in args if not a.startswith("-")]
        if not paths:
            error_msg("mkdir: missing operand")
            return
        for path in paths:
            self.fs.mkdir(path, parents=parents)

    def _cmd_touch(self, args):
        """Create empty file."""
        if not args:
            error_msg("touch: missing file operand")
            return
        for path in args:
            self.fs.touch(path)

    def _cmd_rm(self, args):
        """Remove file or directory."""
        recursive = "-r" in args or "-rf" in args or "--recursive" in args
        force = "-f" in args or "-rf" in args
        paths = [a for a in args if not a.startswith("-")]
        if not paths:
            error_msg("rm: missing operand")
            return
        for path in paths:
            self.fs.rm(path, recursive=recursive)

    def _cmd_cp(self, args):
        """Copy files."""
        recursive = "-r" in args or "--recursive" in args
        paths = [a for a in args if not a.startswith("-")]
        if len(paths) < 2:
            error_msg("cp: missing destination operand")
            return
        self.fs.cp(paths[0], paths[1], recursive=recursive)

    def _cmd_mv(self, args):
        """Move/rename files."""
        paths = [a for a in args if not a.startswith("-")]
        if len(paths) < 2:
            error_msg("mv: missing destination operand")
            return
        self.fs.mv(paths[0], paths[1])

    def _cmd_tree(self, args):
        """Display directory tree."""
        path = args[0] if args else "."
        depth = 3

        for i, arg in enumerate(args):
            if arg == "-L" and i + 1 < len(args):
                try:
                    depth = int(args[i + 1])
                except ValueError:
                    pass

        self.fs.tree(path, max_depth=depth)

    def _cmd_find(self, args):
        """Find files matching a pattern."""
        path = "."
        pattern = "*"
        find_type = None

        i = 0
        non_flag_args = []
        while i < len(args):
            if args[i] == "-name" and i + 1 < len(args):
                pattern = args[i + 1]
                i += 2
            elif args[i] == "-type" and i + 1 < len(args):
                find_type = args[i + 1]
                i += 2
            else:
                non_flag_args.append(args[i])
                i += 1

        if non_flag_args:
            path = non_flag_args[0]

        results = self.fs.find(path, pattern=pattern, find_type=find_type)
        for r in results:
            print(r)

    def _cmd_head(self, args):
        """Display first lines of a file."""
        n = 10
        path = None

        for i, arg in enumerate(args):
            if arg == "-n" and i + 1 < len(args):
                try:
                    n = int(args[i + 1])
                except ValueError:
                    pass
            elif not arg.startswith("-"):
                path = arg

        if not path:
            error_msg("head: missing file operand")
            return

        result = self.fs.head(path, n=n)
        if result is not None:
            print(result)

    def _cmd_tail(self, args):
        """Display last lines of a file."""
        n = 10
        path = None

        for i, arg in enumerate(args):
            if arg == "-n" and i + 1 < len(args):
                try:
                    n = int(args[i + 1])
                except ValueError:
                    pass
            elif not arg.startswith("-"):
                path = arg

        if not path:
            error_msg("tail: missing file operand")
            return

        result = self.fs.tail(path, n=n)
        if result is not None:
            print(result)

    def _cmd_wc(self, args):
        """Count lines, words, chars in a file."""
        paths = [a for a in args if not a.startswith("-")]
        if not paths:
            error_msg("wc: missing file operand")
            return

        for path in paths:
            result = self.fs.wc(path)
            if result:
                lines, words, chars = result
                print(f"  {lines:>6}  {words:>6}  {chars:>6}  {path}")

    def _cmd_chmod(self, args):
        """Change file permissions."""
        if len(args) < 2:
            error_msg("chmod: usage: chmod <mode> <file>")
            return
        self.fs.chmod(args[1], args[0])

    def _cmd_stat(self, args):
        """Display file information."""
        if not args:
            error_msg("stat: missing file operand")
            return

        for path in args:
            info = self.fs.stat_file(path)
            if info:
                print(f"  File: {cyan(info['virtual_path'], bold=True)}")
                print(f"  Type: {info['type']}")
                print(f"  Size: {format_size(info['size'])}")
                print(f"  Perm: {info['permissions']}")
                print(f"  Modified: {info['modified']}")
                print(f"  Created:  {info['created']}")
                print()

    def _cmd_clear(self, args):
        """Clear the screen."""
        clear_screen()

    def _cmd_env(self, args):
        """Display environment variables."""
        for key in sorted(self.env):
            print(f"{green(key)}={self.env[key]}")

    def _cmd_export(self, args):
        """Set an environment variable."""
        if not args:
            self._cmd_env(args)
            return

        for arg in args:
            if "=" in arg:
                key, value = arg.split("=", 1)
                self.env[key] = value
            else:
                error_msg(f"export: usage: export KEY=VALUE")

    def _cmd_unset(self, args):
        """Remove an environment variable."""
        for key in args:
            self.env.pop(key, None)

    def _cmd_history(self, args):
        """Display command history."""
        n = int(args[0]) if args else len(self.history)
        for i, cmd in enumerate(self.history[-n:], 1):
            print(f"  {dim(str(i).rjust(4))}  {cmd}")

    def _cmd_help(self, args):
        """Display available commands."""
        print()
        print(f"  {bold('SandboxOS Shell')} — {dim('Available Commands')}")
        print()

        categories = {
            "📁 File Operations": [
                ("ls [-a] [-l] [path]", "List directory contents"),
                ("cd [path]", "Change directory"),
                ("pwd", "Print working directory"),
                ("cat <file>", "Display file contents"),
                ("head [-n N] <file>", "Show first N lines"),
                ("tail [-n N] <file>", "Show last N lines"),
                ("touch <file>", "Create empty file"),
                ("mkdir [-p] <dir>", "Create directory"),
                ("rm [-r] <path>", "Remove file/directory"),
                ("cp [-r] <src> <dst>", "Copy file/directory"),
                ("mv <src> <dst>", "Move/rename file"),
                ("tree [-L N] [path]", "Show directory tree"),
                ("find [path] -name <pat>", "Find files by pattern"),
                ("wc <file>", "Count lines/words/chars"),
                ("chmod <mode> <file>", "Change permissions"),
                ("stat <file>", "File information"),
                ("write <file> <text>", "Write text to file"),
            ],
            "🖥️  System": [
                ("echo <text>", "Print text"),
                ("clear", "Clear screen"),
                ("env", "Show environment variables"),
                ("export KEY=VAL", "Set environment variable"),
                ("whoami", "Show current user"),
                ("hostname", "Show hostname"),
                ("uname [-a]", "System information"),
                ("date", "Show date/time"),
                ("neofetch", "System info display"),
                ("df", "Disk usage"),
                ("du [path]", "Directory size"),
                ("which <cmd>", "Locate command"),
            ],
            "⚙️  Process Management": [
                ("ps", "List processes"),
                ("kill <pid>", "Kill a process"),
                ("exec <cmd>", "Execute whitelisted command"),
            ],
            "🤖 Agent Commands": [
                ("agent chat", "Start AI agent (Gemini Flash 2.0)"),
                ("agent run <script.py>", "Run an AI agent script"),
                ("agent list", "List agent executions"),
                ("agent log", "Show agent log"),
                ("agent example", "Create example agent"),
                ("agent output <id>", "Show agent output"),
            ],
            "📌 Other": [
                ("history [N]", "Show command history"),
                ("help", "Show this help"),
                ("exit / quit", "Exit SandboxOS"),
            ],
            "🛡️  Security": [
                ("audit [summary|security|N]", "View audit log"),
                ("security", "Show security status"),
                ("quotas", "Show resource quotas"),
            ],
        }

        for category, commands in categories.items():
            print(f"  {bold(category)}")
            for cmd, desc in commands:
                print(f"    {cyan(cmd.ljust(28))} {dim(desc)}")
            print()

        print(f"  {dim('Supports: pipes (|), redirection (>, >>), env vars ($VAR)')}")
        print()

    def _cmd_exit(self, args):
        """Exit the shell."""
        print(f"\n  {dim('Shutting down SandboxOS...')}")
        print(f"  {green('Goodbye!', bold=True)}\n")
        self.running = False

    def _cmd_whoami(self, args):
        """Print current user."""
        print(self.env.get("USER", "agent"))

    def _cmd_date(self, args):
        """Print current date/time."""
        now = datetime.datetime.now()
        print(now.strftime("%a %b %d %H:%M:%S %Z %Y"))

    def _cmd_hostname(self, args):
        """Print hostname."""
        print(self.env.get("HOSTNAME", "sandboxos"))

    def _cmd_uname(self, args):
        """Print system information."""
        if "-a" in args or "--all" in args:
            print(f"{OS_NAME} {OS_KERNEL} sandboxos virtual/sandbox {OS_CODENAME}")
        else:
            print(OS_NAME)

    def _cmd_ps(self, args):
        """List processes."""
        processes = self.pm.list_processes()
        if not processes:
            print(dim("  No processes."))
            return

        headers = ["PID", "STATUS", "COMMAND", "TIME"]
        rows = []
        for p in processes:
            elapsed = ""
            if p.end_time:
                elapsed = f"{p.end_time - p.start_time:.2f}s"
            elif p.status == "running":
                elapsed = f"{time.time() - p.start_time:.2f}s"

            status_colored = p.status
            if "completed" in p.status:
                status_colored = green(p.status)
            elif "killed" in p.status or "error" in p.status:
                status_colored = red(p.status)
            elif p.status == "running":
                status_colored = yellow(p.status)

            rows.append([str(p.pid), status_colored, p.command[:40], elapsed])

        print_table(headers, rows)

    def _cmd_kill(self, args):
        """Kill a process."""
        if not args:
            error_msg("kill: usage: kill <pid>")
            return
        try:
            pid = int(args[0])
            if self.pm.kill_process(pid):
                print(f"  Process {pid} killed.")
        except ValueError:
            error_msg(f"kill: invalid PID: {args[0]}")

    def _cmd_neofetch(self, args):
        """Display system info."""
        from boot import show_neofetch
        show_neofetch(self.fs)

    def _cmd_agent(self, args):
        """Agent management commands."""
        if not args:
            print(f"  Usage: agent <run|chat|list|log|example|output> [args]")
            return

        subcmd = args[0]

        if subcmd == "run":
            if len(args) < 2:
                error_msg("agent run: missing script path")
                return
            script = args[1]
            name = None
            # Parse --name flag
            for i, a in enumerate(args):
                if a == "--name" and i + 1 < len(args):
                    name = args[i + 1]
            self.agent.run_script(script, agent_name=name)

        elif subcmd == "list":
            self.agent.list_agents()

        elif subcmd == "log":
            lines = 20
            if len(args) > 1:
                try:
                    lines = int(args[1])
                except ValueError:
                    pass
            self.agent.show_log(lines)

        elif subcmd == "example":
            self.agent.create_example_agent()

        elif subcmd == "output":
            if len(args) < 2:
                error_msg("agent output: missing agent ID")
                return
            try:
                aid = int(args[1])
                info = self.agent.get_agent_output(aid)
                if info:
                    print(f"\n  {bold('Agent:')} {info['name']} (ID: {info['id']})")
                    print(f"  {bold('Script:')} {info['script']}")
                    print(f"  {bold('Status:')} {info['status']}")
                    print(f"  {bold('Exit:')} {info['return_code']}")
                    print(f"  {bold('Time:')} {info['elapsed']:.2f}s")
                    if info['output']:
                        print(f"\n  {bold('Output:')}")
                        horizontal_line()
                        print(info['output'])
                        horizontal_line()
                    if info['error']:
                        print(f"\n  {red('Stderr:', bold=True)}")
                        print(red(info['error']))
            except ValueError:
                error_msg(f"agent output: invalid ID: {args[1]}")

        elif subcmd == "chat":
            # Launch interactive Gemini agent
            from gemini_agent import run_interactive
            api_key = self.env.get("GEMINI_API_KEY") or os.environ.get("GEMINI_API_KEY")
            run_interactive(self.fs, self.pm, audit=self.audit, api_key=api_key)

        else:
            error_msg(f"agent: unknown subcommand '{subcmd}'")

    def _cmd_exec(self, args):
        """Execute a whitelisted command."""
        if not args:
            error_msg("exec: missing command")
            return
        cmd = " ".join(args)
        result = self.pm.run_command(cmd)
        if result and result.output:
            print(result.output, end="")
        if result and result.error:
            print(result.error, end="", file=sys.stderr)

    def _cmd_grep(self, args):
        """Search for patterns in files."""
        if len(args) < 2:
            error_msg("grep: usage: grep <pattern> <file>")
            return

        pattern = args[0]
        files = args[1:]

        for filepath in files:
            content = self.fs.cat(filepath)
            if content is None:
                continue

            for i, line in enumerate(content.splitlines(), 1):
                if pattern.lower() in line.lower():
                    if len(files) > 1:
                        print(f"{cyan(filepath)}:{yellow(str(i))}:{line}")
                    else:
                        print(f"{yellow(str(i))}:{line}")

    def _cmd_df(self, args):
        """Show disk usage of the sandbox."""
        total = self.fs.disk_usage()
        files = self.fs.file_count()
        print(f"  Filesystem     Size    Files   Mounted on")
        print(f"  sandboxfs      {format_size(total):>6s}  {files:>5d}   /")

    def _cmd_du(self, args):
        """Show size of a path."""
        path = args[0] if args else "."
        size = self.fs.get_size(path)
        print(f"  {format_size(size)}\t{path}")

    def _cmd_which(self, args):
        """Locate a command."""
        if not args:
            error_msg("which: missing argument")
            return

        builtins = self._get_builtins()
        for cmd in args:
            if cmd in builtins:
                print(f"  {cmd}: shell built-in")
            elif cmd in WHITELISTED_COMMANDS:
                print(f"  {cmd}: whitelisted external command")
            else:
                error_msg(f"{cmd}: not found")

    def _cmd_type(self, args):
        """Show type of a command."""
        self._cmd_which(args)

    def _cmd_alias(self, args):
        """Alias management (informational only)."""
        print(dim("  Aliases are not supported in SandboxOS shell."))

    def _cmd_write(self, args):
        """Write text to a file. Usage: write <file> <text...>"""
        if len(args) < 2:
            error_msg("write: usage: write <file> <text>")
            return
        filepath = args[0]
        content = " ".join(args[1:]) + "\n"
        if self.fs.write_file(filepath, content):
            print(f"  {green('✓')} Written to {cyan(filepath)}")

    def _cmd_audit(self, args):
        """View audit log."""
        if not self.audit:
            print(dim("  Audit logging is disabled. Start with --no-audit removed."))
            return

        subcmd = args[0] if args else "20"

        if subcmd == "summary":
            summary = self.audit.get_summary()
            print(f"\n  {bold('Audit Summary')}")
            horizontal_line()
            print(f"  Total events:   {summary['total_events']}")
            print(f"  Blocked events: {red(str(summary['blocked_events']), bold=True)}")
            print(f"\n  {bold('By Category:')}")
            for cat, count in sorted(summary['categories'].items()):
                print(f"    {cat.ljust(15)} {count}")
            print(f"\n  {bold('Counters:')}")
            for key, val in sorted(summary['counters'].items()):
                if val > 0:
                    print(f"    {key.ljust(25)} {val}")
            print()

        elif subcmd == "security":
            events = self.audit.get_security_events()
            if not events:
                print(dim("  No security events recorded."))
                return
            print(f"\n  {bold('Security Events')} {dim(f'({len(events)} events)')}")
            horizontal_line()
            for event in events:
                print(f"  {red('✗')} {event.to_line()}")
            print()

        elif subcmd == "export":
            path = self.audit.export_json()
            if path:
                vpath = self.fs.to_virtual(path) if hasattr(self.fs, 'to_virtual') else path
                print(f"  {green('✓')} Audit log exported to {cyan(vpath)}")
            else:
                error_msg("Failed to export audit log")

        else:
            # Show last N events
            try:
                n = int(subcmd)
            except ValueError:
                n = 20
            events = self.audit.get_events(last_n=n)
            if not events:
                print(dim("  No audit events recorded."))
                return
            print(f"\n  {bold('Audit Log')} {dim(f'(last {len(events)} events)')}")
            horizontal_line()
            for event in events:
                icon_color = green if event.result == "ok" else red
                print(f"  {icon_color(event.to_line())}")
            print()

    def _cmd_security(self, args):
        """Show security status."""
        print(f"\n  {bold('🛡️  SandboxOS Security Status')}")
        horizontal_line()

        # Isolation level
        if self.strict and self.strict.available:
            print(f"  Isolation:    {green('OS-LEVEL', bold=True)} via {self.strict.method}")
            for cap in self.strict.capabilities:
                print(f"                {green('●')} {cap}")
        else:
            print(f"  Isolation:    {yellow('PYTHON-LEVEL', bold=True)}")
            print(f"                {dim('Prevents accidents, not adversarial escape.')}")
            print(f"                {dim('Use --strict for OS-level isolation.')}")

        # Network
        print(f"  Network:      {red('BLOCKED', bold=True) if self.net.active else green('ALLOWED')}")

        # Resource quotas
        from resource_quotas import format_quotas
        quotas = format_quotas()
        print(f"  Quotas:       {green('ENFORCED', bold=True)} (kernel setrlimit)")
        for key, val in quotas.items():
            print(f"                {key}: {val}")

        # Audit
        if self.audit:
            summary = self.audit.get_summary()
            print(f"  Audit:        {green('ACTIVE', bold=True)} ({summary['total_events']} events, "
                  f"{summary['blocked_events']} blocked)")
        else:
            print(f"  Audit:        {dim('DISABLED')}")

        # Blocked modules
        from config import BLOCKED_PYTHON_MODULES
        print(f"  Blocked mods: {len(BLOCKED_PYTHON_MODULES)} modules restricted")
        print(f"                {dim(', '.join(BLOCKED_PYTHON_MODULES[:6]))}...")

        horizontal_line()
        print()

    def _cmd_quotas(self, args):
        """Show resource quota settings."""
        from resource_quotas import format_quotas, get_current_usage

        print(f"\n  {bold('Resource Quotas')} {dim('(kernel-enforced via setrlimit)')}")
        horizontal_line()

        quotas = format_quotas()
        for key, val in quotas.items():
            print(f"  {key.ljust(20)} {green(val)}")

        print(f"\n  {bold('Current Usage')}")
        horizontal_line()
        usage = get_current_usage()
        for key, val in usage["self"].items():
            label = key.replace("_", " ").title()
            print(f"  {label.ljust(28)} {val}")

        if any(v != "0.000s" and v != "0.0MB" and v != "0" for v in usage["children"].values()):
            print(f"\n  {bold('Child Processes')}")
            for key, val in usage["children"].items():
                label = key.replace("_", " ").title()
                print(f"  {label.ljust(28)} {val}")
        print()
