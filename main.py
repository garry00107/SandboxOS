#!/usr/bin/env python3
"""
SandboxOS — Main Entry Point.

A secure, sandboxed terminal operating system for running AI agents.
AI agents can only access files within the sandbox and cannot
communicate with the outside world.

Usage:
    python3 main.py              # Normal boot
    python3 main.py --no-boot    # Skip boot animation
    python3 main.py --reset      # Reset sandbox to clean state
    python3 main.py --strict     # Enable OS-level isolation (if available)
"""

import os
import sys
import shutil
import argparse

# Add project directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import SANDBOX_ROOT, FS_ROOT, OS_NAME, OS_VERSION, OS_CODENAME
from filesystem import SandboxFilesystem
from network_guard import NetworkGuard
from process_manager import ProcessManager
from agent_api import AgentRunner
from audit import AuditLog
from strict_isolation import StrictIsolation
from shell import SandboxShell
from boot import run_boot_sequence
from utils import green, red, yellow, dim, bold, cyan, error_msg


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=f"{OS_NAME} v{OS_VERSION} — Secure Sandbox for AI Agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py              Start SandboxOS with boot animation
  python3 main.py --no-boot    Start without boot animation
  python3 main.py --reset      Wipe sandbox and start fresh
  python3 main.py --allow-net  Start with network access enabled (unsafe)
  python3 main.py --strict     Enable OS-level isolation (bubblewrap/sandbox-exec)
  python3 main.py --no-audit   Disable audit logging
        """
    )
    parser.add_argument(
        "--no-boot", action="store_true",
        help="Skip the boot animation"
    )
    parser.add_argument(
        "--reset", action="store_true",
        help="Reset sandbox to clean state (deletes all files)"
    )
    parser.add_argument(
        "--allow-net", action="store_true",
        help="Allow network access (disables network guard)"
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Enable OS-level isolation (bubblewrap on Linux, sandbox-exec on macOS)"
    )
    parser.add_argument(
        "--no-audit", action="store_true",
        help="Disable audit logging"
    )
    parser.add_argument(
        "--root", type=str, default=None,
        help=f"Custom sandbox root directory (default: {SANDBOX_ROOT})"
    )
    return parser.parse_args()


def reset_sandbox():
    """Delete and recreate the sandbox from scratch."""
    print(f"\n  {yellow('⚠️  WARNING:', bold=True)} This will delete ALL files in the sandbox!")
    print(f"  Path: {dim(FS_ROOT)}")
    try:
        confirm = input(f"\n  Type '{red('RESET', bold=True)}' to confirm: ")
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled.")
        return False

    if confirm.strip() != "RESET":
        print("  Cancelled.")
        return False

    if os.path.exists(FS_ROOT):
        shutil.rmtree(FS_ROOT)
        print(f"  {green('✓')} Sandbox wiped clean.")
    else:
        print(f"  {dim('Sandbox does not exist yet.')}")

    return True


def main():
    """Main entry point for SandboxOS."""
    args = parse_args()

    # Custom root
    if args.root:
        import config
        config.SANDBOX_ROOT = os.path.expanduser(args.root)
        config.FS_ROOT = os.path.join(config.SANDBOX_ROOT, "root")

    # Handle reset
    if args.reset:
        if not reset_sandbox():
            sys.exit(0)

    # ─── Initialize Subsystems ───────────────────────────────────────────

    # 1. Virtual Filesystem
    try:
        filesystem = SandboxFilesystem()
    except Exception as e:
        error_msg(f"Failed to initialize filesystem: {e}")
        sys.exit(1)

    # 2. Network Guard
    network_guard = NetworkGuard()
    if not args.allow_net:
        network_guard.activate()

    # 3. Audit Log
    audit = None
    if not args.no_audit:
        audit = AuditLog()

    # 4. Strict Isolation
    strict_isolation = None
    if args.strict:
        strict_isolation = StrictIsolation()

    # 5. Process Manager (with audit + strict isolation)
    process_manager = ProcessManager(
        filesystem,
        audit=audit,
        strict_isolation=strict_isolation
    )

    # 6. Agent Runner
    agent_runner = AgentRunner(filesystem, process_manager)

    # ─── Boot Sequence ───────────────────────────────────────────────────

    if not args.no_boot:
        try:
            run_boot_sequence(
                filesystem, network_guard, process_manager,
                strict_isolation=strict_isolation,
                audit=audit
            )
        except KeyboardInterrupt:
            print("\n  Boot interrupted. Starting shell...\n")
    else:
        print(f"\n  {bold(f'{OS_NAME} v{OS_VERSION}')} ({OS_CODENAME})")
        net_status = red("BLOCKED", bold=True) if network_guard.active else green("ALLOWED")
        iso_level = "OS-LEVEL" if (strict_isolation and strict_isolation.available) else "PYTHON-LEVEL"
        iso_color = green if iso_level == "OS-LEVEL" else yellow
        print(f"  Network:   {net_status}")
        print(f"  Isolation: {iso_color(iso_level, bold=True)}")
        print(f"  Audit:     {green('ON') if audit else dim('OFF')}")
        print(f"  Quotas:    {green('setrlimit')}")
        print()

    # ─── Start Shell ─────────────────────────────────────────────────────

    shell = SandboxShell(
        filesystem, process_manager, network_guard, agent_runner,
        audit=audit, strict_isolation=strict_isolation
    )

    try:
        shell.run()
    except KeyboardInterrupt:
        print(f"\n\n  {dim('Interrupted. Shutting down...')}")
        print(f"  {green('Goodbye!', bold=True)}\n")
    except Exception as e:
        error_msg(f"Unexpected error: {e}")
        sys.exit(1)
    finally:
        # Export audit log on shutdown
        if audit:
            path = audit.export_json()
            if path:
                print(f"  {dim(f'Audit log exported: {path}')}")


if __name__ == "__main__":
    main()
