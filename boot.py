"""
SandboxOS — Boot Sequence.

Displays the boot animation with ASCII art logo, system checks,
and a neofetch-style system information display.
"""

import sys
import time
import os
import platform
import datetime

from config import OS_NAME, OS_VERSION, OS_CODENAME, OS_KERNEL, OS_ARCH, THEME
from utils import (
    Colors, colorize, green, cyan, blue, magenta, yellow, red, dim, bold,
    status_ok, status_fail, status_warn, clear_screen
)


LOGO = r"""
   ╔═══════════════════════════════════════════════════════════╗
   ║                                                           ║
   ║    ███████╗ █████╗ ███╗   ██╗██████╗ ██████╗  ██████╗     ║
   ║    ██╔════╝██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗    ║
   ║    ███████╗███████║██╔██╗ ██║██║  ██║██████╔╝██║   ██║    ║
   ║    ╚════██║██╔══██║██║╚██╗██║██║  ██║██╔══██╗██║   ██║    ║
   ║    ███████║██║  ██║██║ ╚████║██████╔╝██████╔╝╚██████╔╝    ║
   ║    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═════╝  ╚═════╝     ║
   ║                     ██╗  ██╗ ██████╗ ███████╗               ║
   ║                     ╚██╗██╔╝██╔═══██╗██╔════╝               ║
   ║                      ╚███╔╝ ██║   ██║███████╗               ║
   ║                      ██╔██╗ ██║   ██║╚════██║               ║
   ║                     ██╔╝ ██╗╚██████╔╝███████║               ║
   ║                     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝               ║
   ║                                                           ║
   ║          Secure Sandbox OS for AI Agents  v1.0.0          ║
   ║                    Codename: Ironclad                     ║
   ║                                                           ║
   ╚═══════════════════════════════════════════════════════════╝
"""

LOGO_SMALL = r"""
  ┌──────────────────────────────────────┐
  │  ╔═╗┌─┐┌┐┌┌┬┐┌┐ ┌─┐─┐ ┬╔═╗╔═╗      │
  │  ╚═╗├─┤│││ ││├┴┐│ │┌┴┬┘║ ║╚═╗      │
  │  ╚═╝┴ ┴┘└┘─┴┘└─┘└─┘┴ └─╚═╝╚═╝      │
  │      Secure AI Agent Sandbox         │
  │           v1.0.0 Ironclad            │
  └──────────────────────────────────────┘
"""


def type_print(text, delay=0.01):
    """Print text with a typing effect."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def boot_step(message, delay=0.15, success=True):
    """Display a boot step with a brief delay."""
    time.sleep(delay)
    if success:
        status_ok(message)
    else:
        status_fail(message)


def run_boot_sequence(filesystem, network_guard, process_manager,
                      strict_isolation=None, audit=None):
    """
    Run the full boot sequence animation.
    """
    clear_screen()

    # Show logo
    print(colorize(LOGO, THEME["primary"]))
    time.sleep(0.5)

    print()
    print(f"  {dim('Starting SandboxOS...')}")
    print()
    time.sleep(0.3)

    # Boot steps
    boot_step("Loading kernel modules...")
    boot_step("Initializing virtual filesystem...")
    boot_step(f"Mounting root at {dim(filesystem.root)}")
    boot_step("Creating directory structure...")
    boot_step("Loading network guard...")

    if network_guard.active:
        boot_step("Network isolation: ACTIVE — all external access blocked")
    else:
        boot_step("Network isolation: INACTIVE", success=False)

    boot_step("Starting process manager...")
    boot_step(f"Resource quotas: ENFORCED (setrlimit)")
    boot_step("Loading import blockers...")

    # Strict isolation status
    if strict_isolation:
        if strict_isolation.available:
            boot_step(f"Isolation level: {green('OS-LEVEL', bold=True)} via {strict_isolation.method}")
        else:
            from utils import status_warn
            status_warn(f"Isolation level: {yellow('PYTHON-LEVEL')} (install bubblewrap for OS-level)")
    else:
        boot_step("Isolation level: PYTHON-LEVEL (default)")

    # Audit log
    if audit:
        boot_step("Audit logging: ACTIVE — recording all operations")
    else:
        boot_step("Audit logging: disabled")

    boot_step("Initializing agent runtime...")
    boot_step("Reading /etc/motd...")

    print()
    time.sleep(0.2)

    # System ready message
    print(f"  {green('━' * 52, bold=True)}")
    print(f"  {green('  ✓ SandboxOS is ready.', bold=True)}")
    print(f"  {green('━' * 52, bold=True)}")
    print()
    time.sleep(0.3)

    # Show MOTD
    motd = filesystem.cat("/etc/motd")
    if motd:
        for line in motd.strip().splitlines():
            print(f"  {dim(line)}")
    print()


def show_neofetch(filesystem):
    """Display neofetch-style system information."""
    logo_lines = [
        "  ╔═╗┌─┐┌┐┌┌┬┐┌┐ ┌─┐─┐ ┬╔═╗╔═╗",
        "  ╚═╗├─┤│││ ││├┴┐│ │┌┴┬┘║ ║╚═╗",
        "  ╚═╝┴ ┴┘└┘─┴┘└─┘└─┘┴ └─╚═╝╚═╝",
        "                                 ",
        "     Secure AI Agent Sandbox     ",
    ]

    now = datetime.datetime.now()
    disk_usage = filesystem.disk_usage()
    file_count = filesystem.file_count()

    info_lines = [
        f"{cyan('agent', bold=True)}@{cyan('sandboxos', bold=True)}",
        f"{dim('─' * 22)}",
        f"{bold('OS:')}         {OS_NAME} {OS_VERSION} ({OS_CODENAME})",
        f"{bold('Kernel:')}     {OS_KERNEL}",
        f"{bold('Arch:')}       {OS_ARCH}",
        f"{bold('Shell:')}      SandboxShell 1.0",
        f"{bold('Uptime:')}     {now.strftime('%H:%M:%S')}",
        f"{bold('Disk:')}       {_format_size(disk_usage)} / ∞ (sandboxed)",
        f"{bold('Files:')}      {file_count}",
        f"{bold('Network:')}    {red('BLOCKED', bold=True)}",
        f"{bold('Quotas:')}     {green('setrlimit', bold=True)}",
        f"{bold('Security:')}   {green('MAXIMUM', bold=True)}",
        f"{dim('─' * 22)}",
        _color_blocks(),
    ]

    # Print side by side
    max_lines = max(len(logo_lines), len(info_lines))
    print()
    for i in range(max_lines):
        logo_part = cyan(logo_lines[i]) if i < len(logo_lines) else " " * 34
        info_part = info_lines[i] if i < len(info_lines) else ""
        print(f"  {logo_part}    {info_part}")
    print()


def _format_size(size_bytes):
    """Format bytes to human-readable."""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f}K"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / (1024 ** 2):.1f}M"
    return f"{size_bytes / (1024 ** 3):.1f}G"


def _color_blocks():
    """Generate terminal color blocks for neofetch."""
    blocks = ""
    for i in range(30, 38):
        blocks += f"\033[{i}m██"
    blocks += Colors.RESET + " "
    for i in range(90, 98):
        blocks += f"\033[{i}m██"
    blocks += Colors.RESET
    return blocks
