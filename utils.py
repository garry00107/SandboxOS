"""
SandboxOS — Utility functions for terminal formatting and display.
"""

import os
import datetime


# ─── ANSI Color Codes ────────────────────────────────────────────────────────

class Colors:
    """ANSI escape code constants for terminal coloring."""
    RESET       = "\033[0m"
    BOLD        = "\033[1m"
    DIM         = "\033[2m"
    ITALIC      = "\033[3m"
    UNDERLINE   = "\033[4m"
    BLINK       = "\033[5m"
    REVERSE     = "\033[7m"
    STRIKETHROUGH = "\033[9m"

    # Standard colors
    BLACK       = "\033[30m"
    RED         = "\033[31m"
    GREEN       = "\033[32m"
    YELLOW      = "\033[33m"
    BLUE        = "\033[34m"
    MAGENTA     = "\033[35m"
    CYAN        = "\033[36m"
    WHITE       = "\033[37m"

    # Bright colors
    BRIGHT_BLACK   = "\033[90m"
    BRIGHT_RED     = "\033[91m"
    BRIGHT_GREEN   = "\033[92m"
    BRIGHT_YELLOW  = "\033[93m"
    BRIGHT_BLUE    = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN    = "\033[96m"
    BRIGHT_WHITE   = "\033[97m"

    # Background colors
    BG_BLACK    = "\033[40m"
    BG_RED      = "\033[41m"
    BG_GREEN    = "\033[42m"
    BG_YELLOW   = "\033[43m"
    BG_BLUE     = "\033[44m"
    BG_MAGENTA  = "\033[45m"
    BG_CYAN     = "\033[46m"
    BG_WHITE    = "\033[47m"

    BG_BRIGHT_BLACK   = "\033[100m"
    BG_BRIGHT_RED     = "\033[101m"
    BG_BRIGHT_GREEN   = "\033[102m"
    BG_BRIGHT_YELLOW  = "\033[103m"
    BG_BRIGHT_BLUE    = "\033[104m"
    BG_BRIGHT_MAGENTA = "\033[105m"
    BG_BRIGHT_CYAN    = "\033[106m"
    BG_BRIGHT_WHITE   = "\033[107m"


# ─── Color Helper Functions ──────────────────────────────────────────────────

def colorize(text, color, bold=False):
    """Wrap text in ANSI color codes."""
    prefix = Colors.BOLD if bold else ""
    return f"{prefix}{color}{text}{Colors.RESET}"


def red(text, bold=False):
    return colorize(text, Colors.RED, bold)


def green(text, bold=False):
    return colorize(text, Colors.GREEN, bold)


def yellow(text, bold=False):
    return colorize(text, Colors.YELLOW, bold)


def blue(text, bold=False):
    return colorize(text, Colors.BLUE, bold)


def cyan(text, bold=False):
    return colorize(text, Colors.CYAN, bold)


def magenta(text, bold=False):
    return colorize(text, Colors.MAGENTA, bold)


def white(text, bold=False):
    return colorize(text, Colors.WHITE, bold)


def dim(text):
    return f"{Colors.DIM}{text}{Colors.RESET}"


def bold(text):
    return f"{Colors.BOLD}{text}{Colors.RESET}"


# ─── Display Helpers ─────────────────────────────────────────────────────────

def status_ok(message):
    """Print a green [  OK  ] status message."""
    print(f"  {green('[  OK  ]', bold=True)}  {message}")


def status_fail(message):
    """Print a red [ FAIL ] status message."""
    print(f"  {red('[ FAIL ]', bold=True)}  {message}")


def status_warn(message):
    """Print a yellow [ WARN ] status message."""
    print(f"  {yellow('[ WARN ]', bold=True)}  {message}")


def status_info(message):
    """Print a blue [ INFO ] status message."""
    print(f"  {blue('[ INFO ]', bold=True)}  {message}")


def error_msg(message):
    """Print a formatted error message."""
    print(f"{red('error:', bold=True)} {message}")


def warn_msg(message):
    """Print a formatted warning message."""
    print(f"{yellow('warning:', bold=True)} {message}")


def permission_denied(action=""):
    """Print a permission denied message."""
    msg = "Permission denied"
    if action:
        msg += f": {action}"
    error_msg(msg)


def sandbox_violation(detail=""):
    """Print a sandbox violation message."""
    msg = f"{red('🛡️  SANDBOX VIOLATION', bold=True)}"
    if detail:
        msg += f" — {detail}"
    print(msg)


# ─── Formatting Helpers ─────────────────────────────────────────────────────

def format_size(size_bytes):
    """Format a byte count into a human-readable size string."""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f}K"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / (1024 ** 2):.1f}M"
    else:
        return f"{size_bytes / (1024 ** 3):.1f}G"


def format_time(timestamp):
    """Format a Unix timestamp into a readable date string."""
    dt = datetime.datetime.fromtimestamp(timestamp)
    return dt.strftime("%b %d %H:%M")


def format_permissions(mode):
    """Format file mode into a permission string like -rwxr-xr-x."""
    perms = ""
    for who in range(2, -1, -1):
        bits = (mode >> (who * 3)) & 7
        perms += "r" if bits & 4 else "-"
        perms += "w" if bits & 2 else "-"
        perms += "x" if bits & 1 else "-"
    return perms


def print_table(headers, rows, col_widths=None):
    """Print a formatted table with headers and rows."""
    if not col_widths:
        col_widths = []
        for i, header in enumerate(headers):
            max_width = len(header)
            for row in rows:
                if i < len(row):
                    max_width = max(max_width, len(str(row[i])))
            col_widths.append(max_width + 2)

    # Header
    header_str = ""
    for i, header in enumerate(headers):
        header_str += bold(header.ljust(col_widths[i]))
    print(header_str)

    # Separator
    print(dim("─" * sum(col_widths)))

    # Rows
    for row in rows:
        row_str = ""
        for i, cell in enumerate(row):
            if i < len(col_widths):
                row_str += str(cell).ljust(col_widths[i])
        print(row_str)


def clear_screen():
    """Clear the terminal screen."""
    print("\033[2J\033[H", end="", flush=True)


def move_cursor(row, col):
    """Move cursor to specific position."""
    print(f"\033[{row};{col}H", end="", flush=True)


def horizontal_line(char="─", width=60):
    """Print a horizontal line."""
    print(dim(char * width))
