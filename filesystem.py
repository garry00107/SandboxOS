"""
SandboxOS — Virtual Filesystem with path sandboxing.

All file operations are contained within the sandbox root directory.
Path traversal attacks (../) and symlink escapes are blocked.
"""

import os
import stat
import shutil
import fnmatch
import datetime

from config import (
    FS_ROOT, DEFAULT_DIRS, MAX_FILE_SIZE,
    MAX_FILES, MAX_PATH_DEPTH, MAX_FILENAME_LENGTH
)
from utils import (
    colorize, Colors, format_size, format_time,
    format_permissions, error_msg, sandbox_violation, dim, cyan, blue, green, yellow
)


class SandboxFilesystem:
    """
    A sandboxed virtual filesystem rooted at FS_ROOT.
    All paths are resolved and validated to prevent escape.
    """

    def __init__(self):
        self.root = os.path.realpath(FS_ROOT)
        self.cwd = "/"  # Virtual cwd (relative to sandbox root)
        self._init_filesystem()

    def _init_filesystem(self):
        """Create the sandbox root and default directory structure."""
        os.makedirs(self.root, exist_ok=True)
        for d in DEFAULT_DIRS:
            real_path = os.path.join(self.root, d.lstrip("/"))
            os.makedirs(real_path, exist_ok=True)

        # Create default config files
        etc_hostname = os.path.join(self.root, "etc", "hostname")
        if not os.path.exists(etc_hostname):
            with open(etc_hostname, "w") as f:
                f.write("sandboxos\n")

        etc_os_release = os.path.join(self.root, "etc", "os-release")
        if not os.path.exists(etc_os_release):
            with open(etc_os_release, "w") as f:
                f.write('NAME="SandboxOS"\n')
                f.write('VERSION="1.0.0"\n')
                f.write('CODENAME="Ironclad"\n')
                f.write('ID=sandboxos\n')

        etc_motd = os.path.join(self.root, "etc", "motd")
        if not os.path.exists(etc_motd):
            with open(etc_motd, "w") as f:
                f.write("Welcome to SandboxOS — a secure sandbox for AI agents.\n")
                f.write("All file operations are contained within this environment.\n")
                f.write("Network access is disabled by default.\n")
                f.write("Type 'help' for available commands.\n")

        etc_passwd = os.path.join(self.root, "etc", "passwd")
        if not os.path.exists(etc_passwd):
            with open(etc_passwd, "w") as f:
                f.write("root:x:0:0:root:/root:/bin/sh\n")
                f.write("agent:x:1000:1000:AI Agent:/home/agent:/bin/sh\n")

    # ─── Path Resolution & Validation ────────────────────────────────────────

    def resolve(self, virtual_path):
        """
        Resolve a virtual path to its real host path, ensuring it stays
        within the sandbox root. Returns the real path or raises an error.
        """
        # Handle relative vs absolute virtual paths
        if not virtual_path.startswith("/"):
            virtual_path = os.path.join(self.cwd, virtual_path)

        # Normalize the path (resolve . and ..)
        virtual_path = os.path.normpath(virtual_path)

        # Build the real host path
        # Strip leading / to join properly
        rel = virtual_path.lstrip("/")
        real_path = os.path.realpath(os.path.join(self.root, rel))

        # Security check: ensure resolved path is within sandbox root
        if not real_path.startswith(self.root):
            raise PermissionError(
                f"Path escapes sandbox: '{virtual_path}' resolves outside sandbox root"
            )

        # Check for symlink escape
        if os.path.islink(real_path):
            link_target = os.path.realpath(real_path)
            if not link_target.startswith(self.root):
                raise PermissionError(
                    f"Symlink escape detected: '{virtual_path}' points outside sandbox"
                )

        return real_path

    def to_virtual(self, real_path):
        """Convert a real host path back to a virtual sandbox path."""
        real_path = os.path.realpath(real_path)
        if not real_path.startswith(self.root):
            return "???"
        vpath = real_path[len(self.root):]
        if not vpath:
            return "/"
        return vpath

    def validate_filename(self, name):
        """Validate a filename for safety."""
        if len(name) > MAX_FILENAME_LENGTH:
            raise ValueError(f"Filename too long (max {MAX_FILENAME_LENGTH} chars)")
        if "\0" in name:
            raise ValueError("Null bytes not allowed in filenames")
        if "/" in name and name != "/":
            pass  # paths with / are okay, individual segments are checked
        forbidden = ["<", ">", "|", '"', "?", "*"]
        for ch in forbidden:
            if ch in os.path.basename(name):
                raise ValueError(f"Forbidden character in filename: '{ch}'")

    # ─── File Operations ─────────────────────────────────────────────────────

    def exists(self, virtual_path):
        """Check if a path exists in the sandbox."""
        try:
            real = self.resolve(virtual_path)
            return os.path.exists(real)
        except PermissionError:
            return False

    def is_dir(self, virtual_path):
        """Check if path is a directory."""
        try:
            real = self.resolve(virtual_path)
            return os.path.isdir(real)
        except PermissionError:
            return False

    def is_file(self, virtual_path):
        """Check if path is a regular file."""
        try:
            real = self.resolve(virtual_path)
            return os.path.isfile(real)
        except PermissionError:
            return False

    def listdir(self, virtual_path=".", show_hidden=False, long_format=False):
        """List contents of a directory."""
        try:
            real = self.resolve(virtual_path)
        except PermissionError as e:
            sandbox_violation(str(e))
            return

        if not os.path.isdir(real):
            error_msg(f"'{virtual_path}': Not a directory")
            return

        try:
            entries = sorted(os.listdir(real))
        except OSError as e:
            error_msg(str(e))
            return

        if not show_hidden:
            entries = [e for e in entries if not e.startswith(".")]

        if not entries:
            return

        if long_format:
            self._list_long(real, entries)
        else:
            self._list_short(real, entries)

    def _list_short(self, real_dir, entries):
        """Short listing (names only, colored by type)."""
        output = []
        for entry in entries:
            full = os.path.join(real_dir, entry)
            if os.path.isdir(full):
                output.append(blue(entry + "/", bold=True))
            elif os.access(full, os.X_OK):
                output.append(green(entry, bold=True))
            else:
                output.append(entry)

        # Print in columns
        term_width = os.get_terminal_size().columns if hasattr(os, 'get_terminal_size') else 80
        max_len = max((len(entry) for entry in entries), default=0) + 4
        cols = max(1, term_width // max_len)

        for i in range(0, len(output), cols):
            row = output[i:i + cols]
            # Pad with raw length for alignment
            line = ""
            for j, item in enumerate(row):
                raw_name = entries[i + j]
                padding = max_len - len(raw_name) - (1 if os.path.isdir(os.path.join(real_dir, raw_name)) else 0)
                line += item + " " * padding
            print(line)

    def _list_long(self, real_dir, entries):
        """Long listing with permissions, size, date."""
        for entry in entries:
            full = os.path.join(real_dir, entry)
            try:
                st = os.stat(full)
                is_dir = stat.S_ISDIR(st.st_mode)
                perms = ("d" if is_dir else "-") + format_permissions(st.st_mode)
                size = format_size(st.st_size) if not is_dir else "-"
                mtime = format_time(st.st_mtime)

                if is_dir:
                    name = blue(entry + "/", bold=True)
                elif os.access(full, os.X_OK):
                    name = green(entry, bold=True)
                else:
                    name = entry

                print(f"{dim(perms)}  {size:>6s}  {dim(mtime)}  {name}")
            except OSError:
                print(f"  ???  {entry}")

    def cat(self, virtual_path):
        """Read and return the contents of a file."""
        try:
            real = self.resolve(virtual_path)
        except PermissionError as e:
            sandbox_violation(str(e))
            return None

        if not os.path.exists(real):
            error_msg(f"'{virtual_path}': No such file")
            return None

        if os.path.isdir(real):
            error_msg(f"'{virtual_path}': Is a directory")
            return None

        try:
            with open(real, "r", errors="replace") as f:
                content = f.read()
            return content
        except OSError as e:
            error_msg(str(e))
            return None

    def write_file(self, virtual_path, content, append=False):
        """Write content to a file in the sandbox."""
        try:
            real = self.resolve(virtual_path)
        except PermissionError as e:
            sandbox_violation(str(e))
            return False

        # Check file size limit
        if len(content.encode("utf-8", errors="replace")) > MAX_FILE_SIZE:
            error_msg(f"Content exceeds maximum file size ({format_size(MAX_FILE_SIZE)})")
            return False

        # Ensure parent directory exists
        parent = os.path.dirname(real)
        if not os.path.exists(parent):
            error_msg(f"Parent directory does not exist")
            return False

        try:
            mode = "a" if append else "w"
            with open(real, mode) as f:
                f.write(content)
            return True
        except OSError as e:
            error_msg(str(e))
            return False

    def mkdir(self, virtual_path, parents=False):
        """Create a directory in the sandbox."""
        try:
            real = self.resolve(virtual_path)
        except PermissionError as e:
            sandbox_violation(str(e))
            return False

        if os.path.exists(real):
            error_msg(f"'{virtual_path}': Already exists")
            return False

        try:
            if parents:
                os.makedirs(real, exist_ok=True)
            else:
                parent = os.path.dirname(real)
                if not os.path.exists(parent):
                    error_msg(f"Parent directory does not exist (use -p for recursive)")
                    return False
                os.mkdir(real)
            return True
        except OSError as e:
            error_msg(str(e))
            return False

    def touch(self, virtual_path):
        """Create an empty file or update its timestamp."""
        try:
            real = self.resolve(virtual_path)
        except PermissionError as e:
            sandbox_violation(str(e))
            return False

        parent = os.path.dirname(real)
        if not os.path.exists(parent):
            error_msg(f"Parent directory does not exist")
            return False

        try:
            with open(real, "a"):
                os.utime(real, None)
            return True
        except OSError as e:
            error_msg(str(e))
            return False

    def rm(self, virtual_path, recursive=False):
        """Remove a file or directory."""
        try:
            real = self.resolve(virtual_path)
        except PermissionError as e:
            sandbox_violation(str(e))
            return False

        if not os.path.exists(real):
            error_msg(f"'{virtual_path}': No such file or directory")
            return False

        # Prevent deleting sandbox root
        if os.path.realpath(real) == self.root:
            sandbox_violation("Cannot delete sandbox root")
            return False

        try:
            if os.path.isdir(real):
                if not recursive:
                    error_msg(f"'{virtual_path}': Is a directory (use -r for recursive)")
                    return False
                shutil.rmtree(real)
            else:
                os.remove(real)
            return True
        except OSError as e:
            error_msg(str(e))
            return False

    def cp(self, src_path, dst_path, recursive=False):
        """Copy a file or directory within the sandbox."""
        try:
            real_src = self.resolve(src_path)
            real_dst = self.resolve(dst_path)
        except PermissionError as e:
            sandbox_violation(str(e))
            return False

        if not os.path.exists(real_src):
            error_msg(f"'{src_path}': No such file or directory")
            return False

        try:
            if os.path.isdir(real_src):
                if not recursive:
                    error_msg(f"'{src_path}': Is a directory (use -r for recursive)")
                    return False
                if os.path.exists(real_dst):
                    # Copy into existing directory
                    dst_name = os.path.join(real_dst, os.path.basename(real_src))
                    shutil.copytree(real_src, dst_name)
                else:
                    shutil.copytree(real_src, real_dst)
            else:
                if os.path.isdir(real_dst):
                    real_dst = os.path.join(real_dst, os.path.basename(real_src))
                shutil.copy2(real_src, real_dst)
            return True
        except OSError as e:
            error_msg(str(e))
            return False

    def mv(self, src_path, dst_path):
        """Move/rename a file or directory within the sandbox."""
        try:
            real_src = self.resolve(src_path)
            real_dst = self.resolve(dst_path)
        except PermissionError as e:
            sandbox_violation(str(e))
            return False

        if not os.path.exists(real_src):
            error_msg(f"'{src_path}': No such file or directory")
            return False

        try:
            if os.path.isdir(real_dst):
                real_dst = os.path.join(real_dst, os.path.basename(real_src))
            shutil.move(real_src, real_dst)
            return True
        except OSError as e:
            error_msg(str(e))
            return False

    def cd(self, virtual_path):
        """Change the virtual current working directory."""
        if not virtual_path:
            self.cwd = "/home/agent"
            return True

        try:
            real = self.resolve(virtual_path)
        except PermissionError as e:
            sandbox_violation(str(e))
            return False

        if not os.path.exists(real):
            error_msg(f"'{virtual_path}': No such directory")
            return False

        if not os.path.isdir(real):
            error_msg(f"'{virtual_path}': Not a directory")
            return False

        self.cwd = self.to_virtual(real)
        return True

    def tree(self, virtual_path=".", max_depth=3, _prefix="", _depth=0):
        """Display a tree view of the directory structure."""
        if _depth > max_depth:
            return

        try:
            real = self.resolve(virtual_path)
        except PermissionError as e:
            sandbox_violation(str(e))
            return

        if not os.path.isdir(real):
            error_msg(f"'{virtual_path}': Not a directory")
            return

        if _depth == 0:
            print(blue(virtual_path, bold=True))

        try:
            entries = sorted(os.listdir(real))
            entries = [e for e in entries if not e.startswith(".")]
        except OSError:
            return

        for i, entry in enumerate(entries):
            is_last = (i == len(entries) - 1)
            connector = "└── " if is_last else "├── "
            full_path = os.path.join(real, entry)

            if os.path.isdir(full_path):
                print(f"{_prefix}{connector}{blue(entry + '/', bold=True)}")
                extension = "    " if is_last else "│   "
                vpath = os.path.join(virtual_path, entry) if virtual_path != "." else entry
                self.tree(vpath, max_depth, _prefix + extension, _depth + 1)
            else:
                print(f"{_prefix}{connector}{entry}")

    def find(self, virtual_path=".", pattern="*", find_type=None):
        """Find files/dirs matching a pattern."""
        results = []
        try:
            real = self.resolve(virtual_path)
        except PermissionError as e:
            sandbox_violation(str(e))
            return results

        for dirpath, dirnames, filenames in os.walk(real):
            if find_type != "f":
                for d in dirnames:
                    if fnmatch.fnmatch(d, pattern):
                        full = os.path.join(dirpath, d)
                        results.append(self.to_virtual(full))
            if find_type != "d":
                for f in filenames:
                    if fnmatch.fnmatch(f, pattern):
                        full = os.path.join(dirpath, f)
                        results.append(self.to_virtual(full))

        return sorted(results)

    def head(self, virtual_path, n=10):
        """Read the first n lines of a file."""
        content = self.cat(virtual_path)
        if content is None:
            return None
        lines = content.splitlines()
        return "\n".join(lines[:n])

    def tail(self, virtual_path, n=10):
        """Read the last n lines of a file."""
        content = self.cat(virtual_path)
        if content is None:
            return None
        lines = content.splitlines()
        return "\n".join(lines[-n:])

    def wc(self, virtual_path):
        """Count lines, words, and characters in a file."""
        content = self.cat(virtual_path)
        if content is None:
            return None
        lines = content.count("\n")
        words = len(content.split())
        chars = len(content)
        return lines, words, chars

    def get_size(self, virtual_path):
        """Get file/directory size in bytes."""
        try:
            real = self.resolve(virtual_path)
        except PermissionError:
            return 0

        if os.path.isfile(real):
            return os.path.getsize(real)
        elif os.path.isdir(real):
            total = 0
            for dirpath, dirnames, filenames in os.walk(real):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    try:
                        total += os.path.getsize(fp)
                    except OSError:
                        pass
            return total
        return 0

    def disk_usage(self):
        """Get total sandbox disk usage."""
        total = self.get_size("/")
        return total

    def file_count(self):
        """Count total files in sandbox."""
        count = 0
        for dirpath, dirnames, filenames in os.walk(self.root):
            count += len(filenames)
        return count

    def chmod(self, virtual_path, mode_str):
        """Change file permissions (simplified — octal string like '755')."""
        try:
            real = self.resolve(virtual_path)
        except PermissionError as e:
            sandbox_violation(str(e))
            return False

        if not os.path.exists(real):
            error_msg(f"'{virtual_path}': No such file or directory")
            return False

        try:
            mode = int(mode_str, 8)
            os.chmod(real, mode)
            return True
        except (ValueError, OSError) as e:
            error_msg(str(e))
            return False

    def stat_file(self, virtual_path):
        """Get detailed file information."""
        try:
            real = self.resolve(virtual_path)
        except PermissionError as e:
            sandbox_violation(str(e))
            return None

        if not os.path.exists(real):
            error_msg(f"'{virtual_path}': No such file or directory")
            return None

        try:
            st = os.stat(real)
            return {
                "name": os.path.basename(real),
                "virtual_path": self.to_virtual(real),
                "type": "directory" if stat.S_ISDIR(st.st_mode) else "file",
                "size": st.st_size,
                "permissions": format_permissions(st.st_mode),
                "modified": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(),
                "created": datetime.datetime.fromtimestamp(st.st_ctime).isoformat(),
            }
        except OSError as e:
            error_msg(str(e))
            return None
