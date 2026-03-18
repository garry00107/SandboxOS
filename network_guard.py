"""
SandboxOS — Network Guard.

Monkey-patches Python's networking modules to prevent AI agents
from making any network connections. All socket, HTTP, and URL
operations are blocked when this module is activated.
"""

import sys


class NetworkBlockedError(PermissionError):
    """Raised when a blocked network operation is attempted."""

    def __init__(self, operation="network access"):
        super().__init__(
            f"🛡️  SandboxOS: {operation} is BLOCKED. "
            f"Network access is disabled in this sandbox."
        )


class FakeSocket:
    """A fake socket that raises errors on any operation."""

    def __init__(self, *args, **kwargs):
        raise NetworkBlockedError("socket creation")

    def __getattr__(self, name):
        raise NetworkBlockedError(f"socket.{name}")


class NetworkGuard:
    """
    Patches Python networking modules to block all external access.
    """

    def __init__(self):
        self.active = False
        self._originals = {}

    def activate(self):
        """Activate network blocking by monkey-patching networking modules."""
        if self.active:
            return

        import socket

        # Save originals
        self._originals["socket_class"] = socket.socket
        self._originals["socket_create_connection"] = socket.create_connection
        self._originals["socket_getaddrinfo"] = socket.getaddrinfo

        # Patch socket module
        socket.socket = FakeSocket
        socket.create_connection = self._blocked("socket.create_connection")
        socket.getaddrinfo = self._blocked("socket.getaddrinfo")

        # Patch urllib
        try:
            import urllib.request
            self._originals["urlopen"] = urllib.request.urlopen
            urllib.request.urlopen = self._blocked("urllib.request.urlopen")
        except ImportError:
            pass

        # Patch http.client
        try:
            import http.client
            self._originals["http_connect"] = http.client.HTTPConnection.connect
            self._originals["https_connect"] = http.client.HTTPSConnection.connect
            http.client.HTTPConnection.connect = self._blocked_method("HTTPConnection.connect")
            http.client.HTTPSConnection.connect = self._blocked_method("HTTPSConnection.connect")
        except ImportError:
            pass

        # Block requests if imported
        if "requests" in sys.modules:
            import requests
            self._originals["requests_get"] = requests.get
            self._originals["requests_post"] = requests.post
            self._originals["requests_put"] = requests.put
            self._originals["requests_delete"] = requests.delete
            self._originals["requests_session_send"] = requests.Session.send

            requests.get = self._blocked("requests.get")
            requests.post = self._blocked("requests.post")
            requests.put = self._blocked("requests.put")
            requests.delete = self._blocked("requests.delete")
            requests.Session.send = self._blocked_method("requests.Session.send")

        # Block httpx if imported
        if "httpx" in sys.modules:
            import httpx
            self._originals["httpx_get"] = httpx.get
            self._originals["httpx_post"] = httpx.post
            httpx.get = self._blocked("httpx.get")
            httpx.post = self._blocked("httpx.post")

        # Block aiohttp if imported
        if "aiohttp" in sys.modules:
            import aiohttp
            self._originals["aiohttp_session"] = aiohttp.ClientSession
            aiohttp.ClientSession = self._blocked("aiohttp.ClientSession")

        self.active = True

    def deactivate(self):
        """Restore original networking modules (use with caution)."""
        if not self.active:
            return

        import socket
        socket.socket = self._originals.get("socket_class", socket.socket)
        socket.create_connection = self._originals.get(
            "socket_create_connection", socket.create_connection
        )
        socket.getaddrinfo = self._originals.get(
            "socket_getaddrinfo", socket.getaddrinfo
        )

        try:
            import urllib.request
            if "urlopen" in self._originals:
                urllib.request.urlopen = self._originals["urlopen"]
        except ImportError:
            pass

        try:
            import http.client
            if "http_connect" in self._originals:
                http.client.HTTPConnection.connect = self._originals["http_connect"]
            if "https_connect" in self._originals:
                http.client.HTTPSConnection.connect = self._originals["https_connect"]
        except ImportError:
            pass

        self.active = False
        self._originals.clear()

    def _blocked(self, name):
        """Return a function that raises NetworkBlockedError."""
        def blocked_fn(*args, **kwargs):
            raise NetworkBlockedError(name)
        blocked_fn.__name__ = f"blocked_{name}"
        return blocked_fn

    def _blocked_method(self, name):
        """Return a method that raises NetworkBlockedError."""
        def blocked_method(self_arg, *args, **kwargs):
            raise NetworkBlockedError(name)
        blocked_method.__name__ = f"blocked_{name}"
        return blocked_method

    @property
    def status(self):
        """Return current guard status."""
        return "ACTIVE — all network access blocked" if self.active else "INACTIVE"
