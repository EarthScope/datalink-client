"""Shared, transport-independent state and config for DataLink clients.

Both :class:`~datalink_client.client.DataLink` (sockets) and
:class:`~datalink_client.aio.AsyncDataLink` (asyncio) subclass
:class:`_DataLinkBase` for everything that doesn't touch a connection:
host/port/TLS configuration, ``from_server_string``, ``__repr__``, and the
server identity state recorded by ``identify()``.
"""

from __future__ import annotations

from .protocol import parse_capabilities


class _DataLinkBase:
    """Transport-independent config and state shared by both DataLink clients."""

    TLS_PORT = 16500

    def __init__(
        self,
        host: str = "localhost",
        port: int = 16000,
        timeout: float | None = None,
        tls: bool | None = None,
        tls_noverify: bool = False,
    ):
        self._host = host
        self._port = port
        self._timeout = timeout
        self._tls = tls if tls is not None else (port == self.TLS_PORT)
        self._tls_noverify = tls_noverify
        self._streaming = False
        self.server_id: str | None = None
        self.server_capabilities: dict[str, str | bool] = {}

    @classmethod
    def from_server_string(
        cls,
        server: str,
        timeout: float | None = None,
        tls: bool | None = None,
        tls_noverify: bool = False,
    ):
        """Create a client from a server string (host:port, host@port, host, or '').

        ``host@port`` is an unambiguous alternative to ``host:port`` for use
        with a bare IPv6 host, which cannot otherwise be told apart from the
        ``:port`` suffix; ``[host]:port`` bracket notation works too.
        """
        def _parse_port(text: str) -> int:
            try:
                port = int(text)
            except ValueError:
                raise ValueError(f"Invalid port in server string: {server!r}") from None
            if not 1 <= port <= 65535:
                raise ValueError(f"Port out of range in server string: {server!r}")
            return port

        host = "localhost"
        port = 16000
        server = server.strip()
        if server:
            if server.startswith("["):
                bracket_end = server.find("]")
                if bracket_end < 0:
                    raise ValueError(
                        f"Missing closing bracket in server string: {server!r}"
                    )
                host = server[1:bracket_end] or "localhost"
                remainder = server[bracket_end + 1 :]
                if remainder.startswith(":") and remainder[1:]:
                    port = _parse_port(remainder[1:])
            elif "@" in server:
                # host@port: split on the last '@' only, so a host containing
                # '@' before this point is preserved rather than mangled.
                head, _, tail = server.rpartition("@")
                host = head or "localhost"
                if tail:
                    port = _parse_port(tail)
            elif server.count(":") > 1:
                # A bare IPv6 literal (2+ colons) can't be split from a port
                # suffix unambiguously; require bracket or '@' notation.
                raise ValueError(
                    f"Ambiguous server string {server!r}; use '[host]:port' or "
                    "'host@port' for a bare IPv6 address"
                )
            else:
                parts = server.rsplit(":", 1)
                host = parts[0] or "localhost"
                if len(parts) == 2 and parts[1]:
                    port = _parse_port(parts[1])
        return cls(host, port, timeout=timeout, tls=tls, tls_noverify=tls_noverify)

    @property
    def is_connected(self) -> bool:
        """Whether the transport currently holds an open connection.

        Each transport overrides this: the sync client checks ``_sock``, the
        async client checks its ``_writer``.
        """
        raise NotImplementedError

    @property
    def is_streaming(self) -> bool:
        return self._streaming

    def __repr__(self) -> str:
        state = "connected" if self.is_connected else "disconnected"
        tls = ", tls" if self._tls else ""
        return f"{type(self).__name__}({self._host!r}, {self._port}, {state}{tls})"

    def _store_identity(self, raw: str) -> str:
        """Record a server ID reply's raw string and parsed capabilities."""
        self.server_id = raw
        self.server_capabilities = parse_capabilities(raw)
        return raw
