"""DataLink protocol 1.1 client (query and streaming modes), socket transport."""

from __future__ import annotations

import contextlib
import logging
import socket
import ssl
import time
import warnings
from collections.abc import Generator
from typing import Any, Literal, overload

from . import _commands as commands
from ._base import _DataLinkBase
from ._commands import TIME_UNSET_VALUE, Command
from .protocol import (
    BufferLike,
    DataLinkError,
    DataLinkPacket,
    DataLinkResponse,
    DataLinkTimeout,
    PREHEADER_LEN,
    StreamEvent,
    classify_stream_packet,
    encode_frame,
    expect_ok,
    expected_payload_size,
    generate_client_id,
    parse_info_xml,
    parse_packet,
    parse_response,
    validate_preheader_magic,
)

logger = logging.getLogger(__name__)

# Default/minimum size of the persistent receive buffer. It grows to fit an
# oversized payload but is released back to this size once drained, so one
# large packet doesn't pin that memory for the life of the connection.
_RECV_BUF_SIZE = 65536


class DataLink(_DataLinkBase):
    """DataLink protocol 1.1 client for query and streaming modes.

    Supports all DataLink 1.1 client commands: ID, AUTH (USERPASS/JWT),
    POSITION SET/AFTER, MATCH, REJECT, WRITE, READ, STREAM, ENDSTREAM, and INFO.

    The connection starts in query mode. Call :meth:`stream` to enter streaming
    mode, and :meth:`endstream` to return to query mode.

    For asyncio-based use, see :class:`~datalink_client.aio.AsyncDataLink`,
    which offers the same API as coroutines.

    Args:
        host:       Server hostname or IP address.
        port:       Server TCP port (typically 16000, or 16500 for TLS).
        timeout:    Optional socket timeout in seconds. None means block indefinitely.
        tls:        Enable TLS encryption. If None (default), TLS is auto-enabled
                    when port is 16500.
        tls_noverify: If True, disable TLS certificate verification (insecure;
                      useful for self-signed certificates or testing).

    Attributes:
        server_id:           Raw server ID string after calling :meth:`identify`, or None.
        server_capabilities: Dict of server capabilities parsed from the ID reply.
                             Keys with values are stored as strings (e.g. ``{'DLPROTO': '1.0'}``).
                             Keys without values are stored as ``True`` (e.g. ``{'WRITE': True}``).
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 16000,
        timeout: float | None = None,
        tls: bool | None = None,
        tls_noverify: bool = False,
    ):
        super().__init__(host, port, timeout=timeout, tls=tls, tls_noverify=tls_noverify)
        self._sock: socket.socket | None = None
        self._use_sendmsg = False
        self._write_buf: bytearray | None = None
        self._batch_max: int | None = None
        self._recv_buf = bytearray(_RECV_BUF_SIZE)
        self._recv_view = memoryview(self._recv_buf)
        self._recv_start = 0
        self._recv_end = 0

    @property
    def is_connected(self) -> bool:
        return self._sock is not None

    @property
    def has_buffered_data(self) -> bool:
        """Whether a full frame may be readable without a blocking socket call.

        True if bytes already sit in the internal receive buffer, or (for a
        TLS socket) in the SSL layer's own decrypted-but-unread buffer.
        ``select()``/``poll()`` on the raw socket only reports on-wire data,
        so a caller multiplexing this client's socket with other input
        (e.g. the CLI's ``STREAM`` command) should drain while this is true
        before waiting on ``select()`` again.
        """
        if self._recv_end > self._recv_start:
            return True
        return isinstance(self._sock, ssl.SSLSocket) and self._sock.pending() > 0

    def _reset_recv_buf(self) -> None:
        """Release an oversized receive buffer back to its default capacity."""
        if len(self._recv_buf) > _RECV_BUF_SIZE:
            self._recv_buf = bytearray(_RECV_BUF_SIZE)
            self._recv_view = memoryview(self._recv_buf)
        self._recv_start = 0
        self._recv_end = 0

    def connect(self) -> None:
        """Open TCP connection to the DataLink server, optionally with TLS."""
        if self._sock is not None:
            raise DataLinkError("Already connected")
        infos = socket.getaddrinfo(
            self._host, self._port, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        if not infos:
            raise DataLinkError(f"Could not resolve address: {self._host}:{self._port}")
        last_err: OSError | None = None
        for af, socktype, proto, _canonname, sockaddr in infos:
            sock: socket.socket | None = None
            try:
                sock = socket.socket(af, socktype, proto)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                if self._timeout is not None:
                    sock.settimeout(self._timeout)
                sock.connect(sockaddr)
                if self._tls:
                    context = ssl.create_default_context()
                    if self._tls_noverify:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=self._host)
                self._sock = sock
                self._use_sendmsg = not self._tls and hasattr(sock, "sendmsg")
                self._reset_recv_buf()
                sock = None  # ownership transferred to self._sock
                break
            except ssl.SSLCertVerificationError as e:
                raise DataLinkError(
                    f"TLS certificate verification failed for "
                    f"{self._host}:{self._port}: {e.verify_message}. "
                    f"Use tls_noverify=True to skip verification "
                    f"(insecure, e.g. for self-signed certificates)"
                ) from e
            except OSError as e:
                last_err = e
            finally:
                # Closes the socket on any failure, including one this loop
                # doesn't otherwise handle (e.g. a non-OSError from wrap_socket).
                if sock is not None:
                    sock.close()
        else:
            raise DataLinkError(
                f"Could not connect to {self._host}:{self._port}"
            ) from last_err
        logger.debug("Connected to %s:%d%s", self._host, self._port, " (TLS)" if self._tls else "")

    def close(self) -> None:
        """Gracefully close the connection."""
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                try:
                    self._sock.close()
                finally:
                    self._sock = None
        self._streaming = False
        self._use_sendmsg = False
        self._write_buf = None
        self._batch_max = None
        self._reset_recv_buf()

    def reconnect(self) -> None:
        """Close the current connection (if any) and open a fresh one."""
        self.close()
        self.connect()

    def begin_batch(self, max_bytes: int | None = None) -> None:
        """Enable write buffering. Packets are queued until :meth:`flush` is called.

        Calling this while already batching is a no-op that preserves what's
        already queued (it previously discarded the buffer and any packets
        in it).

        Args:
            max_bytes: If set, the buffer is sent to the wire (without
                ending the batch) whenever it reaches this many bytes, so a
                long batch doesn't grow unbounded between explicit flushes.
        """
        if self._write_buf is None:
            self._write_buf = bytearray()
        self._batch_max = max_bytes

    def _send_bytes(self, buf: bytearray) -> None:
        """Send already-framed bytes to the wire, closing on failure."""
        if not buf:
            return
        if self._sock is None:
            raise DataLinkError(f"Not connected; discarding {len(buf)} buffered bytes")
        try:
            self._sock.sendall(buf)
        except OSError as e:
            self.close()
            raise DataLinkError(f"flush failed: {e}") from e

    def flush(self) -> None:
        """Send all buffered packets and disable buffering.

        Raises:
            DataLinkError: if not connected and packets were buffered (they
                are discarded, since there is nowhere left to send them).
        """
        if self._write_buf is None:
            return
        buf = self._write_buf
        self._write_buf = None
        self._batch_max = None
        self._send_bytes(buf)

    @contextlib.contextmanager
    def batch(self, max_bytes: int | None = None):
        """Context manager for batched writes.

        Usage::

            with dl.batch():
                for record in records:
                    dl.write(streamid, start, end, record)
            # flush() is called automatically on exit

        Args:
            max_bytes: see :meth:`begin_batch`.
        """
        self.begin_batch(max_bytes)
        try:
            yield
        finally:
            self.flush()

    def __enter__(self) -> DataLink:
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    # -- Byte-level transport -----------------------------------------------

    def _recv_all(self, n: int) -> bytes:
        if self._sock is None:
            raise DataLinkError("Not connected")

        # Fast path: buffer already holds enough data.
        available = self._recv_end - self._recv_start
        if available >= n:
            data = bytes(self._recv_view[self._recv_start:self._recv_start + n])
            self._recv_start += n
            return data

        # Buffer is drained and not needed at its current (grown) size: reclaim
        # the capacity from an earlier oversized payload before refilling.
        if available == 0 and n <= _RECV_BUF_SIZE:
            self._reset_recv_buf()

        # Grow the persistent buffer if n exceeds its capacity (rare for large payloads).
        if n > len(self._recv_buf):
            new_size = max(n, len(self._recv_buf) * 2)
            new_buf = bytearray(new_size)
            if available > 0:
                new_buf[:available] = self._recv_buf[self._recv_start:self._recv_end]
            self._recv_buf = new_buf
            self._recv_view = memoryview(self._recv_buf)
            self._recv_start = 0
            self._recv_end = available
        elif len(self._recv_buf) - self._recv_start < n:
            # Available bytes plus remaining tail room are not enough for n; compact to front.
            if available > 0:
                self._recv_buf[:available] = self._recv_buf[self._recv_start:self._recv_end]
            self._recv_start = 0
            self._recv_end = available

        # Fill from the socket until we have n bytes.
        while self._recv_end - self._recv_start < n:
            try:
                chunk = self._sock.recv_into(self._recv_view[self._recv_end:])
            except socket.timeout as e:
                partial = self._recv_end - self._recv_start
                if partial > 0:
                    self.close()
                    raise DataLinkTimeout(
                        f"Timeout after partial read ({partial}/{n} bytes); "
                        "connection closed"
                    ) from e
                raise DataLinkTimeout(f"Timed out waiting for {n} bytes") from e
            except OSError as e:
                self.close()
                raise DataLinkError(f"recv failed: {e}") from e
            if not chunk:
                self.close()
                raise DataLinkError("Connection closed")
            self._recv_end += chunk

        data = bytes(self._recv_view[self._recv_start:self._recv_start + n])
        self._recv_start += n
        return data

    def _send_packet(self, header: str, data: BufferLike | None = None) -> None:
        if self._sock is None:
            raise DataLinkError("Not connected")
        frame = encode_frame(header)
        if self._write_buf is not None:
            self._write_buf.extend(frame)
            if data is not None:
                self._write_buf.extend(data)
            if self._batch_max is not None and len(self._write_buf) >= self._batch_max:
                self._send_bytes(self._write_buf)
                del self._write_buf[:]
            return
        try:
            if self._use_sendmsg:
                if data is None:
                    self._sendmsg_all([frame])
                else:
                    self._sendmsg_all([frame, data])
            else:
                if data is None:
                    self._sock.sendall(frame)
                elif isinstance(data, memoryview):
                    self._sock.sendall(frame)
                    self._sock.sendall(data)
                else:
                    self._sock.sendall(frame + data)
        except OSError as e:
            self.close()
            raise DataLinkError(f"send failed: {e}") from e

    def _sendmsg_all(self, buffers: list[BufferLike]) -> None:
        """Send all buffers via sendmsg, looping to handle short/partial sends.

        Unlike ``sendall``, ``sendmsg`` is a single syscall that may transfer
        fewer bytes than requested (e.g. under a socket timeout, or when
        interrupted by a signal per PEP 475). This loops until every buffer is
        fully sent, so the peer never sees a truncated frame.
        """
        views = [memoryview(b).cast("B") for b in buffers if len(b)]
        while views:
            # Pass a snapshot: `views` is mutated below as buffers are
            # consumed, and callers (real sockets and test doubles alike)
            # may retain the list reference they were given.
            sent = self._sock.sendmsg(list(views))
            if sent <= 0:
                self.close()
                raise DataLinkError("send failed: socket accepted 0 bytes")
            while views and sent >= views[0].nbytes:
                sent -= views[0].nbytes
                views.pop(0)
            if views and sent:
                views[0] = views[0][sent:]

    def _recv_packet(self) -> tuple[str, bytes | None]:
        if self._sock is None:
            raise DataLinkError("Not connected")
        pre = self._recv_all(PREHEADER_LEN)
        try:
            validate_preheader_magic(pre)
        except DataLinkError as e:
            self.close()
            raise DataLinkError(f"{e} Connection closed.") from e
        header_len = pre[2]
        header_bytes = self._recv_all(header_len)
        try:
            header = header_bytes.decode("ascii")
        except UnicodeDecodeError as e:
            self.close()
            raise DataLinkError(f"Header is not ASCII: {header_bytes!r} Connection closed.") from e
        try:
            data_size = expected_payload_size(header)
        except DataLinkError as e:
            self.close()
            raise DataLinkError(f"{e} Connection closed.") from e
        data: bytes | None = None
        if data_size > 0:
            data = self._recv_all(data_size)
        return header, data

    # -- Pure parsing, exposed as DataLink methods; protocol.py owns the ----
    # -- implementation and AsyncDataLink shares the same functions ---------

    _parse_response = staticmethod(parse_response)
    _expect_ok = staticmethod(expect_ok)
    _parse_packet = staticmethod(parse_packet)
    _parse_info_xml = staticmethod(parse_info_xml)
    _generate_client_id = staticmethod(generate_client_id)

    # -- Command dispatch -----------------------------------------------------

    def _execute(self, cmd: Command) -> Any:
        """Send a Command's request and, if it expects a reply, parse it.

        This is the only place command dispatch differs from
        :class:`~datalink_client.aio.AsyncDataLink`: everything about what
        to send and how to interpret the reply lives in ``cmd`` itself.
        """
        # A reply-expecting command can't be queued behind batched writes:
        # there would be nothing on the wire yet for the server to reply to.
        if cmd.parse is not None and self._write_buf is not None:
            self.flush()
        self._send_packet(cmd.header, cmd.payload)
        if cmd.parse is None:
            return None
        header, data = self._recv_packet()
        return cmd.parse(header, data)

    def identify(self, clientid: str | None = None) -> str:
        """Exchange identification with the server and return the server ID string."""
        cid = generate_client_id(clientid)
        raw = self._execute(commands.identify(cid))
        return self._store_identity(raw)

    def auth_userpass(self, username: str, password: str) -> DataLinkResponse:
        return self._execute(commands.auth_userpass(username, password))

    def auth_jwt(self, token: str) -> DataLinkResponse:
        return self._execute(commands.auth_jwt(token))

    def position_set(
        self,
        pktid: str | int,
        uspkttime: int | str = TIME_UNSET_VALUE,
    ) -> DataLinkResponse:
        return self._execute(commands.position_set(pktid, uspkttime))

    def position_after(self, ustime: int | str) -> DataLinkResponse:
        return self._execute(commands.position_after(ustime))

    def set_position_latest(self) -> int:
        """Set the read position to the latest packet and return its ID.

        Calls ``POSITION SET LATEST`` on the server and returns the resulting
        packet ID.  Use this before calling :meth:`stream` when you only want
        packets that arrive after this call.

        Returns:
            The current latest packet ID.
        """
        resp = self.position_set("LATEST")
        return resp.value

    def last_pktid(self) -> int:
        """Deprecated alias for :meth:`set_position_latest`.

        .. deprecated::
            Renamed to ``set_position_latest()`` to make the side effect
            explicit.  ``last_pktid()`` will be removed in a future release.
        """
        warnings.warn(
            "last_pktid() is deprecated and will be removed in a future release; "
            "use set_position_latest() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.set_position_latest()

    def match(self, pattern: str) -> DataLinkResponse:
        return self._execute(commands.match(pattern))

    def reject(self, pattern: str) -> DataLinkResponse:
        return self._execute(commands.reject(pattern))

    @overload
    def write(
        self,
        streamid: str,
        datastart: int,
        dataend: int,
        data: BufferLike,
        ack: Literal[True],
        pktid: int | None = ...,
    ) -> DataLinkResponse: ...

    @overload
    def write(
        self,
        streamid: str,
        datastart: int,
        dataend: int,
        data: BufferLike,
        ack: Literal[False] = ...,
        pktid: int | None = ...,
    ) -> None: ...

    def write(
        self,
        streamid: str,
        datastart: int,
        dataend: int,
        data: BufferLike,
        ack: bool = False,
        pktid: int | None = None,
    ) -> DataLinkResponse | None:
        return self._execute(
            commands.write(streamid, datastart, dataend, data, ack=ack, pktid=pktid)
        )

    def read(self, pktid: int) -> DataLinkPacket:
        return self._execute(commands.read(pktid))

    def bye(self) -> None:
        """Send a BYE command to gracefully notify the server before disconnecting."""
        self._execute(commands.bye())

    def stream(self) -> None:
        self._execute(commands.stream())
        self._streaming = True

    def endstream(self, timeout: float | None = None) -> None:
        if timeout is None:
            timeout = self._timeout if self._timeout is not None else 30.0
        deadline = time.monotonic() + timeout
        self._send_packet("ENDSTREAM")
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DataLinkTimeout(
                    f"Timed out after {timeout:.1f}s waiting for ENDSTREAM confirmation"
                )
            prev_timeout = self._sock.gettimeout() if self._sock else None
            try:
                if self._sock is not None:
                    self._sock.settimeout(remaining)
                header, _ = self._recv_packet()
            except socket.timeout as e:
                raise DataLinkTimeout(
                    f"Timed out after {timeout:.1f}s waiting for ENDSTREAM confirmation"
                ) from e
            finally:
                if self._sock is not None:
                    self._sock.settimeout(prev_timeout)
            event = classify_stream_packet(header)
            if event is StreamEvent.ENDSTREAM:
                self._streaming = False
                return
            if event is StreamEvent.PACKET:
                continue
            if event is StreamEvent.ERROR:
                resp = parse_response(header, _)
                raise DataLinkError(resp.message or "ENDSTREAM failed", resp.value)
            logger.debug("Draining unexpected packet during ENDSTREAM: %s", header[:80])

    def info(self, info_type: str, match: str | None = None) -> str:
        return self._execute(commands.info(info_type, match))

    def info_status(self, match: str | None = None) -> dict[str, Any]:
        return parse_info_xml(self.info("STATUS", match=match))

    def info_streams(self, match: str | None = None) -> dict[str, Any]:
        return parse_info_xml(self.info("STREAMS", match=match))

    def info_connections(self, match: str | None = None) -> dict[str, Any]:
        return parse_info_xml(self.info("CONNECTIONS", match=match))

    def collect(self) -> Generator[DataLinkPacket, None, None]:
        """Streaming generator: yields DataLinkPacket for each received PACKET.

        Abandoning iteration early (``break``, an exception, or simply not
        exhausting the generator) leaves the connection in streaming mode on
        the server. Call :meth:`endstream` when done, or wrap the loop in
        ``contextlib.closing(dl.collect())`` to send ENDSTREAM automatically.
        """
        while True:
            header, data = self._recv_packet()
            event = classify_stream_packet(header)
            if event is StreamEvent.ENDSTREAM:
                self._streaming = False
                return
            if event is StreamEvent.PACKET:
                try:
                    pkt = parse_packet(header, data)
                except DataLinkError as e:
                    self.close()
                    raise DataLinkError(
                        f"Invalid PACKET in stream (connection closed): {header[:80]} — {e}"
                    ) from e
                yield pkt
                continue
            if event is StreamEvent.ERROR:
                resp = parse_response(header, data)
                raise DataLinkError(resp.message or "Stream error", resp.value)
            logger.debug("Unexpected packet in stream: %s", header[:80])
