"""DataLink protocol 1.1 client (query and streaming modes), asyncio transport.

Mirrors :class:`~datalink_client.client.DataLink`'s API as coroutines, sharing
its protocol logic entirely via :mod:`datalink_client.protocol` and
:mod:`datalink_client._commands`. See :class:`DataLink` for the full command
reference; this module's docstrings cover only what's transport-specific.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import ssl
import time
from collections.abc import AsyncGenerator
from typing import Any, Literal, overload

from . import _commands as commands
from ._base import _DataLinkBase
from ._commands import TIME_UNSET_VALUE, Command
from .protocol import (
    PREHEADER_LEN,
    BufferLike,
    DataLinkError,
    DataLinkPacket,
    DataLinkResponse,
    DataLinkTimeout,
    StreamEvent,
    classify_stream_packet,
    encode_frame,
    expected_payload_size,
    generate_client_id,
    parse_info_xml,
    parse_packet,
    parse_response,
    validate_preheader_magic,
)

logger = logging.getLogger(__name__)


class AsyncDataLink(_DataLinkBase):
    """Asyncio-based DataLink protocol 1.1 client.

    Same commands and semantics as :class:`~datalink_client.client.DataLink`
    (ID, AUTH, POSITION SET/AFTER, MATCH, REJECT, WRITE, READ, STREAM,
    ENDSTREAM, INFO), as coroutines, plus an async ``collect()`` generator and
    an async ``batch()`` context manager. Use :meth:`set_position_latest` to
    set the read position to the latest packet.

    Args:
        host:       Server hostname or IP address.
        port:       Server TCP port (typically 16000, or 16500 for TLS).
        timeout:    Optional timeout in seconds for connects/sends/reads.
                    None means wait indefinitely.
        tls:        Enable TLS encryption. If None (default), TLS is auto-enabled
                    when port is 16500.
        tls_noverify: If True, disable TLS certificate verification (insecure;
                      useful for self-signed certificates or testing).

    Note on timeouts: unlike :class:`DataLink`, any read or send timeout here
    closes the connection outright, even if some bytes toward the current
    frame had already arrived. A reader that a timeout has cancelled mid-read
    is not safe to reuse -- it can return stale or inconsistent data on a
    later read -- so treating every timeout as fatal to the connection is the
    safe choice for this transport. The same applies if the task awaiting a
    read, send, or flush is cancelled from outside (e.g. via ``wait_for`` or
    a task group): the connection is dropped rather than left mid-frame.
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
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._write_buf: bytearray | None = None
        self._batch_max: int | None = None

    @property
    def is_connected(self) -> bool:
        return self._writer is not None

    async def connect(self) -> None:
        """Open a TCP connection to the DataLink server, optionally with TLS."""
        if self._writer is not None:
            raise DataLinkError("Already connected")
        kwargs: dict[str, Any] = {}
        if self._tls:
            context = ssl.create_default_context()
            if self._tls_noverify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            # server_hostname is only meaningful (and only accepted) when ssl
            # is set; passing it otherwise raises ValueError.
            kwargs["ssl"] = context
            kwargs["server_hostname"] = self._host
        try:
            async with asyncio.timeout(self._timeout):
                reader, writer = await asyncio.open_connection(
                    self._host, self._port, **kwargs
                )
        except TimeoutError as e:
            raise DataLinkTimeout(
                f"Timed out connecting to {self._host}:{self._port}"
            ) from e
        except ssl.SSLCertVerificationError as e:
            raise DataLinkError(
                f"TLS certificate verification failed for "
                f"{self._host}:{self._port}: {e.verify_message}. "
                f"Use tls_noverify=True to skip verification "
                f"(insecure, e.g. for self-signed certificates)"
            ) from e
        except ssl.SSLError as e:
            raise DataLinkError(
                f"TLS handshake failed for {self._host}:{self._port}: {e}"
            ) from e
        except OSError as e:
            raise DataLinkError(
                f"Could not connect to {self._host}:{self._port}: {e}"
            ) from e
        sock = writer.get_extra_info("socket")
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._reader = reader
        self._writer = writer
        logger.debug(
            "Connected to %s:%d%s", self._host, self._port, " (TLS)" if self._tls else ""
        )

    async def close(self) -> None:
        """Gracefully close the connection."""
        writer = self._writer
        self._writer = None
        self._reader = None
        self._streaming = False
        self._write_buf = None
        self._batch_max = None
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    def _abort(self) -> None:
        """Drop the connection without awaiting.

        Used when an external cancellation interrupts a read/send/flush:
        ``close()`` is a coroutine, and awaiting inside a cancellation
        handler is fragile. The transport finishes closing on the event
        loop in the background.
        """
        writer = self._writer
        self._writer = None
        self._reader = None
        self._streaming = False
        self._write_buf = None
        self._batch_max = None
        if writer is not None:
            writer.close()

    async def reconnect(self) -> None:
        """Close the current connection (if any) and open a fresh one."""
        await self.close()
        await self.connect()

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

    async def _send_bytes(self, buf: bytearray) -> None:
        """Send already-framed bytes to the wire, closing on failure."""
        if not buf:
            return
        if self._writer is None:
            raise DataLinkError(f"Not connected; discarding {len(buf)} buffered bytes")
        try:
            self._writer.write(buf)
            async with asyncio.timeout(self._timeout):
                await self._writer.drain()
        except TimeoutError as e:
            await self.close()
            raise DataLinkTimeout("Timed out flushing buffered writes") from e
        except asyncio.CancelledError:
            self._abort()
            raise
        except OSError as e:
            await self.close()
            raise DataLinkError(f"flush failed: {e}") from e

    async def flush(self) -> None:
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
        await self._send_bytes(buf)

    @contextlib.asynccontextmanager
    async def batch(self, max_bytes: int | None = None):
        """Async context manager for batched writes.

        Usage::

            async with dl.batch():
                for record in records:
                    await dl.write(streamid, start, end, record)
            # flush() is called automatically on exit

        Args:
            max_bytes: see :meth:`begin_batch`.
        """
        self.begin_batch(max_bytes)
        try:
            yield
        finally:
            await self.flush()

    async def __aenter__(self) -> AsyncDataLink:
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    # -- Byte-level transport -----------------------------------------------

    async def _recv_exact(self, n: int) -> bytes:
        if self._reader is None:
            raise DataLinkError("Not connected")
        try:
            async with asyncio.timeout(self._timeout):
                data = await self._reader.readexactly(n)
        except TimeoutError as e:
            await self.close()
            raise DataLinkTimeout(f"Timed out waiting for {n} bytes") from e
        except asyncio.IncompleteReadError as e:
            await self.close()
            raise DataLinkError("Connection closed") from e
        except asyncio.CancelledError:
            self._abort()
            raise
        except OSError as e:
            await self.close()
            raise DataLinkError(f"recv failed: {e}") from e
        return data

    async def _send_packet(self, header: str, data: BufferLike | None = None) -> None:
        if self._writer is None:
            raise DataLinkError("Not connected")
        frame = encode_frame(header)
        if self._write_buf is not None:
            self._write_buf.extend(frame)
            if data is not None:
                self._write_buf.extend(data)
            if self._batch_max is not None and len(self._write_buf) >= self._batch_max:
                await self._send_bytes(self._write_buf)
                del self._write_buf[:]
            return
        try:
            self._writer.write(frame)
            if data is not None:
                self._writer.write(data)
            async with asyncio.timeout(self._timeout):
                await self._writer.drain()
        except TimeoutError as e:
            await self.close()
            raise DataLinkTimeout("Timed out sending data") from e
        except asyncio.CancelledError:
            self._abort()
            raise
        except OSError as e:
            await self.close()
            raise DataLinkError(f"send failed: {e}") from e

    async def _recv_packet(self) -> tuple[str, bytes | None]:
        if self._writer is None:
            raise DataLinkError("Not connected")
        pre = await self._recv_exact(PREHEADER_LEN)
        try:
            validate_preheader_magic(pre)
        except DataLinkError as e:
            await self.close()
            raise DataLinkError(f"{e} Connection closed.") from e
        header_len = pre[2]
        header_bytes = await self._recv_exact(header_len)
        try:
            header = header_bytes.decode("ascii")
        except UnicodeDecodeError as e:
            await self.close()
            raise DataLinkError(f"Header is not ASCII: {header_bytes!r} Connection closed.") from e
        try:
            data_size = expected_payload_size(header)
        except DataLinkError as e:
            await self.close()
            raise DataLinkError(f"{e} Connection closed.") from e
        data: bytes | None = None
        if data_size > 0:
            data = await self._recv_exact(data_size)
        return header, data

    # -- Command dispatch -----------------------------------------------------

    async def _execute(self, cmd: Command) -> Any:
        """Send a Command's request and, if it expects a reply, parse it.

        This is the only place command dispatch differs from
        :class:`~datalink_client.client.DataLink`: everything about what to
        send and how to interpret the reply lives in ``cmd`` itself.
        """
        # A reply-expecting command can't be queued behind batched writes:
        # there would be nothing on the wire yet for the server to reply to.
        if cmd.parse is not None and self._write_buf is not None:
            await self.flush()
        await self._send_packet(cmd.header, cmd.payload)
        if cmd.parse is None:
            return None
        header, data = await self._recv_packet()
        return cmd.parse(header, data)

    async def identify(self, clientid: str | None = None) -> str:
        """Exchange identification with the server and return the server ID string."""
        cid = generate_client_id(clientid)
        raw = await self._execute(commands.identify(cid))
        return self._store_identity(raw)

    async def auth_userpass(self, username: str, password: str) -> DataLinkResponse:
        return await self._execute(commands.auth_userpass(username, password))

    async def auth_jwt(self, token: str) -> DataLinkResponse:
        return await self._execute(commands.auth_jwt(token))

    async def position_set(
        self,
        pktid: str | int,
        uspkttime: int | str = TIME_UNSET_VALUE,
    ) -> DataLinkResponse:
        return await self._execute(commands.position_set(pktid, uspkttime))

    async def position_after(self, ustime: int | str) -> DataLinkResponse:
        return await self._execute(commands.position_after(ustime))

    async def set_position_latest(self) -> int:
        """Set the read position to the latest packet and return its ID.

        Calls ``POSITION SET LATEST`` on the server and returns the resulting
        packet ID.  Use this before calling :meth:`stream` when you only want
        packets that arrive after this call.

        Returns:
            The current latest packet ID.
        """
        resp = await self.position_set("LATEST")
        return resp.value

    async def match(self, pattern: str) -> DataLinkResponse:
        return await self._execute(commands.match(pattern))

    async def reject(self, pattern: str) -> DataLinkResponse:
        return await self._execute(commands.reject(pattern))

    @overload
    async def write(
        self,
        streamid: str,
        datastart: int,
        dataend: int,
        data: BufferLike,
        ack: Literal[True],
        pktid: int | None = ...,
    ) -> DataLinkResponse: ...

    @overload
    async def write(
        self,
        streamid: str,
        datastart: int,
        dataend: int,
        data: BufferLike,
        ack: Literal[False] = ...,
        pktid: int | None = ...,
    ) -> None: ...

    async def write(
        self,
        streamid: str,
        datastart: int,
        dataend: int,
        data: BufferLike,
        ack: bool = False,
        pktid: int | None = None,
    ) -> DataLinkResponse | None:
        return await self._execute(
            commands.write(streamid, datastart, dataend, data, ack=ack, pktid=pktid)
        )

    async def read(self, pktid: int) -> DataLinkPacket:
        return await self._execute(commands.read(pktid))

    async def bye(self) -> None:
        """Send a BYE command to gracefully notify the server before disconnecting."""
        await self._execute(commands.bye())

    async def stream(self) -> None:
        await self._execute(commands.stream())
        self._streaming = True

    async def endstream(self, timeout: float | None = None) -> None:
        if timeout is None:
            timeout = self._timeout if self._timeout is not None else 30.0
        deadline = time.monotonic() + timeout
        await self._send_packet("ENDSTREAM")
        # Override the per-read timeout with the remaining budget for this
        # wait; restored in `finally`.
        prev_timeout = self._timeout
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DataLinkTimeout(
                        f"Timed out after {timeout:.1f}s waiting for ENDSTREAM confirmation"
                    )
                self._timeout = remaining
                try:
                    header, data = await self._recv_packet()
                except DataLinkTimeout as e:
                    raise DataLinkTimeout(
                        f"Timed out after {timeout:.1f}s waiting for ENDSTREAM confirmation"
                    ) from e
                event = classify_stream_packet(header)
                if event is StreamEvent.ENDSTREAM:
                    self._streaming = False
                    return
                if event is StreamEvent.PACKET:
                    continue
                if event is StreamEvent.ERROR:
                    resp = parse_response(header, data)
                    raise DataLinkError(resp.message or "ENDSTREAM failed", resp.value)
                logger.debug("Draining unexpected packet during ENDSTREAM: %s", header[:80])
        finally:
            self._timeout = prev_timeout

    async def info(self, info_type: str, match: str | None = None) -> str:
        return await self._execute(commands.info(info_type, match))

    async def info_status(self, match: str | None = None) -> dict[str, Any]:
        return parse_info_xml(await self.info("STATUS", match=match))

    async def info_streams(self, match: str | None = None) -> dict[str, Any]:
        return parse_info_xml(await self.info("STREAMS", match=match))

    async def info_connections(self, match: str | None = None) -> dict[str, Any]:
        return parse_info_xml(await self.info("CONNECTIONS", match=match))

    async def collect(self) -> AsyncGenerator[DataLinkPacket, None]:
        """Streaming async generator: yields DataLinkPacket for each received PACKET.

        Abandoning iteration early (``break``, an exception, or simply not
        exhausting the generator) leaves the connection in streaming mode on
        the server. Call :meth:`endstream` when done, or wrap the loop in
        ``contextlib.aclosing(dl.collect())`` to send ENDSTREAM automatically.
        """
        while True:
            header, data = await self._recv_packet()
            event = classify_stream_packet(header)
            if event is StreamEvent.ENDSTREAM:
                self._streaming = False
                return
            if event is StreamEvent.PACKET:
                try:
                    pkt = parse_packet(header, data)
                except DataLinkError as e:
                    await self.close()
                    raise DataLinkError(
                        f"Invalid PACKET in stream (connection closed): {header[:80]} — {e}"
                    ) from e
                yield pkt
                continue
            if event is StreamEvent.ERROR:
                resp = parse_response(header, data)
                raise DataLinkError(resp.message or "Stream error", resp.value)
            logger.debug("Unexpected packet in stream: %s", header[:80])
