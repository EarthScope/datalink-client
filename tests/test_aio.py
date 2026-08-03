"""Tests for datalink_client.aio.AsyncDataLink.

These drive a real loopback asyncio.start_server speaking minimal DataLink,
rather than mocking asyncio internals -- the transport is thin enough that a
real socket round-trip is both simpler and more trustworthy than a mock.
Uses asyncio.run() inside ordinary test functions so no pytest-asyncio
dependency is needed.
"""

from __future__ import annotations

import asyncio
import inspect
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from datalink_client.aio import AsyncDataLink
from datalink_client.client import DataLink
from datalink_client.protocol import DataLinkError, DataLinkTimeout


def run(coro):
    """Run a coroutine to completion; thin wrapper for readability."""
    return asyncio.run(coro)


class _Frames:
    """Helper for a test server: encode/decode DataLink preheader+header+data."""

    @staticmethod
    def encode(header: str, data: bytes | None = None) -> bytes:
        hb = header.encode("ascii")
        out = b"DL" + bytes([len(hb)]) + hb
        if data:
            out += data
        return out

    @staticmethod
    async def recv_header(reader: asyncio.StreamReader) -> str:
        pre = await reader.readexactly(3)
        hlen = pre[2]
        return (await reader.readexactly(hlen)).decode("ascii")


async def _serve_once(handler):
    """Start a loopback server running `handler(reader, writer)` once, return its port."""
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


class TestFullCommandRoundTrip:
    def test_identify_match_position_write_read(self):
        async def scenario():
            async def handle(reader, writer):
                header = await _Frames.recv_header(reader)
                assert header.startswith("ID ")
                writer.write(_Frames.encode("ID srv :: WRITE DLPROTO:1.0"))
                await writer.drain()

                header = await _Frames.recv_header(reader)
                assert header.startswith("MATCH")
                size = int(header.split()[1])
                await reader.readexactly(size)
                writer.write(_Frames.encode("OK 3 0"))
                await writer.drain()

                header = await _Frames.recv_header(reader)
                assert header == "POSITION SET LATEST"
                writer.write(_Frames.encode("OK 42 0"))
                await writer.drain()

                header = await _Frames.recv_header(reader)
                assert header.startswith("WRITE")
                size = int(header.split()[5])
                await reader.readexactly(size)
                writer.write(_Frames.encode("OK 99 0"))
                await writer.drain()

                header = await _Frames.recv_header(reader)
                assert header == "READ 99"
                writer.write(_Frames.encode("PACKET sid 99 100 200 300 5", b"hello"))
                await writer.drain()
                writer.close()

            server, port = await _serve_once(handle)
            async with AsyncDataLink("127.0.0.1", port) as dl:
                raw = await dl.identify("test-client")
                assert dl.server_id == raw
                assert dl.server_capabilities == {"WRITE": True, "DLPROTO": "1.0"}

                resp = await dl.match("IU_.*")
                assert resp.value == 3

                pktid = await dl.set_position_latest()
                assert pktid == 42

                resp = await dl.write("sid", 1, 2, b"hello", ack=True)
                assert resp.value == 99

                pkt = await dl.read(99)
                assert pkt.pktid == 99
                assert pkt.data == b"hello"
            assert dl.is_connected is False
            server.close()
            await server.wait_closed()

        run(scenario())


class TestStreamingRoundTrip:
    def test_stream_collect_endstream(self):
        async def scenario():
            async def handle(reader, writer):
                header = await _Frames.recv_header(reader)
                assert header == "STREAM"
                writer.write(_Frames.encode("PACKET sid 1 10 20 30 3", b"abc"))
                writer.write(_Frames.encode("PACKET sid 2 11 21 31 3", b"def"))
                writer.write(_Frames.encode("ENDSTREAM"))
                await writer.drain()
                writer.close()

            server, port = await _serve_once(handle)
            dl = AsyncDataLink("127.0.0.1", port)
            await dl.connect()
            await dl.stream()
            assert dl.is_streaming is True
            pkts = [p async for p in dl.collect()]
            assert [(p.pktid, p.data) for p in pkts] == [(1, b"abc"), (2, b"def")]
            assert dl.is_streaming is False
            await dl.close()
            server.close()
            await server.wait_closed()

        run(scenario())


class TestErrorReply:
    def test_read_error_reply_raises_datalinkerror_with_value(self):
        async def scenario():
            async def handle(reader, writer):
                header = await _Frames.recv_header(reader)
                assert header == "READ 999"
                writer.write(_Frames.encode("ERROR 1 9", b"not found"))
                await writer.drain()
                writer.close()

            server, port = await _serve_once(handle)
            dl = AsyncDataLink("127.0.0.1", port)
            await dl.connect()
            try:
                with pytest.raises(DataLinkError, match="not found") as excinfo:
                    await dl.read(999)
                assert excinfo.value.value == 1
            finally:
                await dl.close()
                server.close()
                await server.wait_closed()

        run(scenario())


class TestTimeoutHandling:
    def test_read_timeout_raises_and_closes_connection(self):
        async def scenario():
            async def handle(reader, writer):
                await _Frames.recv_header(reader)
                await asyncio.sleep(0.5)  # comfortably past the client's 0.2s timeout
                writer.close()

            server, port = await _serve_once(handle)
            dl = AsyncDataLink("127.0.0.1", port, timeout=0.2)
            await dl.connect()
            with pytest.raises(DataLinkTimeout):
                await dl.identify("client")
            assert dl.is_connected is False
            server.close()
            await server.wait_closed()

        run(scenario())

    def test_datalinktimeout_is_catchable_as_timeouterror(self):
        async def scenario():
            async def handle(reader, writer):
                await _Frames.recv_header(reader)
                await asyncio.sleep(0.5)  # comfortably past the client's 0.2s timeout
                writer.close()

            server, port = await _serve_once(handle)
            dl = AsyncDataLink("127.0.0.1", port, timeout=0.2)
            await dl.connect()
            with pytest.raises(TimeoutError):
                await dl.identify("client")
            server.close()
            await server.wait_closed()

        run(scenario())

    def test_connect_timeout_raises_datalinktimeout(self):
        async def scenario():
            async def hang(*args, **kwargs):
                await asyncio.sleep(5)

            dl = AsyncDataLink("127.0.0.1", 1, timeout=0.1)
            with patch("asyncio.open_connection", new=AsyncMock(side_effect=hang)):
                with pytest.raises(DataLinkTimeout):
                    await dl.connect()

        run(scenario())


class TestDesyncClosesConnection:
    def test_bad_preheader_magic_closes_connection(self):
        async def scenario():
            async def handle(reader, writer):
                await _Frames.recv_header(reader)
                writer.write(b"XX\x03bad")
                await writer.drain()
                writer.close()

            server, port = await _serve_once(handle)
            dl = AsyncDataLink("127.0.0.1", port)
            await dl.connect()
            with pytest.raises(DataLinkError, match="Invalid preheader magic"):
                await dl.identify("client")
            assert dl.is_connected is False
            server.close()
            await server.wait_closed()

        run(scenario())

    def test_non_ascii_header_closes_connection(self):
        async def scenario():
            async def handle(reader, writer):
                await _Frames.recv_header(reader)
                bad = b"\xff\xfe garbage"
                writer.write(b"DL" + bytes([len(bad)]) + bad)
                await writer.drain()
                writer.close()

            server, port = await _serve_once(handle)
            dl = AsyncDataLink("127.0.0.1", port)
            await dl.connect()
            with pytest.raises(DataLinkError, match="not ASCII"):
                await dl.identify("client")
            assert dl.is_connected is False
            server.close()
            await server.wait_closed()

        run(scenario())

    def test_invalid_packet_in_stream_closes_connection_and_raises(self):
        async def scenario():
            async def handle(reader, writer):
                header = await _Frames.recv_header(reader)
                assert header == "STREAM"
                # Too few fields for parse_packet.
                writer.write(_Frames.encode("PACKET sid 1 2 3"))
                await writer.drain()
                writer.close()

            server, port = await _serve_once(handle)
            dl = AsyncDataLink("127.0.0.1", port)
            await dl.connect()
            await dl.stream()
            with pytest.raises(DataLinkError, match="Invalid PACKET in stream"):
                await dl.collect().__anext__()
            assert dl.is_connected is False
            server.close()
            await server.wait_closed()

        run(scenario())


class TestBatch:
    def test_batch_coalesces_writes_into_one_flush(self):
        async def scenario():
            received = bytearray()

            async def handle(reader, writer):
                # Read whatever arrives without replying (no-ack writes).
                try:
                    while True:
                        chunk = await reader.read(4096)
                        if not chunk:
                            break
                        received.extend(chunk)
                except (asyncio.IncompleteReadError, ConnectionError):
                    pass
                writer.close()

            server, port = await _serve_once(handle)
            dl = AsyncDataLink("127.0.0.1", port)
            await dl.connect()
            async with dl.batch():
                await dl.write("sid", 1, 2, b"one")
                await dl.write("sid", 3, 4, b"two")
                assert dl._write_buf is not None  # nothing sent yet mid-batch
            assert dl._write_buf is None
            await asyncio.sleep(0.05)  # let the server drain the socket
            await dl.close()
            assert b"one" in received and b"two" in received
            server.close()
            await server.wait_closed()

        run(scenario())

    def test_reply_expecting_command_flushes_pending_batch_first(self):
        """A command expecting a reply must not be queued behind batched
        writes, or it would wait forever for a reply to a request that was
        never sent."""

        async def scenario():
            async def handle(reader, writer):
                header = await _Frames.recv_header(reader)
                assert header.startswith("WRITE")  # the batched write arrived first
                size = int(header.split()[5])
                await reader.readexactly(size)

                header = await _Frames.recv_header(reader)
                assert header.startswith("MATCH")
                size = int(header.split()[1])
                await reader.readexactly(size)
                writer.write(_Frames.encode("OK 3 0"))
                await writer.drain()
                writer.close()

            server, port = await _serve_once(handle)
            dl = AsyncDataLink("127.0.0.1", port)
            await dl.connect()
            dl.begin_batch()
            await dl.write("sid", 1, 2, b"one")
            resp = await dl.match("IU_.*")
            assert resp.value == 3
            assert dl._write_buf is None
            await dl.close()
            server.close()
            await server.wait_closed()

        run(scenario())

    def test_flush_raises_and_discards_when_disconnected(self):
        async def scenario():
            dl = AsyncDataLink("127.0.0.1", 1)
            dl._write_buf = bytearray(b"queued frame bytes")
            with pytest.raises(DataLinkError, match="Not connected"):
                await dl.flush()
            assert dl._write_buf is None

        run(scenario())

    def test_second_begin_batch_preserves_queued_packets(self):
        async def scenario():
            dl = AsyncDataLink("127.0.0.1", 1)
            writer = MagicMock()
            writer.drain = AsyncMock()
            dl._writer = writer

            dl.begin_batch()
            await dl._send_packet("ID foo")
            first_buf_id = id(dl._write_buf)
            dl.begin_batch()  # second call while already batching
            assert id(dl._write_buf) == first_buf_id
            await dl._send_packet("MATCH bar")
            await dl.flush()
            sent = bytes(writer.write.call_args[0][0])
            assert b"ID foo" in sent and b"MATCH bar" in sent

        run(scenario())

    def test_batch_max_bytes_sends_in_chunks(self):
        async def scenario():
            dl = AsyncDataLink("127.0.0.1", 1)
            writer = MagicMock()
            writer.drain = AsyncMock()
            dl._writer = writer
            sent_chunks: list[bytes] = []
            writer.write = MagicMock(side_effect=lambda buf: sent_chunks.append(bytes(buf)))

            dl.begin_batch(max_bytes=15)
            await dl._send_packet("ID foo")  # framed: 9 bytes; under threshold
            assert sent_chunks == []
            await dl._send_packet("ID bar")  # cumulative 18 bytes >= 15: auto-flush
            assert len(sent_chunks) == 1
            assert len(sent_chunks[0]) == 18
            assert dl._write_buf == bytearray()  # cleared, batching still on
            await dl._send_packet("ID baz")
            await dl.flush()
            assert len(sent_chunks) == 2
            assert len(sent_chunks[1]) == 9
            assert dl._write_buf is None

        run(scenario())


class TestCancellation:
    """An external task.cancel() during a read/send/flush must drop the
    connection, not leave it reporting healthy with a reader mid-frame."""

    def test_cancelled_recv_disconnects_cleanly(self):
        async def scenario():
            async def handle(reader, writer):
                # Blocks until the client disconnects (never replies).
                await reader.read(1)
                writer.close()

            server, port = await _serve_once(handle)
            dl = AsyncDataLink("127.0.0.1", port)
            await dl.connect()
            assert dl.is_connected

            task = asyncio.create_task(dl._recv_packet())
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

            assert dl.is_connected is False
            assert dl._reader is None
            server.close()
            await server.wait_closed()

        run(scenario())

    def test_cancelled_collect_disconnects_cleanly(self):
        async def scenario():
            async def handle(reader, writer):
                # Drain the STREAM command but never reply; keep the
                # connection open until the client actually disconnects.
                while await reader.read(4096):
                    pass
                writer.close()

            server, port = await _serve_once(handle)
            dl = AsyncDataLink("127.0.0.1", port)
            await dl.connect()
            await dl.stream()

            gen = dl.collect()
            task = asyncio.create_task(gen.__anext__())
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

            assert dl.is_connected is False
            server.close()
            await server.wait_closed()

        run(scenario())

    def test_cancelled_send_disconnects_cleanly(self):
        async def scenario():
            dl = AsyncDataLink("127.0.0.1", 1)
            writer = MagicMock()
            hang = asyncio.Event()

            async def hanging_drain():
                await hang.wait()

            writer.drain = hanging_drain
            dl._writer = writer

            task = asyncio.create_task(dl._send_packet("ID foo"))
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

            assert dl.is_connected is False
            assert dl._writer is None

        run(scenario())


class TestCloseResetsStateOnUnexpectedException:
    def test_state_reset_even_if_wait_closed_raises_non_oserror(self):
        async def scenario():
            dl = AsyncDataLink("127.0.0.1", 1)
            writer = MagicMock()
            writer.wait_closed = AsyncMock(side_effect=RuntimeError("boom"))
            dl._writer = writer
            dl._reader = MagicMock()
            dl._streaming = True
            dl._write_buf = bytearray(b"queued")

            with pytest.raises(RuntimeError):
                await dl.close()

            assert dl.is_connected is False
            assert dl._streaming is False
            assert dl._write_buf is None

        run(scenario())


class TestCommandParity:
    """Guard against the two clients silently drifting apart."""

    SYNC_ONLY = {"last_pktid"}  # deprecated; intentionally not carried over
    # No I/O, so deliberately synchronous on both clients.
    SYNC_ON_BOTH = {"begin_batch"}
    # @asynccontextmanager-wrapped: the factory function itself is a plain
    # (non-async-def) callable; its async-ness shows up in the object it
    # returns, not in inspect.iscoroutinefunction().
    CONTEXT_MANAGERS = {"batch"}

    def test_async_covers_every_sync_command(self):
        sync_methods = {
            name
            for name, val in vars(DataLink).items()
            if not name.startswith("_") and callable(val)
        } - self.SYNC_ONLY
        for name in sync_methods - self.CONTEXT_MANAGERS:
            assert hasattr(AsyncDataLink, name), f"AsyncDataLink is missing {name}()"
            attr = getattr(AsyncDataLink, name)
            is_async = inspect.iscoroutinefunction(attr) or inspect.isasyncgenfunction(attr)
            if name in self.SYNC_ON_BOTH:
                assert not is_async, f"AsyncDataLink.{name} should stay synchronous"
            else:
                assert is_async, f"AsyncDataLink.{name} exists but isn't async"

    def test_batch_returns_an_async_context_manager(self):
        dl = AsyncDataLink()
        cm = dl.batch()
        assert hasattr(cm, "__aenter__") and hasattr(cm, "__aexit__")
