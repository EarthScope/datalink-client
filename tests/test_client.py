"""Tests for datalink_client.client parsing and framing."""

from __future__ import annotations

import errno
import socket
from unittest.mock import MagicMock, patch

import pytest

from datalink_client.client import DataLink
from datalink_client.protocol import DL_MAGIC, DataLinkError, DataLinkTimeout


def make_client(use_sendmsg: bool = False, buffered: bool = False) -> DataLink:
    """Construct a DataLink with a mocked socket for framing tests."""
    client = DataLink(host="localhost", port=16000, tls=False)
    client._sock = MagicMock()
    # Default sendmsg behavior: consume every buffer fully in one call (no
    # partial sends), returning the real byte count rather than a MagicMock.
    # This matches an ordinary socket and keeps _sendmsg_all's retry loop
    # from spinning; TestSendmsgPartialSend below exercises real partial sends.
    client._sock.sendmsg = MagicMock(
        side_effect=lambda bufs: sum(memoryview(b).nbytes for b in bufs)
    )
    client._use_sendmsg = use_sendmsg
    if buffered:
        client.begin_batch()
    return client


class TestParsePacket:
    def test_valid_packet(self):
        header = "PACKET FDSN:IU_ANMO_00_B_H_Z/MSEED 42 1000000 2000000 3000000 7"
        pkt = DataLink._parse_packet(header, b"payload")
        assert pkt.streamid == "FDSN:IU_ANMO_00_B_H_Z/MSEED"
        assert pkt.pktid == 42
        assert pkt.pkttime == 1_000_000
        assert pkt.datastart == 2_000_000
        assert pkt.dataend == 3_000_000
        assert pkt.data == b"payload"

    def test_payload_exact_size(self):
        # _recv_packet guarantees data is exactly size bytes; _parse_packet trusts this.
        header = "PACKET sid 1 10 20 30 3"
        pkt = DataLink._parse_packet(header, b"abc")
        assert pkt.data == b"abc"

    def test_empty_data_when_none(self):
        header = "PACKET sid 1 10 20 30 0"
        pkt = DataLink._parse_packet(header, None)
        assert pkt.data == b""

    def test_missing_fields_raises(self):
        with pytest.raises(DataLinkError):
            DataLink._parse_packet("PACKET sid 1 10 20", b"")

    def test_non_numeric_raises(self):
        with pytest.raises(DataLinkError):
            DataLink._parse_packet("PACKET sid abc 10 20 30 0", b"")

    def test_negative_values_allowed(self):
        # The protocol permits negative values in some fields; parser only validates format.
        header = "PACKET sid -1 -2 -3 -4 0"
        pkt = DataLink._parse_packet(header, None)
        assert pkt.pktid == -1
        assert pkt.pkttime == -2


class TestParseInfoXml:
    def test_status(self):
        xml = """<DataLink>
            <Status RingVersion="1" RingSize="100" PacketSize="512"
                    MaximumPackets="10" MaximumPacketID="99"
                    EarliestPacketID="1" LatestPacketID="99"
                    TotalConnections="5" TotalStreams="3"
                    MemoryMappedRing="TRUE" VolatileRing="FALSE" />
        </DataLink>"""
        result = DataLink._parse_info_xml(xml)
        assert result["Status"]["RingSize"] == 100
        assert result["Status"]["RingVersion"] == 1
        assert result["Status"]["MemoryMappedRing"] is True
        assert result["Status"]["VolatileRing"] is False

    def test_stream_list(self):
        xml = """<DataLink>
            <StreamList TotalStreams="2" SelectedStreams="2">
                <Stream Name="FDSN:IU_ANMO_00_BHZ/MSEED" EarliestPacketID="1"
                        LatestPacketID="10" DataLatency="0.5" />
                <Stream Name="FDSN:IU_COLA_00_BHZ/MSEED" EarliestPacketID="2"
                        LatestPacketID="20" DataLatency="1.0" />
            </StreamList>
        </DataLink>"""
        result = DataLink._parse_info_xml(xml)
        streams = result["StreamList"]["Stream"]
        assert len(streams) == 2
        assert streams[0]["Name"] == "FDSN:IU_ANMO_00_BHZ/MSEED"
        assert streams[0]["EarliestPacketID"] == 1
        assert streams[0]["DataLatency"] == 0.5
        assert streams[1]["LatestPacketID"] == 20

    def test_connection_list(self):
        xml = """<DataLink>
            <ConnectionList TotalConnections="1" SelectedConnections="1">
                <Connection Host="10.0.0.1" Port="16000"
                            TXPacketCount="100" TXByteRate="1.5" />
            </ConnectionList>
        </DataLink>"""
        result = DataLink._parse_info_xml(xml)
        conns = result["ConnectionList"]["Connection"]
        assert len(conns) == 1
        assert conns[0]["Host"] == "10.0.0.1"
        assert conns[0]["Port"] == 16000
        assert conns[0]["TXPacketCount"] == 100
        assert conns[0]["TXByteRate"] == 1.5

    def test_server_threads(self):
        xml = """<DataLink>
            <ServerThreads TotalServerThreads="2">
                <Thread Flags="active" />
                <Thread Flags="idle" />
            </ServerThreads>
        </DataLink>"""
        result = DataLink._parse_info_xml(xml)
        threads = result["ServerThreads"]["Thread"]
        assert len(threads) == 2

    def test_dash_becomes_none(self):
        xml = '<DataLink><Status RingSize="-" /></DataLink>'
        result = DataLink._parse_info_xml(xml)
        assert result["Status"]["RingSize"] is None

    def test_malformed_xml_raises_datalinkerror(self):
        with pytest.raises(DataLinkError) as excinfo:
            DataLink._parse_info_xml("not valid <xml")
        assert "Malformed INFO XML" in str(excinfo.value)

    def test_empty_xml_raises_datalinkerror(self):
        with pytest.raises(DataLinkError):
            DataLink._parse_info_xml("")


class TestFraming:
    def test_frame_structure_no_data(self):
        client = make_client(use_sendmsg=False)
        client._send_packet("ID foo")
        client._sock.sendall.assert_called_once()
        sent = bytes(client._sock.sendall.call_args[0][0])
        # DL magic (2 bytes) + header length (1 byte) + ASCII header
        assert sent[:2] == DL_MAGIC
        assert sent[2] == len(b"ID foo")
        assert sent[3:] == b"ID foo"

    def test_frame_with_bytes_payload_single_sendall(self):
        client = make_client(use_sendmsg=False)
        payload = b"hello world"
        client._send_packet("WRITE sid 1 2 N 11", payload)
        client._sock.sendall.assert_called_once()
        sent = bytes(client._sock.sendall.call_args[0][0])
        assert sent[:2] == DL_MAGIC
        assert sent[2] == len(b"WRITE sid 1 2 N 11")
        assert sent[3:3 + sent[2]] == b"WRITE sid 1 2 N 11"
        assert sent[3 + sent[2]:] == payload

    def test_frame_with_bytearray_payload(self):
        client = make_client(use_sendmsg=False)
        payload = bytearray(b"mutable payload")
        client._send_packet("WRITE sid 1 2 N 15", payload)
        client._sock.sendall.assert_called_once()
        sent = bytes(client._sock.sendall.call_args[0][0])
        assert sent[-15:] == b"mutable payload"

    def test_frame_with_memoryview_splits_sendall(self):
        client = make_client(use_sendmsg=False)
        payload = memoryview(b"zero-copy payload")
        client._send_packet("WRITE sid 1 2 N 17", payload)
        # memoryview is sent separately to avoid materializing a concat.
        assert client._sock.sendall.call_count == 2
        frame = bytes(client._sock.sendall.call_args_list[0][0][0])
        data = client._sock.sendall.call_args_list[1][0][0]
        assert frame[:2] == DL_MAGIC
        assert frame[2] == len(b"WRITE sid 1 2 N 17")
        assert bytes(data) == b"zero-copy payload"

    def test_sendmsg_no_data(self):
        client = make_client(use_sendmsg=True)
        client._send_packet("ID foo")
        client._sock.sendmsg.assert_called_once()
        buffers = client._sock.sendmsg.call_args[0][0]
        assert len(buffers) == 1
        assert bytes(buffers[0])[:2] == DL_MAGIC

    def test_sendmsg_with_data_scatter_gather(self):
        client = make_client(use_sendmsg=True)
        payload = b"scatter gather"
        client._send_packet("WRITE sid 1 2 N 14", payload)
        client._sock.sendmsg.assert_called_once()
        buffers = client._sock.sendmsg.call_args[0][0]
        assert len(buffers) == 2
        assert bytes(buffers[0])[:2] == DL_MAGIC
        assert bytes(buffers[1]) == payload

    def test_header_too_long_raises(self):
        client = make_client()
        with pytest.raises(DataLinkError, match="Header length"):
            client._send_packet("X" * 256)

    def test_header_exactly_max_len_ok(self):
        client = make_client()
        header = "X" * 255
        client._send_packet(header)
        client._sock.sendall.assert_called_once()
        sent = bytes(client._sock.sendall.call_args[0][0])
        assert sent[2] == 255
        assert sent[3:] == header.encode("ascii")

    def test_not_connected_raises(self):
        client = DataLink()
        with pytest.raises(DataLinkError, match="Not connected"):
            client._send_packet("ID foo")


class TestBufferedFraming:
    def test_buffered_append_no_send(self):
        client = make_client(buffered=True)
        client._send_packet("ID foo")
        client._send_packet("WRITE sid 1 2 N 5", b"hello")
        client._sock.sendall.assert_not_called()
        client._sock.sendmsg.assert_not_called()
        buf = bytes(client._write_buf)
        # Two frames concatenated in buffer.
        assert buf.startswith(DL_MAGIC)
        # ID foo frame: magic(2) + len(1) + "ID foo"(6) = 9 bytes
        assert buf[2] == 6
        assert buf[3:9] == b"ID foo"
        # Second frame starts at offset 9.
        assert buf[9:11] == DL_MAGIC
        assert buf[11] == len(b"WRITE sid 1 2 N 5")
        assert buf[-5:] == b"hello"

    def test_flush_sends_and_clears(self):
        client = make_client(buffered=True)
        client._send_packet("ID foo")
        client.flush()
        client._sock.sendall.assert_called_once()
        sent = bytes(client._sock.sendall.call_args[0][0])
        assert sent[:2] == DL_MAGIC
        assert client._write_buf is None

    def test_flush_with_empty_buffer_no_send(self):
        client = make_client(buffered=True)
        client.flush()
        client._sock.sendall.assert_not_called()
        assert client._write_buf is None

    def test_flush_outside_batch_is_noop(self):
        client = make_client()
        assert client._write_buf is None
        client.flush()  # Should not raise.
        client._sock.sendall.assert_not_called()

    def test_flush_raises_and_discards_when_disconnected(self):
        client = make_client(buffered=True)
        client._send_packet("ID foo")
        client._sock = None
        with pytest.raises(DataLinkError, match="Not connected"):
            client.flush()
        assert client._write_buf is None

    def test_execute_flushes_batch_before_reply_expecting_command(self):
        """A command expecting a reply must not be queued behind batched
        writes, or it would wait forever for a reply to a request that was
        never sent."""
        client = make_client(buffered=True)
        client._send_packet("WRITE sid 1 2 N 5", b"hello")
        ok_header = b"OK 0 0"
        stream = b"DL" + bytes([len(ok_header)]) + ok_header
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(stream))
        resp = client.match("FDSN:.*")
        # One sendall for the flushed WRITE, one for MATCH itself.
        assert client._sock.sendall.call_count == 2
        assert resp.status == "OK"
        assert client._write_buf is None

    def test_batch_context_manager_flushes_on_exit(self):
        client = make_client()
        with client.batch():
            client._send_packet("ID foo")
            client._sock.sendall.assert_not_called()
        client._sock.sendall.assert_called_once()
        assert client._write_buf is None

    def test_batch_context_manager_flushes_on_exception(self):
        client = make_client()
        with pytest.raises(RuntimeError):
            with client.batch():
                client._send_packet("ID foo")
                raise RuntimeError("boom")
        # Buffered packet is still flushed on the way out.
        client._sock.sendall.assert_called_once()
        assert client._write_buf is None

    def test_second_begin_batch_preserves_queued_packets(self):
        client = make_client(buffered=True)
        client._send_packet("ID foo")
        first_buf_id = id(client._write_buf)
        client.begin_batch()  # second call while already batching
        assert id(client._write_buf) == first_buf_id
        client._send_packet("MATCH bar")
        client.flush()
        client._sock.sendall.assert_called_once()
        sent = bytes(client._sock.sendall.call_args[0][0])
        assert b"ID foo" in sent and b"MATCH bar" in sent

    def test_batch_max_bytes_sends_in_chunks(self):
        # sendall's argument is the live _write_buf, cleared in place right
        # after the call, so capture a copy at call time rather than relying
        # on call_args (which would see the buffer post-clear).
        client = make_client()
        sent_chunks: list[bytes] = []
        client._sock.sendall = MagicMock(side_effect=lambda buf: sent_chunks.append(bytes(buf)))
        client.begin_batch(max_bytes=15)
        client._send_packet("ID foo")  # framed: 9 bytes; under threshold
        assert sent_chunks == []
        client._send_packet("ID bar")  # cumulative 18 bytes >= 15: auto-flush
        assert len(sent_chunks) == 1
        assert len(sent_chunks[0]) == 18
        assert client._write_buf == bytearray()  # cleared, batching still on
        client._send_packet("ID baz")
        client.flush()
        assert len(sent_chunks) == 2
        assert len(sent_chunks[1]) == 9
        assert client._write_buf is None


class TestParseResponse:
    def test_ok_with_value_and_message(self):
        client = DataLink()
        resp = client._parse_response("OK 42 5", b"hello")
        assert resp.status == "OK"
        assert resp.value == 42
        assert resp.message == "hello"

    def test_error_with_message(self):
        client = DataLink()
        resp = client._parse_response("ERROR 1 10", b"bad request")
        assert resp.status == "ERROR"
        assert resp.value == 1
        assert resp.message == "bad request"

    def test_no_data_message_is_none(self):
        client = DataLink()
        resp = client._parse_response("OK 0 0", None)
        assert resp.message is None

    def test_non_integer_value_defaults_to_zero(self):
        client = DataLink()
        resp = client._parse_response("OK abc 0", None)
        assert resp.value == 0


class TestPositionTimeStringWrapping:
    def test_position_set_invalid_time_raises_datalinkerror(self):
        client = make_client()
        with pytest.raises(DataLinkError, match="Invalid time string"):
            client.position_set("0", "not-a-date")

    def test_position_after_invalid_time_raises_datalinkerror(self):
        client = make_client()
        with pytest.raises(DataLinkError, match="Invalid time string"):
            client.position_after("not-a-date")


class TestFromServerString:
    def test_empty_defaults(self):
        dl = DataLink.from_server_string("")
        assert dl._host == "localhost"
        assert dl._port == 16000

    def test_host_only(self):
        dl = DataLink.from_server_string("example.com")
        assert dl._host == "example.com"
        assert dl._port == 16000

    def test_host_port_colon(self):
        dl = DataLink.from_server_string("example.com:16500")
        assert dl._host == "example.com"
        assert dl._port == 16500

    def test_host_port_at(self):
        dl = DataLink.from_server_string("example.com@16500")
        assert dl._host == "example.com"
        assert dl._port == 16500

    def test_tls_auto_on_16500(self):
        dl = DataLink.from_server_string("example.com:16500")
        assert dl._tls is True

    def test_ipv6_bracketed(self):
        dl = DataLink.from_server_string("[::1]:16000")
        assert dl._host == "::1"
        assert dl._port == 16000

    def test_bare_ipv6_without_brackets_raises(self):
        with pytest.raises(ValueError, match="Ambiguous server string"):
            DataLink.from_server_string("::1")

    def test_host_containing_at_before_port_uses_last_at(self):
        # rpartition on the *last* '@' keeps a host containing '@' intact,
        # rather than a global '@'->':' replace mangling it.
        dl = DataLink.from_server_string("user@example.org@16000")
        assert dl._host == "user@example.org"
        assert dl._port == 16000

    def test_port_out_of_range_raises(self):
        with pytest.raises(ValueError, match="Port out of range"):
            DataLink.from_server_string("example.com:99999")

    def test_negative_port_raises(self):
        with pytest.raises(ValueError, match="Port out of range"):
            DataLink.from_server_string("example.com:-5")

    def test_invalid_port_raises(self):
        with pytest.raises(ValueError):
            DataLink.from_server_string("example.com:notaport")

    def test_unclosed_bracket_raises(self):
        with pytest.raises(ValueError):
            DataLink.from_server_string("[::1")


class TestConnectFailover:
    """connect() must fall back to the next address, not crash, when
    socket creation itself fails (e.g. an unsupported address family)."""

    def test_socket_creation_failure_falls_back_to_next_address(self):
        infos = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 16000, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 16000)),
        ]
        attempted: list[int] = []

        def fake_socket(af, socktype, proto):
            attempted.append(af)
            if af == socket.AF_INET6:
                raise OSError(errno.EAFNOSUPPORT, "Address family not supported")
            return MagicMock()

        with patch("datalink_client.client.socket.getaddrinfo", return_value=infos), \
                patch("datalink_client.client.socket.socket", side_effect=fake_socket):
            client = DataLink("example.com", 16000, tls=False)
            client.connect()  # must not raise UnboundLocalError

        assert attempted == [socket.AF_INET6, socket.AF_INET]
        assert client.is_connected

    def test_all_addresses_failing_raises_datalinkerror(self):
        infos = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 16000, 0, 0))]

        def fake_socket(af, socktype, proto):
            raise OSError(errno.EAFNOSUPPORT, "Address family not supported")

        with patch("datalink_client.client.socket.getaddrinfo", return_value=infos), \
                patch("datalink_client.client.socket.socket", side_effect=fake_socket):
            client = DataLink("example.com", 16000, tls=False)
            with pytest.raises(DataLinkError):
                client.connect()


class TestRecvAllTimeout:
    def test_clean_timeout_raises_datalinktimeout_without_closing(self):
        client = make_client()
        client._sock.recv_into = MagicMock(side_effect=TimeoutError("timed out"))
        with pytest.raises(DataLinkTimeout):
            client._recv_all(5)
        # No bytes were consumed; the stream is still in sync, so the
        # connection is left open for a subsequent retry.
        assert client.is_connected

    def test_timeout_after_partial_read_closes_connection(self):
        client = make_client()
        client._sock.recv_into = MagicMock(side_effect=[2, TimeoutError("timed out")])
        with pytest.raises(DataLinkTimeout, match="partial read"):
            client._recv_all(5)
        assert not client.is_connected

    def test_datalinktimeout_is_caught_as_datalinkerror(self):
        client = make_client()
        client._sock.recv_into = MagicMock(side_effect=TimeoutError("timed out"))
        with pytest.raises(DataLinkError):
            client._recv_all(5)

    def test_datalinktimeout_is_caught_as_timeouterror(self):
        client = make_client()
        client._sock.recv_into = MagicMock(side_effect=TimeoutError("timed out"))
        with pytest.raises(TimeoutError):
            client._recv_all(5)


class TestRecvBufShrink:
    """_recv_buf grows to fit an oversized payload; it must not stay grown
    for the life of the connection."""

    def test_shrink_on_close_after_oversized_payload(self):
        client = make_client()
        big = b"x" * 200_000
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(big))
        data = client._recv_all(len(big))
        assert data == big
        assert len(client._recv_buf) >= len(big)
        client.close()
        assert len(client._recv_buf) == 65536

    def test_shrink_lazily_on_next_read_after_buffer_drained(self):
        client = make_client()
        big = b"x" * 200_000
        small = b"y" * 10
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(big + small))
        client._recv_all(len(big))
        assert len(client._recv_buf) >= len(big)
        data = client._recv_all(len(small))
        assert data == small
        assert len(client._recv_buf) == 65536

    def test_no_shrink_between_consecutive_large_reads(self):
        client = make_client()
        size = 200_000
        stream = (b"a" * size) + (b"b" * size)
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(stream))
        first = client._recv_all(size)
        grown_id = id(client._recv_buf)
        grown_len = len(client._recv_buf)
        second = client._recv_all(size)
        assert first == b"a" * size
        assert second == b"b" * size
        # No shrink-then-regrow churn between back-to-back large reads.
        assert id(client._recv_buf) == grown_id
        assert len(client._recv_buf) == grown_len

    def test_shrink_survives_reconnect(self):
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 16000))]
        client = make_client()
        client._recv_buf = bytearray(200_000)
        client._recv_view = memoryview(client._recv_buf)
        with patch("datalink_client.client.socket.getaddrinfo", return_value=infos), \
                patch("datalink_client.client.socket.socket", return_value=MagicMock()):
            client.close()
            client.connect()
        assert len(client._recv_buf) == 65536


class TestConnectClosesOnUnhandledException:
    def test_non_oserror_from_wrap_socket_still_closes_socket(self):
        """connect() must close the raw socket even when wrap_socket() raises
        something other than SSLCertVerificationError or OSError."""
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 16500))]
        created_socket = MagicMock()
        fake_context = MagicMock()
        fake_context.wrap_socket.side_effect = ValueError("boom")
        with patch("datalink_client.client.socket.getaddrinfo", return_value=infos), \
                patch("datalink_client.client.socket.socket", return_value=created_socket), \
                patch("datalink_client.client.ssl.create_default_context", return_value=fake_context):
            client = DataLink("example.com", 16500, tls=True)
            with pytest.raises(ValueError):
                client.connect()
        created_socket.close.assert_called_once()
        assert client._sock is None


class TestDesyncClosesConnection:
    def test_bad_preheader_magic_closes_connection(self):
        client = make_client()
        bad_header = b"HELLO"
        stream = b"XX" + bytes([len(bad_header)]) + bad_header
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(stream))
        with pytest.raises(DataLinkError, match="Invalid preheader magic"):
            client._recv_packet()
        assert not client.is_connected

    def test_unrecognized_packet_type_closes_connection(self):
        client = make_client()
        header = b"WEIRD 1 2 3"
        stream = b"DL" + bytes([len(header)]) + header
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(stream))
        with pytest.raises(DataLinkError, match="Unrecognized packet type"):
            client._recv_packet()
        assert not client.is_connected

    def test_non_ascii_header_closes_connection(self):
        client = make_client()
        header = b"\xff\xfe garbage"
        stream = b"DL" + bytes([len(header)]) + header
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(stream))
        with pytest.raises(DataLinkError, match="not ASCII"):
            client._recv_packet()
        assert not client.is_connected

    def test_negative_payload_size_closes_connection(self):
        client = make_client()
        header = b"OK 1 -5"
        stream = b"DL" + bytes([len(header)]) + header
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(stream))
        with pytest.raises(DataLinkError, match="Negative payload size"):
            client._recv_packet()
        assert not client.is_connected


class TestHasBufferedData:
    def test_false_when_buffer_empty(self):
        client = make_client()
        assert client.has_buffered_data is False

    def test_true_when_a_second_frame_is_already_buffered(self):
        client = make_client()
        header1 = b"OK 1 0"
        header2 = b"OK 2 0"
        stream = (
            b"DL" + bytes([len(header1)]) + header1
            + b"DL" + bytes([len(header2)]) + header2
        )
        # A single recv_into call, as a real socket often would, delivers
        # both frames at once; has_buffered_data must see the leftover one.
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(stream))
        client._recv_packet()
        assert client.has_buffered_data is True
        client._recv_packet()
        assert client.has_buffered_data is False


class TestCollectDesync:
    def test_invalid_packet_closes_connection_and_raises(self):
        client = make_client()
        client._streaming = True
        header = b"PACKET sid 1 2 3"  # too few fields for parse_packet
        stream = b"DL" + bytes([len(header)]) + header
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_stream(stream))
        with pytest.raises(DataLinkError, match="Invalid PACKET in stream"):
            next(client.collect())
        assert not client.is_connected


class TestSendmsgPartialSend:
    """sendmsg is a single syscall that may transfer fewer bytes than
    requested; _sendmsg_all must loop until every buffer is fully sent."""

    def test_partial_send_is_retried_until_complete(self):
        client = make_client(use_sendmsg=True)
        payload = b"scatter gather payload"
        header = "WRITE sid 1 2 N 23"
        header_bytes = header.encode("ascii")
        expected_frame = b"DL" + bytes([len(header_bytes)]) + header_bytes
        expected_total = expected_frame + payload

        # Fake a socket that only ever accepts a small, fixed-size chunk per
        # call (deliberately smaller than either buffer), forcing _sendmsg_all
        # to loop across several partial sends, including at least one that
        # splits a single buffer mid-way.
        sent = bytearray()
        CHUNK = 7

        def fake_sendmsg(views):
            remaining = CHUNK
            n_total = 0
            for v in views:
                take = min(remaining, v.nbytes)
                if take <= 0:
                    break
                sent.extend(bytes(v[:take]))
                n_total += take
                remaining -= take
            return n_total

        client._sock.sendmsg = MagicMock(side_effect=fake_sendmsg)
        client._send_packet(header, payload)

        assert bytes(sent) == expected_total
        assert client._sock.sendmsg.call_count > 1

    def test_zero_byte_send_raises_and_closes(self):
        client = make_client(use_sendmsg=True)
        client._sock.sendmsg = MagicMock(return_value=0)
        with pytest.raises(DataLinkError, match="0 bytes"):
            client._send_packet("ID foo")
        assert not client.is_connected


class TestDeprecatedLastPktid:
    def test_last_pktid_emits_deprecation_warning(self):
        client = make_client()
        client._sock.recv_into = MagicMock(side_effect=_mock_recv_ok(42))
        with pytest.warns(DeprecationWarning, match="set_position_latest"):
            client.last_pktid()


def _mock_recv_ok(value: int):
    """Build a recv_into side-effect that returns an OK response for POSITION SET.

    The response is a single OK frame whose value field is set to `value`.
    """
    header = f"OK {value} 0".encode("ascii")
    preheader = b"DL" + bytes([len(header)])
    stream = preheader + header

    # recv_into copies bytes into a caller-supplied buffer and returns count.
    offset = [0]

    def side_effect(buf):
        remaining = len(stream) - offset[0]
        n = min(len(buf), remaining)
        buf[:n] = stream[offset[0]:offset[0] + n]
        offset[0] += n
        return n

    return side_effect


def _mock_recv_stream(stream: bytes):
    """Build a recv_into side-effect that serves raw `stream` bytes verbatim."""
    offset = [0]

    def side_effect(buf):
        remaining = len(stream) - offset[0]
        n = min(len(buf), remaining)
        buf[:n] = stream[offset[0]:offset[0] + n]
        offset[0] += n
        return n

    return side_effect
