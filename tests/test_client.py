"""Tests for datalink_client.client parsing and framing."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from datalink_client.client import DataLink
from datalink_client.protocol import DL_MAGIC, DataLinkError


def make_client(use_sendmsg: bool = False, buffered: bool = False) -> DataLink:
    """Construct a DataLink with a mocked socket for framing tests."""
    client = DataLink(host="localhost", port=16000, tls=False)
    client._sock = MagicMock()
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

    def test_payload_truncated_to_size(self):
        header = "PACKET sid 1 10 20 30 3"
        pkt = DataLink._parse_packet(header, b"abcdefg")
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

    def test_invalid_port_raises(self):
        with pytest.raises(ValueError):
            DataLink.from_server_string("example.com:notaport")

    def test_unclosed_bracket_raises(self):
        with pytest.raises(ValueError):
            DataLink.from_server_string("[::1")


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
