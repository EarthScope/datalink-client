"""Tests for datalink_client._commands: pure request/reply builders, no I/O.

These are the tests that give the shared command layer its real coverage —
both DataLink and AsyncDataLink dispatch these same Command objects, so
correctness here is correctness for both transports.
"""

from __future__ import annotations

import pytest

from datalink_client._commands import (
    TIME_UNSET_VALUE,
    auth_jwt,
    auth_userpass,
    bye,
    identify,
    info,
    match,
    position_after,
    position_set,
    read,
    reject,
    stream,
    write,
)
from datalink_client.protocol import DataLinkError, DataLinkPacket, DataLinkResponse


class TestIdentify:
    def test_header(self):
        cmd = identify("myclient")
        assert cmd.header == "ID myclient"
        assert cmd.payload is None

    def test_parse_extracts_raw_id(self):
        cmd = identify("myclient")
        assert cmd.parse("ID some server info :: WRITE", None) == "some server info :: WRITE"

    def test_parse_rejects_non_id_reply(self):
        cmd = identify("myclient")
        with pytest.raises(DataLinkError, match="Expected ID reply"):
            cmd.parse("ERROR 1 0", None)


class TestAuth:
    def test_userpass_header_and_payload(self):
        cmd = auth_userpass("alice", "secret")
        assert cmd.header == "AUTH USERPASS 12"
        assert cmd.payload == b"alice\rsecret"
        assert cmd.parse is not None

    def test_jwt_header_and_payload(self):
        cmd = auth_jwt("tok.en")
        assert cmd.header == "AUTH JWT 6"
        assert cmd.payload == b"tok.en"

    def test_userpass_parse_returns_response_on_ok(self):
        cmd = auth_userpass("alice", "secret")
        resp = cmd.parse("OK 0 0", None)
        assert isinstance(resp, DataLinkResponse)
        assert bool(resp) is True

    def test_userpass_parse_raises_on_error(self):
        cmd = auth_userpass("alice", "secret")
        with pytest.raises(DataLinkError):
            cmd.parse("ERROR 1 0", b"bad credentials")


class TestPosition:
    def test_set_without_time_omits_time_from_wire(self):
        cmd = position_set("LATEST")
        assert cmd.header == "POSITION SET LATEST"

    def test_set_with_int_time(self):
        cmd = position_set(5, 123456)
        assert cmd.header == "POSITION SET 5 123456"

    def test_set_with_string_time_converts(self):
        cmd = position_set(5, "1970-01-01T00:00:01Z")
        assert cmd.header == "POSITION SET 5 1000000"

    def test_set_with_explicit_unset_sentinel_omits_time(self):
        cmd = position_set(5, TIME_UNSET_VALUE)
        assert cmd.header == "POSITION SET 5"

    def test_set_invalid_time_string_raises_datalinkerror(self):
        with pytest.raises(DataLinkError, match="Invalid time string"):
            position_set(5, "not-a-date")

    def test_after_with_int_time(self):
        cmd = position_after(999)
        assert cmd.header == "POSITION AFTER 999"

    def test_after_invalid_time_string_raises_datalinkerror(self):
        with pytest.raises(DataLinkError, match="Invalid time string"):
            position_after("not-a-date")


class TestMatchReject:
    def test_match_header_and_payload(self):
        cmd = match("FDSN:IU_.*")
        assert cmd.header == "MATCH 10"
        assert cmd.payload == b"FDSN:IU_.*"

    def test_reject_header_and_payload(self):
        cmd = reject("FDSN:IU_.*")
        assert cmd.header == "REJECT 10"
        assert cmd.payload == b"FDSN:IU_.*"


class TestWrite:
    def test_noack_no_pktid(self):
        cmd = write("sid", 1, 2, b"hello")
        assert cmd.header == "WRITE sid 1 2 N 5"
        assert cmd.payload == b"hello"
        assert cmd.parse is None  # no reply expected

    def test_ack_with_pktid(self):
        cmd = write("sid", 1, 2, b"hello", ack=True, pktid=7)
        assert cmd.header == "WRITE sid 1 2 IA 5 7"
        assert cmd.parse is not None

    def test_ack_without_pktid(self):
        cmd = write("sid", 1, 2, b"hello", ack=True)
        assert cmd.header == "WRITE sid 1 2 A 5"

    def test_pktid_without_ack(self):
        cmd = write("sid", 1, 2, b"hello", pktid=3)
        assert cmd.header == "WRITE sid 1 2 IN 5 3"
        assert cmd.parse is None

    def test_size_uses_nbytes_not_len_for_memoryview(self):
        # M4: an int-typed memoryview has len() == element count, not byte
        # count; the wire size must reflect actual bytes to avoid desync.
        from array import array

        data = memoryview(array("i", [1, 2, 3, 4]))  # 4 elements, 16 bytes
        assert len(data) == 4
        cmd = write("sid", 1, 2, data)
        assert cmd.header == "WRITE sid 1 2 N 16"


class TestRead:
    def test_header(self):
        cmd = read(42)
        assert cmd.header == "READ 42"
        assert cmd.payload is None

    def test_parse_valid_packet(self):
        cmd = read(42)
        pkt = cmd.parse("PACKET sid 42 10 20 30 3", b"abc")
        assert isinstance(pkt, DataLinkPacket)
        assert pkt.pktid == 42

    def test_parse_error_reply_raises(self):
        cmd = read(42)
        with pytest.raises(DataLinkError, match="not found"):
            cmd.parse("ERROR 1 9", b"not found")

    def test_parse_unexpected_reply_raises(self):
        cmd = read(42)
        with pytest.raises(DataLinkError, match="Expected PACKET reply"):
            cmd.parse("OK 0 0", None)


class TestFireAndForget:
    def test_bye_no_reply_expected(self):
        cmd = bye()
        assert cmd.header == "BYE"
        assert cmd.payload is None
        assert cmd.parse is None

    def test_stream_no_reply_expected(self):
        cmd = stream()
        assert cmd.header == "STREAM"
        assert cmd.parse is None


class TestInfo:
    def test_without_match(self):
        cmd = info("STATUS")
        assert cmd.header == "INFO STATUS"
        assert cmd.payload is None

    def test_with_match(self):
        cmd = info("STREAMS", "IU_.*")
        assert cmd.header == "INFO STREAMS 5"
        assert cmd.payload == b"IU_.*"

    def test_parse_returns_decoded_xml(self):
        cmd = info("STATUS")
        assert cmd.parse("INFO 11", b"<DataLink/>") == "<DataLink/>"

    def test_parse_error_reply_raises(self):
        cmd = info("STATUS")
        with pytest.raises(DataLinkError):
            cmd.parse("ERROR 1 0", b"bad match expression")

    def test_parse_unexpected_reply_raises(self):
        cmd = info("STATUS")
        with pytest.raises(DataLinkError, match="Expected INFO reply"):
            cmd.parse("OK 0 0", None)
