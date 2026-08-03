"""Tests for datalink_client.protocol (typed_attrs, dataclasses, exceptions)."""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from datalink_client.protocol import (
    DL_MAGIC,
    MAX_HEADER_LEN,
    MAX_PAYLOAD_SIZE,
    PREHEADER_LEN,
    DataLinkError,
    DataLinkPacket,
    DataLinkResponse,
    StreamEvent,
    classify_stream_packet,
    encode_frame,
    expect_ok,
    expected_payload_size,
    generate_client_id,
    parse_capabilities,
    parse_info_xml,
    parse_packet,
    parse_response,
    typed_attrs,
    validate_preheader_magic,
)


class TestConstants:
    def test_magic_is_two_bytes(self):
        assert DL_MAGIC == b"DL"
        assert len(DL_MAGIC) == 2

    def test_preheader_len(self):
        assert PREHEADER_LEN == 3

    def test_max_header_len_fits_in_byte(self):
        assert MAX_HEADER_LEN == 255


class TestTypedAttrs:
    def test_int_attr_parsed(self):
        el = ET.fromstring('<x RingSize="12345" />')
        assert typed_attrs(el) == {"RingSize": 12345}

    def test_float_attr_parsed(self):
        el = ET.fromstring('<x TXByteRate="1.5" />')
        assert typed_attrs(el) == {"TXByteRate": 1.5}

    def test_bool_attr_true(self):
        el = ET.fromstring('<x VolatileRing="TRUE" />')
        assert typed_attrs(el) == {"VolatileRing": True}

    def test_bool_attr_false(self):
        el = ET.fromstring('<x VolatileRing="FALSE" />')
        assert typed_attrs(el) == {"VolatileRing": False}

    def test_bool_attr_variations(self):
        assert typed_attrs(ET.fromstring('<x VolatileRing="1" />'))["VolatileRing"] is True
        assert typed_attrs(ET.fromstring('<x VolatileRing="yes" />'))["VolatileRing"] is True
        assert typed_attrs(ET.fromstring('<x VolatileRing="0" />'))["VolatileRing"] is False

    def test_unknown_attr_stays_string(self):
        el = ET.fromstring('<x Name="abc" />')
        assert typed_attrs(el) == {"Name": "abc"}

    def test_dash_becomes_none(self):
        el = ET.fromstring('<x RingSize="-" Name="-" />')
        assert typed_attrs(el) == {"RingSize": None, "Name": None}

    def test_int_with_bad_value_falls_back_to_string(self):
        el = ET.fromstring('<x RingSize="not-a-number" />')
        assert typed_attrs(el) == {"RingSize": "not-a-number"}

    def test_multiple_attrs(self):
        el = ET.fromstring(
            '<x RingSize="100" TXByteRate="2.5" VolatileRing="TRUE" Name="ringA" />'
        )
        result = typed_attrs(el)
        assert result == {
            "RingSize": 100,
            "TXByteRate": 2.5,
            "VolatileRing": True,
            "Name": "ringA",
        }


class TestDataLinkPacket:
    def test_dataclass_fields(self):
        pkt = DataLinkPacket(
            streamid="FDSN:IU_ANMO_00_B_H_Z/MSEED",
            pktid=42,
            pkttime=1_000_000,
            datastart=2_000_000,
            dataend=3_000_000,
            data=b"payload",
        )
        assert pkt.streamid == "FDSN:IU_ANMO_00_B_H_Z/MSEED"
        assert pkt.pktid == 42
        assert pkt.pkttime == 1_000_000
        assert pkt.datastart == 2_000_000
        assert pkt.dataend == 3_000_000
        assert pkt.data == b"payload"


class TestDataLinkResponse:
    def test_ok_is_truthy(self):
        resp = DataLinkResponse(status="OK", value=0, message=None)
        assert bool(resp) is True

    def test_error_is_falsy(self):
        resp = DataLinkResponse(status="ERROR", value=1, message="bad")
        assert bool(resp) is False

    def test_unknown_status_is_falsy(self):
        resp = DataLinkResponse(status="", value=0, message=None)
        assert bool(resp) is False


class TestDataLinkError:
    def test_default_value_is_zero(self):
        e = DataLinkError("something failed")
        assert str(e) == "something failed"
        assert e.value == 0

    def test_custom_value(self):
        e = DataLinkError("bad", 42)
        assert e.value == 42

    def test_is_exception(self):
        with pytest.raises(DataLinkError):
            raise DataLinkError("boom")


class TestEncodeFrame:
    def test_builds_magic_length_header(self):
        frame = encode_frame("ID foo")
        assert frame[:2] == DL_MAGIC
        assert frame[2] == len(b"ID foo")
        assert frame[3:] == b"ID foo"

    def test_exactly_max_len_ok(self):
        header = "X" * MAX_HEADER_LEN
        frame = encode_frame(header)
        assert frame[2] == MAX_HEADER_LEN

    def test_too_long_raises(self):
        with pytest.raises(DataLinkError, match="Header length"):
            encode_frame("X" * (MAX_HEADER_LEN + 1))

    def test_non_ascii_raises(self):
        with pytest.raises(DataLinkError, match="not ASCII"):
            encode_frame("WRITE FDSN:XX_ÜÜ/MSEED 0 0 N 4")

    def test_returns_immutable_bytes(self):
        assert isinstance(encode_frame("ID foo"), bytes)


class TestValidatePreheaderMagic:
    def test_valid_magic_ok(self):
        validate_preheader_magic(b"DL\x05")  # must not raise

    def test_invalid_magic_raises(self):
        with pytest.raises(DataLinkError, match="Invalid preheader magic"):
            validate_preheader_magic(b"XX\x05")


class TestExpectedPayloadSize:
    @pytest.mark.parametrize(
        "header,expected",
        [
            ("OK 42 5", 5),
            ("ERROR 1 10", 10),
            ("PACKET sid 1 10 20 30 7", 7),
            ("INFO STATUS 100", 100),
            ("ID some server string", 0),
            ("ENDSTREAM", 0),
            ("OK 42 0", 0),
            ("OK 42", 0),  # size token missing entirely
        ],
    )
    def test_known_types(self, header, expected):
        assert expected_payload_size(header) == expected

    def test_unrecognized_type_raises(self):
        with pytest.raises(DataLinkError, match="Unrecognized packet type"):
            expected_payload_size("WEIRD 1 2 3")

    def test_oversized_payload_raises(self):
        with pytest.raises(DataLinkError, match="exceeds sanity limit"):
            expected_payload_size(f"OK 42 {MAX_PAYLOAD_SIZE + 1}")

    def test_negative_size_raises(self):
        with pytest.raises(DataLinkError, match="Negative payload size"):
            expected_payload_size("OK 42 -5")

    def test_non_numeric_size_raises(self):
        with pytest.raises(DataLinkError, match="Non-numeric payload size"):
            expected_payload_size("OK 42 notanumber")

    def test_at_sanity_limit_is_ok(self):
        assert expected_payload_size(f"OK 42 {MAX_PAYLOAD_SIZE}") == MAX_PAYLOAD_SIZE


class TestParseResponseAndExpectOk:
    def test_parse_response_ok_with_message(self):
        resp = parse_response("OK 42 5", b"hello")
        assert resp.status == "OK"
        assert resp.value == 42
        assert resp.message == "hello"

    def test_expect_ok_raises_on_error(self):
        with pytest.raises(DataLinkError, match="bad"):
            expect_ok("ERROR 1 3", b"bad")

    def test_expect_ok_passes_through_ok(self):
        resp = expect_ok("OK 7 0", None)
        assert resp.value == 7


class TestParsePacketPure:
    def test_valid(self):
        pkt = parse_packet("PACKET sid 1 10 20 30 3", b"abc")
        assert pkt.streamid == "sid"
        assert pkt.pktid == 1
        assert pkt.data == b"abc"

    def test_invalid_raises(self):
        with pytest.raises(DataLinkError):
            parse_packet("PACKET sid 1 10", b"")


class TestParseInfoXmlPure:
    def test_status(self):
        xml = '<DataLink><Status RingSize="100" /></DataLink>'
        result = parse_info_xml(xml)
        assert result["Status"]["RingSize"] == 100

    def test_malformed_raises(self):
        with pytest.raises(DataLinkError, match="Malformed INFO XML"):
            parse_info_xml("not valid <xml")


class TestParseCapabilities:
    def test_no_double_colon_returns_empty(self):
        assert parse_capabilities("just a server string") == {}

    def test_flag_and_valued_capabilities(self):
        caps = parse_capabilities("server v1 :: WRITE DLPROTO:1.0 AUTH:JWT")
        assert caps == {"WRITE": True, "DLPROTO": "1.0", "AUTH": "JWT"}


class TestGenerateClientId:
    def test_uses_given_program_name(self):
        cid = generate_client_id("myprog")
        parts = cid.split(":")
        assert parts[0] == "myprog"
        assert len(parts) == 4  # program:user:pid:platform

    def test_pid_is_numeric(self):
        cid = generate_client_id("myprog")
        pid_field = cid.split(":")[2]
        assert pid_field.isdigit()


class TestClassifyStreamPacket:
    @pytest.mark.parametrize(
        "header,expected",
        [
            ("PACKET sid 1 2 3 4 5", StreamEvent.PACKET),
            ("ENDSTREAM", StreamEvent.ENDSTREAM),
            ("ERROR 1 2", StreamEvent.ERROR),
            ("OK 1 2", StreamEvent.OTHER),
            ("", StreamEvent.OTHER),
        ],
    )
    def test_classification(self, header, expected):
        assert classify_stream_packet(header) == expected
