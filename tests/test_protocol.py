"""Tests for datalink_client.protocol (typed_attrs, dataclasses, exceptions)."""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from datalink_client.protocol import (
    DL_MAGIC,
    MAX_HEADER_LEN,
    PREHEADER_LEN,
    DataLinkError,
    DataLinkPacket,
    DataLinkResponse,
    typed_attrs,
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
