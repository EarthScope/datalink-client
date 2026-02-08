"""DataLink protocol constants, types, and XML parsing helpers."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any

# Preheader magic
DL_MAGIC = b"DL"
PREHEADER_LEN = 3
MAX_HEADER_LEN = 255

# Attribute names that should be parsed as int, float, or bool in INFO XML.
# Everything else stays as str (including datetime strings).
_INFO_INT_ATTRS: set[str] = {
    "RingVersion", "RingSize", "PacketSize", "MaximumPackets",
    "MaximumPacketID", "TotalConnections", "SelectedConnections",
    "TotalStreams", "SelectedStreams", "TotalServerThreads",
    "EarliestPacketID", "LatestPacketID",
    "StreamCount", "PacketID",
    "TXPacketCount", "TXByteCount", "RXPacketCount", "RXByteCount",
    "PercentLag", "Port", "MaxRecursion",
}

_INFO_FLOAT_ATTRS: set[str] = {
    "TXPacketRate", "TXByteRate", "RXPacketRate", "RXByteRate",
    "DataLatency", "Latency", "ScanTime", "PacketRate", "ByteRate",
}

_INFO_BOOL_ATTRS: set[str] = {
    "MemoryMappedRing", "VolatileRing",
}


def typed_attrs(element: ET.Element) -> dict[str, Any]:
    """Convert an XML element's attributes to a dict with typed values.

    Integer, float, and boolean attribute names are recognized by the
    module-level sets. A value of "-" (used by ringserver for missing/unset
    fields) is converted to None.
    """
    out: dict[str, Any] = {}
    for key, value in element.attrib.items():
        if value == "-":
            out[key] = None
            continue
        if key in _INFO_INT_ATTRS:
            try:
                out[key] = int(value)
            except ValueError:
                out[key] = value
        elif key in _INFO_FLOAT_ATTRS:
            try:
                out[key] = float(value)
            except ValueError:
                out[key] = value
        elif key in _INFO_BOOL_ATTRS:
            out[key] = value.upper() in ("TRUE", "1", "YES")
        else:
            out[key] = value
    return out


@dataclass
class DataLinkPacket:
    """Parsed PACKET response from the server.

    Attributes:
        streamid:   Stream identifier (e.g. 'FDSN:IU_COLA_00_B_H_Z/MSEED').
        pktid:      Integer packet ID.
        pkttime:    Epoch microseconds when the server accepted the packet.
        datastart:  Epoch microseconds of the data start time.
        dataend:    Epoch microseconds of the data end time.
        data:       Raw packet payload bytes.
    """

    streamid: str
    pktid: int
    pkttime: int
    datastart: int
    dataend: int
    data: bytes


@dataclass
class DataLinkResponse:
    """OK or ERROR status response from the server.

    Attributes:
        status:  'OK' or 'ERROR'.
        value:   Integer value whose meaning depends on the command.
        message: Optional human-readable message from the server, or None.
    """

    status: str  # "OK" or "ERROR"
    value: int
    message: str | None

    def __bool__(self) -> bool:
        """True if status is 'OK', False if 'ERROR'."""
        return self.status == "OK"


class DataLinkError(Exception):
    """Raised when the server returns ERROR or on protocol/socket errors.

    Attributes:
        value: The integer value from the server ERROR response (0 if not applicable).
    """

    def __init__(self, message: str, value: int = 0):
        super().__init__(message)
        self.value = value
