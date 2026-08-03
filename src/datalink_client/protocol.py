"""DataLink protocol wire codec: framing, header/reply parsing, and types.

Everything in this module is pure (no sockets, no I/O), so it is shared
verbatim by both the synchronous :class:`~datalink_client.client.DataLink`
and the asyncio-based :class:`~datalink_client.aio.AsyncDataLink`. Each
transport is responsible only for getting bytes on and off the wire; every
decision about what those bytes *mean* is made here.
"""

from __future__ import annotations

import os
import platform
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from enum import Enum
from typing import Any, Union

# Anything accepted as a WRITE/send payload: a buffer-protocol type shared by
# both the sync (socket) and async (asyncio streams) transports.
BufferLike = Union[bytes, bytearray, memoryview]

# Preheader magic
DL_MAGIC = b"DL"
PREHEADER_LEN = 3
MAX_HEADER_LEN = 255

# Sanity cap on a declared PACKET/OK/ERROR/INFO payload size. A corrupt or
# malicious header could otherwise claim an enormous size and force the
# reader to allocate/wait for a buffer far beyond any real DataLink payload
# (miniSEED records are typically <=4 KiB; even large custom payloads are
# nowhere near this). 256 MiB is generous headroom while still bounding the
# damage from a garbage header.
#
# A large INFO reply (e.g. STREAMS on a server with many streams) can
# legitimately approach this cap; parsing it holds the raw bytes, decoded
# string, XML tree, and result dict at once, so peak memory for one INFO
# call scales with the reply size.
MAX_PAYLOAD_SIZE = 256 * 1024 * 1024

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


class DataLinkTimeout(DataLinkError, TimeoutError):
    """Raised when a socket operation exceeds its timeout.

    Inherits from both :class:`DataLinkError` and the built-in
    :class:`TimeoutError` (which ``socket.timeout`` is an alias of), so it
    can be caught as either.
    """


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------

def encode_frame(header: str) -> bytes:
    """Build a DataLink preheader + header frame.

    Payload bytes, if any, are appended separately by the transport.

    Raises:
        DataLinkError: if the header isn't ASCII, or its encoded length
            exceeds ``MAX_HEADER_LEN``.
    """
    try:
        header_bytes = header.encode("ascii")
    except UnicodeEncodeError as e:
        raise DataLinkError(f"Header is not ASCII: {header!r}") from e
    hlen = len(header_bytes)
    if hlen > MAX_HEADER_LEN:
        raise DataLinkError(f"Header length {hlen} exceeds {MAX_HEADER_LEN}")
    frame = bytearray(3 + hlen)
    frame[0:2] = DL_MAGIC
    frame[2] = hlen
    frame[3:] = header_bytes
    return bytes(frame)


def validate_preheader_magic(pre: bytes) -> None:
    """Raise DataLinkError if the first two bytes of `pre` aren't the DL magic.

    Closing the connection on failure is the transport's responsibility, not
    this function's.
    """
    if pre[:2] != DL_MAGIC:
        raise DataLinkError(f"Invalid preheader magic: {pre[:2]!r}")


def expected_payload_size(header: str) -> int:
    """Return the payload size in bytes declared by a raw DataLink header.

    Per the DataLink 1.1 wire format, only OK/ERROR/PACKET/INFO replies carry
    a declared payload size, at a fixed token position; ID and ENDSTREAM never
    do. Any other packet type means the connection is desynchronized, since
    there is then no way to know how many bytes to skip before the next frame.

    Raises:
        DataLinkError: for an unrecognized packet type, a size token that
            isn't a non-negative integer, or a declared size larger than
            ``MAX_PAYLOAD_SIZE`` (a corrupt or malicious header could
            otherwise force an unbounded buffer wait/allocation, or desync
            the stream by under-reading a payload it failed to size).
    """
    parts = header.split(None, 1)
    packet_type = parts[0] if parts else ""
    if packet_type in ("ID", "ENDSTREAM"):
        return 0
    if packet_type in ("OK", "ERROR", "INFO"):
        idx = 2
    elif packet_type == "PACKET":
        idx = 6
    else:
        raise DataLinkError(
            f"Unrecognized packet type {packet_type!r}; cannot determine "
            "data payload size (stream was desynchronized)."
        )
    tokens = header.split()
    if len(tokens) <= idx:
        return 0
    try:
        size = int(tokens[idx])
    except ValueError:
        raise DataLinkError(
            f"Non-numeric payload size {tokens[idx]!r} in header "
            f"(stream was desynchronized): {header}"
        ) from None
    if size < 0:
        raise DataLinkError(
            f"Negative payload size {size} in header "
            f"(stream was desynchronized): {header}"
        )
    if size == 0:
        return 0
    if size > MAX_PAYLOAD_SIZE:
        raise DataLinkError(
            f"Declared payload size {size} exceeds sanity limit "
            f"{MAX_PAYLOAD_SIZE} (stream may be desynchronized or corrupt)."
        )
    return size


# ---------------------------------------------------------------------------
# Reply / packet parsing
# ---------------------------------------------------------------------------

def parse_response(header: str, data: bytes | None) -> DataLinkResponse:
    """Parse an OK/ERROR header (plus optional message payload) into a
    :class:`DataLinkResponse`."""
    parts = header.split(None, 2)
    status = parts[0] if parts else ""
    value = 0
    if len(parts) >= 2:
        try:
            value = int(parts[1])
        except ValueError:
            pass
    message = data.decode("utf-8", errors="replace") if data else None
    return DataLinkResponse(status=status, value=value, message=message)


def expect_ok(header: str, data: bytes | None) -> DataLinkResponse:
    """Like :func:`parse_response`, but raise DataLinkError if status is ERROR."""
    resp = parse_response(header, data)
    if resp.status == "ERROR":
        raise DataLinkError(resp.message or "Server returned ERROR", resp.value)
    return resp


def parse_packet(header: str, data: bytes | None) -> DataLinkPacket:
    """Parse a PACKET header (plus its payload) into a :class:`DataLinkPacket`."""
    tokens = header.split()
    if len(tokens) < 7:
        raise DataLinkError(f"Invalid PACKET header: {header}")
    try:
        streamid = tokens[1]
        pktid = int(tokens[2])
        pkttime = int(tokens[3])
        datastart = int(tokens[4])
        dataend = int(tokens[5])
        int(tokens[6])  # validate data_size field is numeric
    except (ValueError, IndexError) as e:
        raise DataLinkError(f"Invalid PACKET header: {e}") from e
    payload = data if data is not None else b""
    return DataLinkPacket(
        streamid=streamid,
        pktid=pktid,
        pkttime=pkttime,
        datastart=datastart,
        dataend=dataend,
        data=payload,
    )


def parse_info_xml(xml_string: str) -> dict[str, Any]:
    """Parse an INFO reply's XML body into a nested dict of typed values.

    For a large reply (e.g. STREAMS on a server with many streams), the
    parsed tree and the result dict are briefly held at once; the tree is
    cleared before returning so its elements don't outlive this call.
    """
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as e:
        raise DataLinkError(f"Malformed INFO XML from server: {e}") from e
    result = typed_attrs(root)
    status_el = root.find("Status")
    if status_el is not None:
        result["Status"] = typed_attrs(status_el)
    threads_el = root.find("ServerThreads")
    if threads_el is not None:
        threads_info = typed_attrs(threads_el)
        threads_info["Thread"] = [typed_attrs(t) for t in threads_el.findall("Thread")]
        result["ServerThreads"] = threads_info
    slist_el = root.find("StreamList")
    if slist_el is not None:
        slist_info = typed_attrs(slist_el)
        slist_info["Stream"] = [typed_attrs(s) for s in slist_el.findall("Stream")]
        result["StreamList"] = slist_info
    clist_el = root.find("ConnectionList")
    if clist_el is not None:
        clist_info = typed_attrs(clist_el)
        clist_info["Connection"] = [typed_attrs(c) for c in clist_el.findall("Connection")]
        result["ConnectionList"] = clist_info
    root.clear()
    return result


def parse_capabilities(raw: str) -> dict[str, str | bool]:
    """Parse the capabilities segment of a server ID reply.

    The raw ID string looks like ``"<server info> :: CAP1 CAP2:value ..."``.
    Capability tokens without a ``:value`` suffix are stored as ``True``.
    """
    capabilities: dict[str, str | bool] = {}
    if "::" in raw:
        caps_str = raw.split("::", 1)[1].strip()
        for token in caps_str.split():
            if ":" in token:
                key, value = token.split(":", 1)
                capabilities[key] = value
            else:
                capabilities[token] = True
    return capabilities


def generate_client_id(program_name: str | None = None) -> str:
    """Build a client identification string: ``'<program>:<user>:<pid>:<platform>'``."""
    if program_name is None:
        main_module = sys.modules["__main__"]
        if hasattr(main_module, "__file__"):
            program_name = os.path.basename(main_module.__file__)
        else:
            program_name = "DataLink Client"
    try:
        import getpass
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    pid = os.getpid()
    arch = platform.platform(terse=True) or platform.system()
    return f"{program_name}:{user}:{pid}:{arch}"


# ---------------------------------------------------------------------------
# Streaming-mode header classification
# ---------------------------------------------------------------------------

class StreamEvent(Enum):
    """Classification of a received header while in streaming mode.

    Shared by both transports' ``collect()`` and ``endstream()`` loops, so
    the decision of what a header *means* is made in exactly one place.
    """

    PACKET = "PACKET"
    ENDSTREAM = "ENDSTREAM"
    ERROR = "ERROR"
    OTHER = "OTHER"


def classify_stream_packet(header: str) -> StreamEvent:
    packet_type = header.split(None, 1)[0] if header else ""
    if packet_type == "PACKET":
        return StreamEvent.PACKET
    if packet_type == "ENDSTREAM":
        return StreamEvent.ENDSTREAM
    if packet_type == "ERROR":
        return StreamEvent.ERROR
    return StreamEvent.OTHER
