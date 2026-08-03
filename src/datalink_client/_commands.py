"""The DataLink command vocabulary: pure request/reply builders, no I/O.

Every DataLink command has the same shape: build a header (and maybe a
payload), send it, and — for all but a few fire-and-forget commands — read
back exactly one reply and parse it. A :class:`Command` captures that shape
as data. Both transports (:class:`~datalink_client.client.DataLink` and
:class:`~datalink_client.aio.AsyncDataLink`) execute a ``Command`` with the
same six-line dispatch:

    send(cmd.header, cmd.payload)
    if cmd.parse is None:
        return None
    header, data = recv()
    return cmd.parse(header, data)

so this module is the single place the request/reply shape of each command
is defined, and the only thing that differs between transports is *how*
bytes get sent and received.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .protocol import (
    BufferLike,
    DataLinkError,
    DataLinkPacket,
    expect_ok,
    parse_packet,
    parse_response,
)
from .time_utils import timestring_to_ustime

# Sentinel meaning "no time value supplied" for POSITION SET, distinct from
# any real epoch-microsecond time (including 0 and negative values).
TIME_UNSET_VALUE: int = -(2**63)


@dataclass(frozen=True)
class Command:
    """A DataLink request plus how to interpret its reply.

    Attributes:
        header:  The ASCII header line to send (without preheader framing).
        payload: Optional payload bytes to send after the header.
        parse:   Callable to turn ``(reply_header, reply_data)`` into a
                 result, or ``None`` if this command expects no reply at all
                 (e.g. ``BYE``, ``STREAM``, or an unacknowledged ``WRITE``).
    """

    header: str
    payload: BufferLike | None = None
    parse: Callable[[str, bytes | None], Any] | None = None


def _coerce_ustime(value: int | str) -> int:
    """Convert a time string to epoch microseconds; pass integers through."""
    if isinstance(value, str):
        try:
            return timestring_to_ustime(value)
        except ValueError as e:
            raise DataLinkError(f"Invalid time string {value!r}: {e}") from e
    return value


def identify(clientid: str) -> Command:
    def _parse(header: str, data: bytes | None) -> str:
        if not header.startswith("ID "):
            raise DataLinkError(f"Expected ID reply, got: {header[:50]}")
        return header[3:].strip()

    return Command(f"ID {clientid}", None, _parse)


def auth_userpass(username: str, password: str) -> Command:
    payload = f"{username}\r{password}".encode("utf-8")
    return Command(f"AUTH USERPASS {len(payload)}", payload, expect_ok)


def auth_jwt(token: str) -> Command:
    payload = token.encode("utf-8")
    return Command(f"AUTH JWT {len(payload)}", payload, expect_ok)


def position_set(pktid: str | int, uspkttime: int | str = TIME_UNSET_VALUE) -> Command:
    t = _coerce_ustime(uspkttime)
    if t == TIME_UNSET_VALUE:
        header = f"POSITION SET {pktid}"
    else:
        header = f"POSITION SET {pktid} {t}"
    return Command(header, None, expect_ok)


def position_after(ustime: int | str) -> Command:
    t = _coerce_ustime(ustime)
    return Command(f"POSITION AFTER {t}", None, expect_ok)


def match(pattern: str) -> Command:
    payload = pattern.encode("utf-8")
    return Command(f"MATCH {len(payload)}", payload, expect_ok)


def reject(pattern: str) -> Command:
    payload = pattern.encode("utf-8")
    return Command(f"REJECT {len(payload)}", payload, expect_ok)


def write(
    streamid: str,
    datastart: int,
    dataend: int,
    data: BufferLike,
    ack: bool = False,
    pktid: int | None = None,
) -> Command:
    flags = ("I" if pktid is not None else "") + ("A" if ack else "N")
    # nbytes: a memoryview over a non-byte itemsize (e.g. array('i', ...))
    # has fewer elements than bytes; the header must declare the byte count.
    size = memoryview(data).nbytes
    header = f"WRITE {streamid} {datastart} {dataend} {flags} {size}"
    if pktid is not None:
        header += f" {pktid}"
    return Command(header, data, expect_ok if ack else None)


def read(pktid: int) -> Command:
    def _parse(header: str, data: bytes | None) -> DataLinkPacket:
        if header.startswith("ERROR"):
            resp = parse_response(header, data)
            raise DataLinkError(resp.message or "READ failed", resp.value)
        if not header.startswith("PACKET "):
            raise DataLinkError(f"Expected PACKET reply, got: {header[:50]}")
        return parse_packet(header, data)

    return Command(f"READ {pktid}", None, _parse)


def bye() -> Command:
    return Command("BYE", None, None)


def stream() -> Command:
    return Command("STREAM", None, None)


def info(info_type: str, match_expr: str | None = None) -> Command:
    def _parse(header: str, data: bytes | None) -> str:
        if header.startswith("ERROR"):
            resp = parse_response(header, data)
            raise DataLinkError(resp.message or "INFO failed", resp.value)
        if not header.startswith("INFO "):
            raise DataLinkError(f"Expected INFO reply, got: {header[:50]}")
        return (data or b"").decode("utf-8", errors="replace")

    if match_expr is not None:
        match_bytes = match_expr.encode("utf-8")
        return Command(f"INFO {info_type} {len(match_bytes)}", match_bytes, _parse)
    return Command(f"INFO {info_type}", None, _parse)
