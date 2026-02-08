"""Epoch microsecond time conversion utilities."""

from datetime import datetime, timezone, timedelta

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def ustime_to_timestring(ustime: int) -> str:
    """Convert epoch microseconds to an ISO 8601 UTC string.

    DataLink timestamps are Unix/POSIX epoch times in microseconds.

    Args:
        ustime: Epoch time in microseconds.

    Returns:
        String in ``YYYY-MM-DDThh:mm:ss.ssssssZ`` format.
    """
    sec = ustime // 1_000_000
    frac = ustime % 1_000_000
    dt = _EPOCH + timedelta(seconds=sec, microseconds=frac)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{dt.microsecond:06d}Z"


def timestring_to_ustime(timestring: str) -> int:
    """Convert an ISO 8601 string to epoch microseconds.

    Accepts strings with ``Z``, ``+00:00``, or no timezone (treated as UTC).

    Args:
        timestring: ISO 8601 datetime string.

    Returns:
        Epoch time in microseconds.
    """
    dt = datetime.fromisoformat(timestring.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - _EPOCH
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds
