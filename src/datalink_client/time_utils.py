"""Epoch microsecond time conversion utilities."""

import re
import time as _time
from datetime import datetime, timezone

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def ustime_to_timestring(ustime: int) -> str:
    """Convert epoch microseconds to an ISO 8601 UTC string.

    DataLink timestamps are Unix/POSIX epoch times in microseconds.

    Args:
        ustime: Epoch time in microseconds.

    Returns:
        String in ``YYYY-MM-DDThh:mm:ss.ssssssZ`` format.
    """
    sec, frac = divmod(ustime, 1_000_000)
    t = _time.gmtime(sec)
    return (
        f"{t.tm_year:04d}-{t.tm_mon:02d}-{t.tm_mday:02d}T"
        f"{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}.{frac:06d}Z"
    )


def _normalize_timestring(timestring: str) -> str:
    """Normalize a datetime string to strict ISO 8601 for fromisoformat().

    Handles:
      - Single-digit month/day (2026-2-9 → 2026-02-09)
      - Single-digit hour/minute/second (0:1:1 → 00:01:01)
      - Space separator instead of T (2026-02-09 16:00 → 2026-02-09T16:00)
      - Z suffix → +00:00
      - Date-only strings (2026-02-09 → 2026-02-09T00:00:00)
    """
    s = timestring.strip()

    # Zero-pad month and day: 2026-2-9 → 2026-02-09
    m = re.match(r"^(\d{4})-(\d{1,2})-(\d{1,2})(.*)", s)
    if m:
        s = f"{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d}{m.group(4)}"

    # Replace space separator with T
    s = re.sub(r"^(\d{4}-\d{2}-\d{2})\s+(\d)", r"\1T\2", s)

    # Zero-pad hour, minute, second: 0:1:1 → 00:01:01
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T)(\d{1,2}):(\d{1,2}):(\d{1,2})(.*)", s)
    if m:
        s = f"{m.group(1)}{int(m.group(2)):02d}:{int(m.group(3)):02d}:{int(m.group(4)):02d}{m.group(5)}"

    # Z suffix → +00:00
    s = s.replace("Z", "+00:00")

    # Date-only → append T00:00:00
    if re.match(r"^\d{4}-\d{2}-\d{2}$", s):
        s += "T00:00:00"

    return s


def timestring_to_ustime(timestring: str) -> int:
    """Convert a datetime string to epoch microseconds.

    Accepts ISO 8601 strings and relaxed variants:
      - ``2025-02-06T10:30:00.123456Z``
      - ``2025-2-6T10:30:00`` (single-digit month/day)
      - ``2025-02-06 10:30:00`` (space instead of T)
      - ``2025-02-06`` (date only, midnight UTC)
      - Timezone ``Z``, ``+00:00``, or omitted (treated as UTC)

    Args:
        timestring: Datetime string.

    Returns:
        Epoch time in microseconds.
    """
    normalized = _normalize_timestring(timestring)
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - _EPOCH
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds
