"""Tests for datalink_client.time_utils."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from datalink_client.time_utils import (
    _normalize_timestring,
    timestring_to_ustime,
    ustime_to_timestring,
)

# 2025-02-06T10:30:00Z
_REF = datetime(2025, 2, 6, 10, 30, 0, tzinfo=timezone.utc)
_REF_US = int(_REF.timestamp() * 1_000_000)
# 2025-02-06T00:00:00Z
_REF_DATE_ONLY = datetime(2025, 2, 6, 0, 0, 0, tzinfo=timezone.utc)
_REF_DATE_ONLY_US = int(_REF_DATE_ONLY.timestamp() * 1_000_000)


class TestNormalizeTimestring:
    def test_already_normalized(self):
        assert (
            _normalize_timestring("2026-02-09T16:22:00")
            == "2026-02-09T16:22:00"
        )

    def test_single_digit_month_and_day(self):
        assert (
            _normalize_timestring("2026-2-9T16:22:00")
            == "2026-02-09T16:22:00"
        )

    def test_single_digit_month_only(self):
        assert (
            _normalize_timestring("2026-2-09T00:00:00")
            == "2026-02-09T00:00:00"
        )

    def test_single_digit_day_only(self):
        assert (
            _normalize_timestring("2026-02-9T00:00:00")
            == "2026-02-09T00:00:00"
        )

    def test_single_digit_hms(self):
        assert (
            _normalize_timestring("2026-01-01T0:1:1")
            == "2026-01-01T00:01:01"
        )

    def test_space_separator(self):
        assert (
            _normalize_timestring("2026-02-09 16:22:00")
            == "2026-02-09T16:22:00"
        )

    def test_z_suffix(self):
        assert (
            _normalize_timestring("2026-02-09T16:22:00Z")
            == "2026-02-09T16:22:00+00:00"
        )

    def test_date_only(self):
        assert (
            _normalize_timestring("2026-02-09")
            == "2026-02-09T00:00:00"
        )

    def test_date_only_single_digit(self):
        assert (
            _normalize_timestring("2026-2-9")
            == "2026-02-09T00:00:00"
        )

    def test_fractional_seconds_preserved(self):
        # Fractional seconds pass through the HMS pad unchanged.
        assert (
            _normalize_timestring("2026-02-09T16:22:00.123456")
            == "2026-02-09T16:22:00.123456"
        )

    def test_explicit_offset_preserved(self):
        assert (
            _normalize_timestring("2026-02-09T16:22:00+08:00")
            == "2026-02-09T16:22:00+08:00"
        )

    def test_whitespace_stripped(self):
        assert (
            _normalize_timestring("  2026-02-09T16:22:00  ")
            == "2026-02-09T16:22:00"
        )


class TestTimestringToUstime:
    def test_basic_iso(self):
        assert timestring_to_ustime("2025-02-06T10:30:00Z") == _REF_US

    def test_fractional_seconds(self):
        assert (
            timestring_to_ustime("2025-02-06T10:30:00.123456Z")
            == _REF_US + 123_456
        )

    def test_no_timezone_is_utc(self):
        assert timestring_to_ustime("2025-02-06T10:30:00") == _REF_US

    def test_lenient_parsing(self):
        assert timestring_to_ustime("2025-2-6T10:30:00") == _REF_US

    def test_date_only(self):
        assert timestring_to_ustime("2025-02-06") == _REF_DATE_ONLY_US

    def test_invalid_raises_valueerror(self):
        with pytest.raises(ValueError):
            timestring_to_ustime("not-a-date")


class TestRoundTrip:
    @pytest.mark.parametrize(
        "ustime",
        [
            0,
            1_000_000,
            _REF_US,
            _REF_US + 123_456,
        ],
    )
    def test_round_trip(self, ustime):
        s = ustime_to_timestring(ustime)
        assert timestring_to_ustime(s) == ustime

    def test_ustime_format(self):
        s = ustime_to_timestring(_REF_US + 123_456)
        assert s == "2025-02-06T10:30:00.123456Z"
