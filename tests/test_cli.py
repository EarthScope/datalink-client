"""Tests for datalink_client.cli argument parsing and error handling."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from datalink_client.cli import DataLinkShell, _parse_write_args
from datalink_client.client import DataLink
from datalink_client.protocol import DataLinkError


class TestParseWriteArgs:
    """_parse_write_args must keep multi-word payloads intact and only treat
    a trailing integer as an explicit packet ID."""

    @pytest.mark.parametrize(
        "arg,expected",
        [
            ("sid hello", ("sid", "hello", None)),
            ("sid hello 5", ("sid", "hello", 5)),
            ("sid hello world 5", ("sid", "hello world", 5)),
            ("sid hello world", ("sid", "hello world", None)),
            ("sid  multiple   spaces  here", ("sid", "multiple   spaces  here", None)),
        ],
    )
    def test_multiword_payload_preserved(self, arg, expected):
        assert _parse_write_args(arg) == expected

    def test_missing_payload_returns_none(self):
        assert _parse_write_args("sid") is None

    def test_empty_returns_none(self):
        assert _parse_write_args("") is None


def make_shell(recv_side_effect) -> DataLinkShell:
    """Build a DataLinkShell with a "connected" mock socket."""
    dl = DataLink(host="localhost", port=16000, tls=False)
    dl._sock = MagicMock()
    dl._sock.sendmsg = MagicMock(
        side_effect=lambda bufs: sum(memoryview(b).nbytes for b in bufs)
    )
    dl._sock.recv_into = MagicMock(side_effect=recv_side_effect)
    return DataLinkShell(dl)


class TestCliTimeoutHandling:
    """A socket timeout must surface as a clean error message, not an
    unhandled traceback (the CLI's long-standing TODO item)."""

    def test_do_id_reports_error_without_raising(self, capsys):
        shell = make_shell(TimeoutError("timed out"))
        shell.do_id("")  # must not raise
        assert shell.had_error is True
        out = capsys.readouterr().out
        assert "Error" in out

    def test_do_status_reports_error_without_raising(self, capsys):
        shell = make_shell(TimeoutError("timed out"))
        shell.do_status("")  # must not raise
        assert shell.had_error is True
        out = capsys.readouterr().out
        assert "Error" in out


class TestDoStreamRobustness:
    def test_error_reply_reported_without_crashing_repl(self, capsys):
        """do_stream must report a mid-stream ERROR via _fail(), not let it
        propagate out of cmd.Cmd and exit the whole program."""
        shell = make_shell(lambda buf: 0)
        shell.dl._recv_packet = MagicMock(return_value=("ERROR 5 0", b"boom"))
        with patch("select.select", return_value=([shell.dl._sock], [], [])):
            shell.do_stream("")  # must not raise
        assert shell.had_error is True
        assert "boom" in capsys.readouterr().out

    def test_drains_buffered_frames_before_calling_select(self, capsys):
        """A frame already sitting in the receive buffer must be processed
        without waiting on select(), which only reports on-wire data."""
        shell = make_shell(lambda buf: 0)
        shell.dl._recv_end = 10  # pretend a frame is already buffered
        shell.dl._recv_packet = MagicMock(return_value=("ENDSTREAM", None))
        with patch("select.select") as mock_select:
            shell.do_stream("")
        mock_select.assert_not_called()
        assert "Server ended stream." in capsys.readouterr().out


class TestWithReconnect:
    def test_reconnects_on_any_transport_error_not_just_known_messages(self, capsys):
        """Reconnection must be driven by connection state, not by matching
        substrings in the exception message (which is transport-specific and
        easy to change without meaning to break this)."""
        shell = make_shell(lambda buf: 0)
        attempts = {"n": 0}

        def flaky_run():
            attempts["n"] += 1
            if attempts["n"] == 1:
                shell.dl.close()
                raise DataLinkError("send failed: [Errno 32] Broken pipe")

        def fake_ensure_connected():
            if not shell.dl.is_connected:
                shell.dl._sock = MagicMock()
                return True
            return False

        shell._ensure_connected = fake_ensure_connected
        shell._with_reconnect(flaky_run)

        assert attempts["n"] == 2
        assert shell.had_error is False
        assert "Reconnected to" in capsys.readouterr().out
