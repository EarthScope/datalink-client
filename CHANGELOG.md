# Changelog

## 1.4.0

- Add `DataLink.bye()` to send the BYE command; CLI `BYE` command sends it and exits.
- Faster CLI streaming: a persistent 64 KiB recv buffer coalesces the per-packet 3-syscall read path into fewer, larger reads and eliminates per-call `bytearray` allocations.
- Faster `ustime_to_timestring` via `time.gmtime` + direct f-string, eliminating `datetime`/`timedelta` object creation and `strftime` overhead.
- `position_set()` `uspkttime` is now optional; when omitted the time field is not sent on the wire.
- CLI `POSITION SET <pktid> [time]`: time argument is now optional for numeric packet IDs.
- CLI: `-c "<command>"` (repeatable) runs one-shot commands without entering the REPL.
- CLI: `-f <file>` reads commands from a script file (`#` comments and blank lines ignored).
- CLI: when no `-c`/`-f` flags are given and stdin is not a TTY, piped stdin is treated as a script.
- CLI: `-i`/`--interactive` drops into the REPL after non-interactive commands complete successfully.
- CLI: non-interactive mode is fail-fast — the first failing command stops execution and produces a non-zero exit code; interactive mode is unchanged (errors print but do not exit).

## 1.3.1

- Wrap socket-level `OSError` in `_send_packet`, `flush`, and `_recv_all` and re-raise as `DataLinkError` so callers can handle all transport failures with a single exception type.
- Wrap other exceptions so callers only need to handle a single exception type for API-level failures.
- Switched to recv_into with a pre-allocated bytearray(n).
- Rename `DataLink.last_pktid()` to `set_position_latest()` for clarity.
- Add a test suite.

## 1.3.0

- Add a `batch()` context manager for coalescing many no-ack writes into a single send.
- Sending uses scatter-gather on plain (non-TLS) sockets, eliminating the payload copy per write.

## 1.2.0

- `write()` `data` parameter now accepts `bytes`, `bytearray`, or `memoryview`, avoiding a buffer copy for zero-copy writes.
- CLI `WRITE <streamID> <text> [pktID]` command to write a plain text packet.
- CLI `WRITEMSEED2 <sourceID> <text> [pktID]` and `WRITEMSEED3 <sourceID> <text> [pktID]` commands to write text wrapped in a miniSEED v2 or v3 record (requires pymseed).

## 1.1.1

- Update license to Apache 2.

## 1.1.0

- For `position_set()` and `position_after()` accept date-time strings and convert as needed.
- CLI "POSITION SET" to accept "EARLIEST" and "LATEST" special values.
- CLI "STREAM" accepts an optional -p to parse /MSEED and /MSEED3 packets if pymseed is available.
- Add CLI command completion with tab.

## 1.0.0

- Initial release.
- DataLink protocol 1.1 client with support for ID, AUTH (USERPASS/JWT), POSITION SET/AFTER, MATCH, REJECT, WRITE, READ, STREAM, ENDSTREAM, and INFO commands.
- Interactive command-line client (`datalink-client`) with formatted STATUS, STREAMS, and CONNECTIONS output.
- Auto-reconnect on connection close during interactive sessions.
- TLS support with auto-detection on port 16500.
- Epoch microsecond time conversion utilities (`ustime_to_timestring`, `timestring_to_ustime`).
