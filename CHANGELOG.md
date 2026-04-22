# Changelog

## unreleased

- Wrap socket-level `OSError` in `_send_packet`, `flush`, and `_recv_all` and re-raise as `DataLinkError` so callers can handle all transport failures with a single exception type.
- Wrap remaining exceptions so callers only need to handle a single exception type for API-level failures.
- Rename `DataLink.last_pktid()` to `set_position_latest()` for clarity.

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
