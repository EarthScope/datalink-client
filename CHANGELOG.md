# Changelog

## 1.5.0

- Add `AsyncDataLink`, an asyncio-based client offering the same commands as `DataLink`
  as coroutines (ID, AUTH, POSITION SET/AFTER, MATCH, REJECT, WRITE, READ, STREAM,
  ENDSTREAM, INFO, `collect()` as an async generator, `batch()` as an async context
  manager). Import it directly (`from datalink_client import AsyncDataLink`); it is
  lazily imported so plain `DataLink` usage does not pull in `asyncio`.
- **Breaking:** raised the Python floor to `>=3.11`, to use `asyncio.timeout()` and the
  3.11 alignment of `asyncio.TimeoutError` with the builtin `TimeoutError` -- both
  load-bearing for `AsyncDataLink`'s timeout handling.
- `write()`'s declared payload size now uses the buffer's actual byte length
  (`memoryview(...).nbytes`) rather than `len()`, fixing an under-declared size (and a
  resulting desync) when writing a `memoryview` over a non-byte-sized array.
- Added a sanity cap on declared reply/packet payload sizes so a corrupt or malicious
  header cannot force an unbounded buffer wait or allocation.
- Avoid truncation of payload on CLI `WRITE`/`WRITEMSEED2`/`WRITEMSEED3` commands.
- Fixed `connect()` raising `UnboundLocalError` (instead of failing over to the next resolved
  address) when socket creation itself failed for a given address family.
- Added `DataLinkTimeout` (subclasses both `DataLinkError` and `TimeoutError`) and raised it
  consistently on socket read timeouts, instead of letting a bare `socket.timeout` escape past
  the client and CLI into an unhandled traceback.
- Fixed `_send_packet()`'s `sendmsg` fast path silently accepting a short send (a single
  syscall with no retry, unlike `sendall`) and desynchronizing the connection; it now loops
  until every buffer is fully sent. Also stopped assuming `sendmsg` exists on the socket
  (it doesn't on Windows), falling back to `sendall` there instead of raising `AttributeError`.
- The client now closes the connection when the protocol stream is detected as
  desynchronized (bad preheader magic or an unrecognized packet type), instead of leaving a
  corrupt connection open that the CLI would otherwise treat as still usable.
- Fixed a batched write deadlocking any subsequent command that expects a reply, by flushing
  pending batched writes before sending it.
- Fixed `flush()` silently discarding buffered writes when disconnected; it now raises
  `DataLinkError` instead of losing data quietly.
- Fixed a non-numeric or negative declared payload size desyncing the stream instead of
  raising; also wrapped non-ASCII header encode/decode errors in `DataLinkError` (closing the
  connection on the decode side) instead of letting a bare `UnicodeError` escape.
- `collect()` now closes the connection and raises on an invalid `PACKET` header instead of
  logging a warning and continuing to read an already-desynchronized stream.
- Fixed `from_server_string()` mishandling a bare (unbracketed) IPv6 host, a `host@port` value
  containing an extra `@`, and an out-of-range port, instead of silently producing a wrong host
  or port.
- Fixed the CLI's `STREAM` command lagging behind incoming packets, since `select()` doesn't
  see frames already pulled into the client's internal receive buffer; added
  `DataLink.has_buffered_data` and drain it before waiting on `select()`.
- Fixed a mid-stream `ERROR` reply (or other failure) in the CLI's `STREAM` command exiting the
  whole program instead of reporting the error and returning to the prompt.
- Fixed CLI auto-reconnect only triggering on specific error-message text, missing transport
  errors like a reset connection; it now reconnects based on connection state instead.
- Fixed `DataLink`'s persistent receive buffer never shrinking back down after growing to fit
  an oversized payload, permanently pinning that memory for the life of the connection; it now
  releases back to its default 64 KiB once drained, and on `close()`.
- Fixed `connect()` leaking the socket if anything other than `SSLCertVerificationError` or
  `OSError` was raised while establishing a connection.
- Fixed `begin_batch()` silently discarding an in-progress batch and its queued packets when
  called a second time; added an optional `max_bytes` to `begin_batch()`/`batch()` to bound a
  long batch's memory instead of growing it unboundedly until an explicit `flush()`.

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
