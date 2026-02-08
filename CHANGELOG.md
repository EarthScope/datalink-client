# Changelog

## 1.0.0

- Initial release.
- DataLink protocol 1.1 client with support for ID, AUTH (USERPASS/JWT), POSITION SET/AFTER, MATCH, REJECT, WRITE, READ, STREAM, ENDSTREAM, and INFO commands.
- Interactive command-line client (`datalink-client`) with formatted STATUS, STREAMS, and CONNECTIONS output.
- Auto-reconnect on connection close during interactive sessions.
- TLS support with auto-detection on port 16500.
- Epoch microsecond time conversion utilities (`ustime_to_timestring`, `timestring_to_ustime`).
