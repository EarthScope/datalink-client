"""Interactive command-line DataLink client."""

from __future__ import annotations

import sys
from typing import Any

from .client import DataLink
from .protocol import DataLinkError, DataLinkPacket
from .time_utils import ustime_to_timestring


_HELP_TEXT = """\
DataLink interactive client commands:

  ID [name]                  - Send identification (default: auto-generated)
  AUTH USERPASS <user> <pass> - Authenticate with username and password
  AUTH JWT <token>           - Authenticate with a JSON Web Token
  MATCH <pattern>            - Set match expression (e.g. IU_ANMO.*)
  REJECT <pattern>           - Set reject expression
  POSITION SET <pktid> <us>  - Set read position (pktid: int, EARLIEST, LATEST)
  POSITION AFTER <us>        - Set read position after time (epoch microseconds)
  READ <pktid>               - Read a specific packet by ID
  STREAM                     - Start streaming (Ctrl+C to stop)
  INFO <type> [match]        - Request info (STATUS, STREAMS, CONNECTIONS)
  QUIT / EXIT                - Disconnect and exit (or Ctrl+D or Ctrl+C)

  All commands are case-insensitive.
"""


def _print_packet(pkt: DataLinkPacket) -> None:
    print(
        f"  PACKET {pkt.streamid} pktid={pkt.pktid} "
        f"pkttime={ustime_to_timestring(pkt.pkttime)} "
        f"start={ustime_to_timestring(pkt.datastart)} "
        f"end={ustime_to_timestring(pkt.dataend)} "
        f"bytes={len(pkt.data)}"
    )


def _fmt(v: Any) -> str:
    """Format value for display; use '-' for None."""
    if v is None:
        return "-"
    return str(v)


def _print_info_status(info: dict[str, Any]) -> None:
    """Format STATUS info in dalitool-style human-readable output."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"Current time: {now} UTC")
    print(f"Server ID: {_fmt(info.get('ServerID'))} ({_fmt(info.get('Version'))})")
    cap = info.get("Capabilities")
    if cap:
        print(f"Capabilities: {cap}")

    status = info.get("Status") or {}
    if status:
        print()
        ring = status.get("RingSize")
        pkt_size = status.get("PacketSize")
        if ring is not None or pkt_size is not None:
            print(f"Ring size: {_fmt(ring)}, Packet size: {_fmt(pkt_size)}")
        mmap = status.get("MemoryMappedRing")
        vol = status.get("VolatileRing")
        if mmap is not None or vol is not None:
            print(f"Memory-mapped ring: {_fmt(mmap)}, Volatile ring: {_fmt(vol)}")
        max_id = status.get("MaximumPacketID")
        max_pkts = status.get("MaximumPackets")
        if max_id is not None or max_pkts is not None:
            print(f"Max packet ID: {_fmt(max_id)}, Max packets: {_fmt(max_pkts)}")

        print()
        print(
            f" Started: {_fmt(status.get('StartTime'))}, "
            f"{_fmt(status.get('TotalConnections'))} connections, "
            f"{_fmt(status.get('TotalStreams'))} streams"
        )
        print(
            f" Input: {_fmt(status.get('RXPacketRate'))} packets/sec, "
            f"{_fmt(status.get('RXByteRate'))} bytes/sec"
        )
        print(
            f" Output: {_fmt(status.get('TXPacketRate'))} packets/sec, "
            f"{_fmt(status.get('TXByteRate'))} bytes/sec"
        )
        print(
            f" Earliest Packet: {_fmt(status.get('EarliestPacketDataStartTime'))} - "
            f"{_fmt(status.get('EarliestPacketDataEndTime'))} (ID {_fmt(status.get('EarliestPacketID'))})"
        )
        print(
            f" Latest Packet: {_fmt(status.get('LatestPacketDataStartTime'))} - "
            f"{_fmt(status.get('LatestPacketDataEndTime'))} (ID {_fmt(status.get('LatestPacketID'))})"
        )

    threads = info.get("ServerThreads") or {}
    thread_list = threads.get("Thread") or []
    if thread_list:
        print()
        print(" Server threads:")
        for t in thread_list:
            typ = _fmt(t.get("Type"))
            flags = _fmt(t.get("Flags", "")).lstrip()
            print(f"  {typ} [{flags}]")
            if t.get("Port") is not None:
                print(f"   Port: {_fmt(t.get('Port'))}")
        total = threads.get("TotalServerThreads")
        if total is not None:
            print(f" Total server threads: {_fmt(total)}")


def _print_info_streams(info: dict[str, Any]) -> None:
    """Format STREAMS info in dalitool-style table."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"Current time: {now} UTC")
    print(f"Server ID: {_fmt(info.get('ServerID'))} ({_fmt(info.get('Version'))})")

    slist = info.get("StreamList") or {}
    streams = slist.get("Stream") or []
    if not streams:
        print("\nNo streams.")
        total = slist.get("TotalStreams")
        sel = slist.get("SelectedStreams")
        print(f"{_fmt(sel)} of {_fmt(total)} streams")
        return

    print()
    print("Stream ID  Earliest Packet  Latest Packet  Latency")
    print("-" * 20 + "  " + "-" * 20 + "  " + "-" * 20 + "  " + "-" * 10)
    for s in streams:
        name = _fmt(s.get("Name"))
        earliest_start = _fmt(s.get("EarliestPacketDataStartTime"))
        latest_start = _fmt(s.get("LatestPacketDataStartTime"))
        latency = s.get("DataLatency")
        latency_str = f"{latency} seconds" if latency is not None else "-"
        print(f"{name}  {earliest_start}  {latest_start}  {latency_str}")

    total = slist.get("TotalStreams")
    sel = slist.get("SelectedStreams")
    print(f"\n{_fmt(sel)} of {_fmt(total)} streams")


def _print_info_connections(info: dict[str, Any]) -> None:
    """Format CONNECTIONS info in dalitool-style per-connection blocks."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"Current time: {now} UTC")
    print(f"Server ID: {_fmt(info.get('ServerID'))} ({_fmt(info.get('Version'))})")

    status = info.get("Status") or {}
    if status:
        print()
        print(
            f" Started: {_fmt(status.get('StartTime'))}, "
            f"{_fmt(status.get('TotalConnections'))} connections, "
            f"{_fmt(status.get('TotalStreams'))} streams"
        )
        print(
            f" Input: {_fmt(status.get('RXPacketRate'))} packets/sec, "
            f"{_fmt(status.get('RXByteRate'))} bytes/sec"
        )
        print(
            f" Output: {_fmt(status.get('TXPacketRate'))} packets/sec, "
            f"{_fmt(status.get('TXByteRate'))} bytes/sec"
        )

    clist = info.get("ConnectionList") or {}
    connections = clist.get("Connection") or []
    print()
    if not connections:
        print("No connections.")
    else:
        for c in connections:
            host = _fmt(c.get("Host"))
            ip = _fmt(c.get("IP"))
            port = _fmt(c.get("Port"))
            typ = _fmt(c.get("Type"))
            client_id = _fmt(c.get("ClientID"))
            conn_time = _fmt(c.get("ConnectionTime"))
            print(f"{host} [{ip}:{port}]")
            print(f" [{typ}] {client_id} {conn_time}")

            pkt_id = _fmt(c.get("PacketID"))
            pkt_start = _fmt(c.get("PacketDataStartTime"))
            pct_lag = c.get("PercentLag")
            pct_suffix = "%" if pct_lag is not None and pct_lag != "-" else ""
            latency = _fmt(c.get("Latency"))
            print(f" Packet {pkt_id} ({pkt_start}) Lag {_fmt(pct_lag)}{pct_suffix}, {latency} seconds")

            tx_pkts = c.get("TXPacketCount")
            tx_rate = c.get("TXPacketRate")
            tx_bytes = c.get("TXByteCount")
            tx_brate = c.get("TXByteRate")
            if tx_pkts is not None or tx_rate is not None or tx_bytes is not None or tx_brate is not None:
                print(
                    f" TX {_fmt(tx_pkts)} packets {_fmt(tx_rate)} packets/sec "
                    f"{_fmt(tx_bytes)} bytes {_fmt(tx_brate)} bytes/sec"
                )
            rx_pkts = c.get("RXPacketCount")
            rx_rate = c.get("RXPacketRate")
            rx_bytes = c.get("RXByteCount")
            rx_brate = c.get("RXByteRate")
            if rx_pkts is not None or rx_rate is not None or rx_bytes is not None or rx_brate is not None:
                print(
                    f" RX {_fmt(rx_pkts)} packets {_fmt(rx_rate)} packets/sec "
                    f"{_fmt(rx_bytes)} bytes {_fmt(rx_brate)} bytes/sec"
                )
            stream_count = c.get("StreamCount")
            if stream_count is not None:
                print(f" Stream count: {_fmt(stream_count)}")
            match = c.get("Match")
            reject = c.get("Reject")
            if match is not None or reject is not None:
                print(f" Match: {_fmt(match)}")
                print(f" Reject: {_fmt(reject)}")
            print()

    total = clist.get("TotalConnections")
    sel = clist.get("SelectedConnections")
    print(f"{_fmt(sel)} of {_fmt(total)} connections")


def _print_info_dict(info: dict[str, Any], indent: int = 0) -> None:
    """Fallback: pretty-print generic INFO dict (e.g. raw or unknown type)."""
    prefix = "  " * indent
    for key, value in info.items():
        if isinstance(value, dict):
            print(f"{prefix}{key}:")
            _print_info_dict(value, indent + 1)
        elif isinstance(value, list):
            print(f"{prefix}{key}: ({len(value)} entries)")
            for item in value:
                if isinstance(item, dict):
                    _print_info_dict(item, indent + 1)
                    if indent < 2:
                        print()
                else:
                    print(f"{prefix}  {item}")
        elif value is None:
            print(f"{prefix}{key}: -")
        else:
            print(f"{prefix}{key}: {value}")


def _run_stream(dl: DataLink) -> None:
    import select

    dl.stream()
    print("Streaming... press Enter or Ctrl+C to stop.")
    try:
        while True:
            readable, _, _ = select.select([dl._sock, sys.stdin], [], [], 1.0)
            if sys.stdin in readable:
                sys.stdin.readline()
                break
            if dl._sock in readable:
                header, data = dl._recv_packet()
                packet_type = header.split(None, 1)[0] if header else ""
                if packet_type == "PACKET":
                    try:
                        _print_packet(dl._parse_packet(header, data))
                    except DataLinkError:
                        pass
                elif packet_type == "ENDSTREAM":
                    dl._streaming = False
                    print("Server ended stream.")
                    return
                elif packet_type == "ERROR":
                    resp = dl._parse_response(header, data)
                    raise DataLinkError(resp.message or "Stream error", resp.value)
    except KeyboardInterrupt:
        print()
    try:
        dl.endstream()
        print("Returned to query mode.")
    except DataLinkError:
        pass


# Auth credentials for reconnect: None, or ("userpass", user, password), or ("jwt", token)
AuthCredentials = None | tuple[str, str, str] | tuple[str, str]


def _ensure_connected(dl: DataLink, auth: AuthCredentials) -> bool:
    """Reconnect and re-identify (and re-auth if auth given). Returns True if we reconnected."""
    if dl.is_connected:
        return False
    dl.connect()
    dl.identify()
    if auth is not None:
        if auth[0] == "userpass":
            dl.auth_userpass(auth[1], auth[2])
        else:
            dl.auth_jwt(auth[1])
    return True


def _handle_command(dl: DataLink, line: str, auth: AuthCredentials = None) -> bool:
    parts = line.split()
    if not parts:
        return True
    cmd = parts[0].upper()

    if cmd in ("QUIT", "EXIT"):
        return False

    if cmd == "HELP":
        print(_HELP_TEXT)
        return True

    # Commands below need a live connection; reconnect if closed
    try:
        if _ensure_connected(dl, auth):
            tls_label = " (TLS)" if dl._tls else ""
            print(f"Reconnected to {dl._host}:{dl._port}{tls_label}")
    except DataLinkError as e:
        print(f"Error: {e}")
        return True

    # Run command with one retry on connection closed (so user doesn't have to re-enter)
    for attempt in range(2):
        try:
            return _run_command(dl, cmd, parts)
        except DataLinkError as e:
            msg = str(e)
            if attempt == 0 and ("Connection closed" in msg or "Not connected" in msg):
                try:
                    if _ensure_connected(dl, auth):
                        tls_label = " (TLS)" if dl._tls else ""
                        print(f"Reconnected to {dl._host}:{dl._port}{tls_label}")
                        continue  # retry command
                except DataLinkError:
                    pass
            print(f"Error: {e}")
            return True

    return True


def _run_command(dl: DataLink, cmd: str, parts: list[str]) -> bool:
    """Execute a single command. Raises DataLinkError on connection errors."""
    if cmd == "ID":
        name = parts[1] if len(parts) > 1 else None
        server_id = dl.identify(name)
        print(f"Server: {server_id}")
        if dl.server_capabilities:
            print(f"Capabilities: {dl.server_capabilities}")
        return True

    if cmd == "AUTH":
        if len(parts) < 2:
            print("Usage: AUTH USERPASS <user> <pass>  or  AUTH JWT <token>")
            return True
        subcmd = parts[1].upper()
        if subcmd == "USERPASS":
            if len(parts) < 4:
                print("Usage: AUTH USERPASS <username> <password>")
                return True
            resp = dl.auth_userpass(parts[2], parts[3])
            print(
                f"OK: authenticated as {parts[2]}" if resp else f"ERROR: {resp.message}"
            )
        elif subcmd == "JWT":
            if len(parts) < 3:
                print("Usage: AUTH JWT <token>")
                return True
            resp = dl.auth_jwt(parts[2])
            print("OK: authenticated with JWT" if resp else f"ERROR: {resp.message}")
        else:
            print("Usage: AUTH USERPASS <user> <pass>  or  AUTH JWT <token>")
        return True

    if cmd == "MATCH":
        if len(parts) < 2:
            print("Usage: MATCH <pattern>")
            return True
        resp = dl.match(parts[1])
        print(f"OK: {resp.value} streams matched" if resp else f"ERROR: {resp.message}")
        return True

    if cmd == "REJECT":
        if len(parts) < 2:
            print("Usage: REJECT <pattern>")
            return True
        resp = dl.reject(parts[1])
        print(
            f"OK: {resp.value} streams rejected" if resp else f"ERROR: {resp.message}"
        )
        return True

    if cmd == "POSITION":
        if len(parts) < 3:
            print(
                "Usage: POSITION SET <pktid> <uspkttime>  or  POSITION AFTER <ustime>"
            )
            return True
        subcmd = parts[1].upper()
        if subcmd == "SET" and len(parts) >= 4:
            pktid: str | int = parts[2]
            if pktid not in ("EARLIEST", "LATEST"):
                try:
                    pktid = int(pktid)
                except ValueError:
                    print(f"Invalid pktid: {parts[2]}")
                    return True
            try:
                uspkttime = int(parts[3])
            except ValueError:
                print(f"Invalid uspkttime: {parts[3]}")
                return True
            resp = dl.position_set(pktid, uspkttime)
            print(f"OK: position set to pktid={resp.value}")
        elif subcmd == "AFTER":
            try:
                ustime = int(parts[2])
            except ValueError:
                print(f"Invalid ustime: {parts[2]}")
                return True
            resp = dl.position_after(ustime)
            print(f"OK: position set to pktid={resp.value}")
        else:
            print(
                "Usage: POSITION SET <pktid> <uspkttime>  or  POSITION AFTER <ustime>"
            )
        return True

    if cmd == "READ":
        if len(parts) < 2:
            print("Usage: READ <pktid>")
            return True
        try:
            pkt_id = int(parts[1])
        except ValueError:
            print(f"Error: invalid pktid {parts[1]}")
            return True
        pkt = dl.read(pkt_id)
        _print_packet(pkt)
        return True

    if cmd == "STREAM":
        _run_stream(dl)
        return True

    if cmd == "INFO":
        if len(parts) < 2:
            print("Usage: INFO <STATUS|STREAMS|CONNECTIONS> [match]")
            return True
        info_type = parts[1].upper()
        match_expr = " ".join(parts[2:]).strip() or None if len(parts) > 2 else None
        if info_type == "STATUS":
            _print_info_status(dl.info_status(match=match_expr))
        elif info_type == "STREAMS":
            _print_info_streams(dl.info_streams(match=match_expr))
        elif info_type == "CONNECTIONS":
            _print_info_connections(dl.info_connections(match=match_expr))
        else:
            xml = dl.info(info_type, match_expr)
            print(xml)
        return True

    print(f"Unknown command: {cmd}  (type HELP for usage)")
    return True


def main() -> int:
    """Interactive DataLink client entry point."""
    import argparse
    import readline  # noqa: F401 — enables arrow keys and history

    parser = argparse.ArgumentParser(
        description="Interactive DataLink protocol client.",
    )
    parser.add_argument(
        "server",
        nargs="?",
        default="",
        help="Server address as host:port, host@port, or host (default: localhost:16000)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Socket timeout in seconds (default: none)",
    )
    parser.add_argument(
        "--tls",
        action="store_true",
        default=False,
        help="Force TLS encryption (auto-enabled for port 16500)",
    )
    parser.add_argument(
        "--tls-noverify",
        action="store_true",
        default=False,
        help="Disable TLS certificate verification (insecure)",
    )
    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument(
        "--auth",
        metavar="USER:PASS",
        default=None,
        help="Authenticate with username:password",
    )
    auth_group.add_argument(
        "--jwt",
        metavar="TOKEN",
        default=None,
        help="Authenticate with a JWT",
    )
    args = parser.parse_args()

    # Build auth credentials for reconnect-after-close
    auth: AuthCredentials = None
    if args.auth:
        auth_parts = args.auth.split(":", 1)
        if len(auth_parts) != 2:
            print("Error: --auth requires USER:PASS format", file=sys.stderr)
            return 1
        auth = ("userpass", auth_parts[0], auth_parts[1])
    elif args.jwt:
        auth = ("jwt", args.jwt)

    tls = True if args.tls else None
    try:
        dl = DataLink.from_server_string(
            args.server,
            timeout=args.timeout,
            tls=tls,
            tls_noverify=args.tls_noverify,
        )
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    try:
        dl.connect()
        tls_label = " (TLS)" if dl._tls else ""
        print(f"Connected to {dl._host}:{dl._port}{tls_label}")
        dl.identify()
        print(f"Server: {dl.server_id}")

        if auth is not None:
            if auth[0] == "userpass":
                resp = dl.auth_userpass(auth[1], auth[2])
                print(
                    f"Authenticated as {auth[1]}"
                    if resp
                    else f"Auth failed: {resp.message}"
                )
            else:
                resp = dl.auth_jwt(auth[1])
                print("Authenticated with JWT" if resp else f"Auth failed: {resp.message}")
        print("Type HELP for commands, QUIT to exit.\n")

        while True:
            try:
                line = input("DL> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not _handle_command(dl, line, auth):
                break
    except DataLinkError as e:
        msg = str(e)
        if "tls_noverify=True" in msg:
            msg = msg.replace(
                "Use tls_noverify=True to skip verification "
                "(insecure, e.g. for self-signed certificates)",
                "Use --tls-noverify to skip verification "
                "(insecure, e.g. for self-signed certificates)",
            )
        print(f"Error: {msg}", file=sys.stderr)
        return 1
    except ConnectionRefusedError:
        print(f"Connection refused: {dl._host}:{dl._port}", file=sys.stderr)
        return 1
    finally:
        dl.close()
        print("Disconnected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
