"""Interactive command-line DataLink client using cmd.Cmd."""

from __future__ import annotations

import cmd
import sys
from typing import Any

from .client import DataLink
from .protocol import DataLinkError, DataLinkPacket
from .time_utils import ustime_to_timestring


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

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
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"Current time: {now} UTC")
    print(f"Server ID: {_fmt(info.get('ServerID'))} ({_fmt(info.get('Version'))})")

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

    col1_h, col2_h, col3_h, col4_h = "Stream ID", "Earliest Packet", "Latest Packet", "Latency"
    sep = "  "
    w1 = max(len(col1_h), max(len(_fmt(s.get("Name"))) for s in streams)) + 2
    w2 = max(len(col2_h), max(len(_fmt(s.get("EarliestPacketDataStartTime"))) for s in streams))
    w3 = max(len(col3_h), max(len(_fmt(s.get("LatestPacketDataStartTime"))) for s in streams))
    latency_lengths = [len(f"{s.get('DataLatency')} seconds") if s.get("DataLatency") is not None else 1 for s in streams]
    w4 = max(len(col4_h), max(latency_lengths))
    print()
    print(f"{col1_h:<{w1}}{sep}{col2_h:<{w2}}{sep}{col3_h:<{w3}}{sep}{col4_h:<{w4}}")
    print("-" * w1 + sep + "-" * w2 + sep + "-" * w3 + sep + "-" * w4)
    for s in streams:
        name = _fmt(s.get("Name"))
        earliest_start = _fmt(s.get("EarliestPacketDataStartTime"))
        latest_start = _fmt(s.get("LatestPacketDataStartTime"))
        latency = s.get("DataLatency")
        latency_str = f"{latency} seconds" if latency is not None else "-"
        print(f"{name:<{w1}}{sep}{earliest_start:<{w2}}{sep}{latest_start:<{w3}}{sep}{latency_str:<{w4}}")

    total = slist.get("TotalStreams")
    sel = slist.get("SelectedStreams")
    print(f"\n{_fmt(sel)} of {_fmt(total)} streams")


def _print_info_connections(info: dict[str, Any]) -> None:
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


# ---------------------------------------------------------------------------
# Auth credentials for reconnect
# ---------------------------------------------------------------------------

# None, or ("userpass", user, password), or ("jwt", token)
AuthCredentials = None | tuple[str, str, str] | tuple[str, str]


# ---------------------------------------------------------------------------
# cmd.Cmd-based interactive client
# ---------------------------------------------------------------------------

class DataLinkShell(cmd.Cmd):
    """Interactive DataLink command shell."""

    prompt = "DL> "
    intro = ""

    def __init__(self, dl: DataLink, auth: AuthCredentials = None) -> None:
        super().__init__()
        self.dl = dl
        self.auth = auth

    # -- Connection management ---------------------------------------------

    def _ensure_connected(self) -> bool:
        """Reconnect if needed. Returns True if reconnected."""
        if self.dl.is_connected:
            return False
        self.dl.connect()
        self.dl.identify()
        if self.auth is not None:
            if self.auth[0] == "userpass":
                self.dl.auth_userpass(self.auth[1], self.auth[2])
            else:
                self.dl.auth_jwt(self.auth[1])
        return True

    def _with_reconnect(self, func: Any) -> None:
        """Run func(); on connection error, reconnect once and retry."""
        for attempt in range(2):
            try:
                if self._ensure_connected():
                    tls_label = " (TLS)" if self.dl._tls else ""
                    print(f"Reconnected to {self.dl._host}:{self.dl._port}{tls_label}")
                func()
                return
            except ValueError as e:
                print(f"Error: {e}")
                return
            except DataLinkError as e:
                msg = str(e)
                if attempt == 0 and ("Connection closed" in msg or "Not connected" in msg):
                    try:
                        if self._ensure_connected():
                            tls_label = " (TLS)" if self.dl._tls else ""
                            print(f"Reconnected to {self.dl._host}:{self.dl._port}{tls_label}")
                            continue
                    except DataLinkError:
                        pass
                print(f"Error: {e}")
                return

    # -- Case-insensitive command dispatch ---------------------------------

    def parseline(self, line: str) -> tuple[str | None, str | None, str]:
        """Override to make commands case-insensitive (preserving 'EOF' for Ctrl+D)."""
        cmd_name, arg, line = super().parseline(line)
        if cmd_name is not None and cmd_name != "EOF":
            cmd_name = cmd_name.lower()
        return cmd_name, arg, line

    def emptyline(self) -> bool:
        """Don't repeat last command on empty line."""
        return False

    def default(self, line: str) -> None:
        print(f"Unknown command: {line.split()[0]}  (type HELP for commands)")

    # -- Commands ----------------------------------------------------------

    def do_id(self, arg: str) -> None:
        """ID [name] - Send identification"""
        def run() -> None:
            name = arg.strip() or None
            self.dl.identify(name)
            print(f"Server: {self.dl.server_id}")
            if self.dl.server_capabilities:
                print(f"Capabilities: {self.dl.server_capabilities}")
        self._with_reconnect(run)

    def do_auth(self, arg: str) -> None:
        """AUTH USERPASS <user> <pass> | AUTH JWT <token> - Authenticate"""
        parts = arg.split()
        if len(parts) < 1:
            print("Usage: AUTH USERPASS <user> <pass>  or  AUTH JWT <token>")
            return
        subcmd = parts[0].upper()
        def run() -> None:
            if subcmd == "USERPASS":
                if len(parts) < 3:
                    print("Usage: AUTH USERPASS <username> <password>")
                    return
                resp = self.dl.auth_userpass(parts[1], parts[2])
                print(f"OK: authenticated as {parts[1]}" if resp else f"ERROR: {resp.message}")
            elif subcmd == "JWT":
                if len(parts) < 2:
                    print("Usage: AUTH JWT <token>")
                    return
                resp = self.dl.auth_jwt(parts[1])
                print("OK: authenticated with JWT" if resp else f"ERROR: {resp.message}")
            else:
                print("Usage: AUTH USERPASS <user> <pass>  or  AUTH JWT <token>")
        self._with_reconnect(run)

    def complete_auth(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        subs = ["USERPASS", "JWT"]
        return [s for s in subs if s.lower().startswith(text.lower())]

    def do_match(self, arg: str) -> None:
        """MATCH <pattern> - Set match expression"""
        if not arg.strip():
            print("Usage: MATCH <pattern>")
            return
        def run() -> None:
            resp = self.dl.match(arg.strip())
            print(f"OK: {resp.value} streams matched" if resp else f"ERROR: {resp.message}")
        self._with_reconnect(run)

    def do_reject(self, arg: str) -> None:
        """REJECT <pattern> - Set reject expression"""
        if not arg.strip():
            print("Usage: REJECT <pattern>")
            return
        def run() -> None:
            resp = self.dl.reject(arg.strip())
            print(f"OK: {resp.value} streams rejected" if resp else f"ERROR: {resp.message}")
        self._with_reconnect(run)

    def do_position(self, arg: str) -> None:
        """POSITION SET <pktid|EARLIEST|LATEST> [time] | POSITION AFTER <time>

        <time> can be epoch microseconds (int) or an ISO 8601 datetime string.
        EARLIEST and LATEST do not require a time argument.
        """
        parts = arg.split()
        if len(parts) < 2:
            print("Usage: POSITION SET <pktid|EARLIEST|LATEST> [time]")
            print("       POSITION AFTER <time>")
            print("  <time> is epoch microseconds or an ISO 8601 datetime string")
            return
        subcmd = parts[0].upper()
        def _parse_time(value: str) -> int | str:
            try:
                return int(value)
            except ValueError:
                return value  # pass as string; client will convert
        def run() -> None:
            if subcmd == "SET":
                pktid: str | int = parts[1].upper()
                if pktid in ("EARLIEST", "LATEST"):
                    uspkttime: int | str = _parse_time(parts[2]) if len(parts) >= 3 else 0
                elif len(parts) >= 3:
                    try:
                        pktid = int(parts[1])
                    except ValueError:
                        print(f"Invalid pktid: {parts[1]}")
                        return
                    uspkttime = _parse_time(parts[2])
                else:
                    print("Usage: POSITION SET <pktid|EARLIEST|LATEST> [time]")
                    return
                resp = self.dl.position_set(pktid, uspkttime)
                print(f"OK: position set to pktid={resp.value}")
            elif subcmd == "AFTER":
                ustime = _parse_time(parts[1])
                resp = self.dl.position_after(ustime)
                print(f"OK: position set to pktid={resp.value}")
            else:
                print("Usage: POSITION SET <pktid|EARLIEST|LATEST> [time]")
                print("       POSITION AFTER <time>")
        self._with_reconnect(run)

    def complete_position(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        parts = line.split()
        if len(parts) == 2 or (len(parts) == 1 and line.endswith(" ")):
            subs = ["SET", "AFTER"]
            return [s for s in subs if s.lower().startswith(text.lower())]
        upper = line.upper()
        if "POSITION SET" in upper:
            words_after_set = upper.split("SET", 1)[1].split()
            if len(words_after_set) == 0 or (len(words_after_set) == 1 and not line.endswith(" ")):
                subs = ["EARLIEST", "LATEST"]
                return [s for s in subs if s.lower().startswith(text.lower())]
        return []

    def do_read(self, arg: str) -> None:
        """READ <pktid> - Read a specific packet by ID"""
        if not arg.strip():
            print("Usage: READ <pktid>")
            return
        try:
            pkt_id = int(arg.strip())
        except ValueError:
            print(f"Error: invalid pktid {arg.strip()}")
            return
        def run() -> None:
            pkt = self.dl.read(pkt_id)
            _print_packet(pkt)
        self._with_reconnect(run)

    def do_stream(self, arg: str) -> None:
        """STREAM - Start streaming (Ctrl+C to stop)"""
        import select

        try:
            self._ensure_connected()
        except DataLinkError as e:
            print(f"Error: {e}")
            return

        self.dl.stream()
        print("Streaming... press Enter or Ctrl+C to stop.")
        try:
            while True:
                readable, _, _ = select.select([self.dl._sock, sys.stdin], [], [], 1.0)
                if sys.stdin in readable:
                    sys.stdin.readline()
                    break
                if self.dl._sock in readable:
                    header, data = self.dl._recv_packet()
                    packet_type = header.split(None, 1)[0] if header else ""
                    if packet_type == "PACKET":
                        try:
                            _print_packet(self.dl._parse_packet(header, data))
                        except DataLinkError:
                            pass
                    elif packet_type == "ENDSTREAM":
                        self.dl._streaming = False
                        print("Server ended stream.")
                        return
                    elif packet_type == "ERROR":
                        resp = self.dl._parse_response(header, data)
                        raise DataLinkError(resp.message or "Stream error", resp.value)
        except KeyboardInterrupt:
            print()
        try:
            self.dl.endstream()
            print("Returned to query mode.")
        except DataLinkError:
            pass

    def do_status(self, arg: str) -> None:
        """STATUS [match] - Print formatted server status"""
        match_expr = arg.strip() or None
        def run() -> None:
            _print_info_status(self.dl.info_status(match=match_expr))
        self._with_reconnect(run)

    def do_streams(self, arg: str) -> None:
        """STREAMS [match] - Print formatted stream list"""
        match_expr = arg.strip() or None
        def run() -> None:
            _print_info_streams(self.dl.info_streams(match=match_expr))
        self._with_reconnect(run)

    def do_connections(self, arg: str) -> None:
        """CONNECTIONS [match] - Print formatted connection list"""
        match_expr = arg.strip() or None
        def run() -> None:
            _print_info_connections(self.dl.info_connections(match=match_expr))
        self._with_reconnect(run)

    def do_info(self, arg: str) -> None:
        """INFO <type> [match] - Request info and print raw XML"""
        parts = arg.split(None, 1)
        if not parts:
            print("Usage: INFO <type> [match]")
            return
        info_type = parts[0].upper()
        match_expr = parts[1].strip() if len(parts) > 1 else None
        def run() -> None:
            xml = self.dl.info(info_type, match_expr)
            print(xml)
        self._with_reconnect(run)

    def complete_info(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        subs = ["STATUS", "STREAMS", "CONNECTIONS"]
        return [s for s in subs if s.lower().startswith(text.lower())]

    def do_quit(self, arg: str) -> bool:
        """QUIT - Disconnect and exit"""
        return True

    def do_exit(self, arg: str) -> bool:
        """EXIT - Disconnect and exit"""
        return True

    def do_EOF(self, arg: str) -> bool:
        """Handle Ctrl+D."""
        print()
        return True

    # -- Help override for clean formatting --------------------------------

    def do_help(self, arg: str) -> None:
        """HELP - Show available commands"""
        print(
            "DataLink interactive client commands:\n"
            "\n"
            "  ID [name]                  - Send identification (default: auto-generated)\n"
            "  AUTH USERPASS <user> <pass> - Authenticate with username and password\n"
            "  AUTH JWT <token>           - Authenticate with a JSON Web Token\n"
            "  MATCH <pattern>            - Set match expression (e.g. IU_ANMO.*)\n"
            "  REJECT <pattern>           - Set reject expression\n"
            "  POSITION SET <pktid> <time> - Set read position (pktid: int or EARLIEST/LATEST)\n"
            "  POSITION AFTER <time>      - Set read position after time\n"
            "  POSITION SET EARLIEST      - Set read position to earliest packet\n"
            "  POSITION SET LATEST        - Set read position to latest packet\n"
            "  READ <pktid>               - Read a specific packet by ID\n"
            "  STREAM                     - Start streaming (Ctrl+C or Enter to stop)\n"
            "  STATUS [match]             - Print formatted server status\n"
            "  STREAMS [match]            - Print formatted stream list\n"
            "  CONNECTIONS [match]        - Print formatted connection list\n"
            "  INFO <type> [match]        - Request info and print raw XML\n"
            "  QUIT / EXIT                - Disconnect and exit (or Ctrl+D or Ctrl+C)\n"
            "\n"
            "  <time> is epoch microseconds or an ISO 8601 datetime string.\n"
            "  All commands are case-insensitive. Tab completion is supported.\n"
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    """Interactive DataLink client entry point."""
    import argparse

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

    # Build auth credentials for reconnect
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

        shell = DataLinkShell(dl, auth)
        print("Type HELP for commands, QUIT to exit.\n")
        try:
            shell.cmdloop()
        except KeyboardInterrupt:
            print()
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
