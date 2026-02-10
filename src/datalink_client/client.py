"""DataLink protocol 1.1 client (query and streaming modes)."""

from __future__ import annotations

import logging
import os
import platform
import socket
import ssl
import sys
import time
import xml.etree.ElementTree as ET
from collections.abc import Generator
from typing import Any, Literal, overload

from .protocol import (
    DL_MAGIC,
    MAX_HEADER_LEN,
    PREHEADER_LEN,
    DataLinkError,
    DataLinkPacket,
    DataLinkResponse,
    typed_attrs,
)
from .time_utils import timestring_to_ustime

logger = logging.getLogger(__name__)


class DataLink:
    """DataLink protocol 1.1 client for query and streaming modes.

    Supports all DataLink 1.1 client commands: ID, AUTH (USERPASS/JWT),
    POSITION SET/AFTER, MATCH, REJECT, WRITE, READ, STREAM, ENDSTREAM, and INFO.

    The connection starts in query mode. Call :meth:`stream` to enter streaming
    mode, and :meth:`endstream` to return to query mode.

    Args:
        host:       Server hostname or IP address.
        port:       Server TCP port (typically 16000, or 16500 for TLS).
        timeout:    Optional socket timeout in seconds. None means block indefinitely.
        tls:        Enable TLS encryption. If None (default), TLS is auto-enabled
                    when port is 16500.
        tls_noverify: If True, disable TLS certificate verification (insecure;
                      useful for self-signed certificates or testing).

    Attributes:
        server_id:           Raw server ID string after calling :meth:`identify`, or None.
        server_capabilities: Dict of server capabilities parsed from the ID reply.
                             Keys with values are stored as strings (e.g. ``{'DLPROTO': '1.0'}``).
                             Keys without values are stored as ``True`` (e.g. ``{'WRITE': True}``).
    """

    TLS_PORT = 16500

    def __init__(
        self,
        host: str = "localhost",
        port: int = 16000,
        timeout: float | None = None,
        tls: bool | None = None,
        tls_noverify: bool = False,
    ):
        self._host = host
        self._port = port
        self._timeout = timeout
        self._tls = tls if tls is not None else (port == self.TLS_PORT)
        self._tls_noverify = tls_noverify
        self._sock: socket.socket | None = None
        self._streaming = False
        self.server_id: str | None = None
        self.server_capabilities: dict[str, str | bool] = {}

    @classmethod
    def from_server_string(
        cls,
        server: str,
        timeout: float | None = None,
        tls: bool | None = None,
        tls_noverify: bool = False,
    ) -> DataLink:
        """Create a DataLink from a server string (host:port, host@port, host, or '')."""
        host = "localhost"
        port = 16000
        server = server.strip()
        if server:
            normalized = server.replace("@", ":")
            if normalized.startswith("["):
                bracket_end = normalized.find("]")
                if bracket_end < 0:
                    raise ValueError(
                        f"Missing closing bracket in server string: {server!r}"
                    )
                host = normalized[1:bracket_end] or "localhost"
                remainder = normalized[bracket_end + 1 :]
                if remainder.startswith(":") and remainder[1:]:
                    try:
                        port = int(remainder[1:])
                    except ValueError:
                        raise ValueError(
                            f"Invalid port in server string: {server!r}"
                        ) from None
            else:
                parts = normalized.rsplit(":", 1)
                host = parts[0] or "localhost"
                if len(parts) == 2 and parts[1]:
                    try:
                        port = int(parts[1])
                    except ValueError:
                        raise ValueError(
                            f"Invalid port in server string: {server!r}"
                        ) from None
        return cls(host, port, timeout=timeout, tls=tls, tls_noverify=tls_noverify)

    @property
    def is_connected(self) -> bool:
        return self._sock is not None

    @property
    def is_streaming(self) -> bool:
        return self._streaming

    def __repr__(self) -> str:
        state = "connected" if self._sock is not None else "disconnected"
        tls = ", tls" if self._tls else ""
        return f"DataLink({self._host!r}, {self._port}, {state}{tls})"

    def connect(self) -> None:
        """Open TCP connection to the DataLink server, optionally with TLS."""
        if self._sock is not None:
            raise DataLinkError("Already connected")
        infos = socket.getaddrinfo(
            self._host, self._port, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        if not infos:
            raise DataLinkError(f"Could not resolve address: {self._host}:{self._port}")
        last_err: OSError | None = None
        for af, socktype, proto, _canonname, sockaddr in infos:
            try:
                sock = socket.socket(af, socktype, proto)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                if self._timeout is not None:
                    sock.settimeout(self._timeout)
                sock.connect(sockaddr)
                if self._tls:
                    context = ssl.create_default_context()
                    if self._tls_noverify:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=self._host)
                self._sock = sock
                break
            except ssl.SSLCertVerificationError as e:
                sock.close()
                raise DataLinkError(
                    f"TLS certificate verification failed for "
                    f"{self._host}:{self._port}: {e.verify_message}. "
                    f"Use tls_noverify=True to skip verification "
                    f"(insecure, e.g. for self-signed certificates)"
                ) from e
            except OSError as e:
                last_err = e
                sock.close()
        else:
            raise DataLinkError(
                f"Could not connect to {self._host}:{self._port}"
            ) from last_err
        logger.debug("Connected to %s:%d%s", self._host, self._port, " (TLS)" if self._tls else "")

    def close(self) -> None:
        """Gracefully close the connection."""
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                try:
                    self._sock.close()
                finally:
                    self._sock = None
        self._streaming = False

    def reconnect(self) -> None:
        """Close the current connection (if any) and open a fresh one."""
        self.close()
        self.connect()

    def __enter__(self) -> DataLink:
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def _recv_all(self, n: int) -> bytes:
        if self._sock is None:
            raise DataLinkError("Not connected")
        buf = []
        received = 0
        while received < n:
            try:
                chunk = self._sock.recv(n - received)
            except socket.timeout:
                if received > 0:
                    self.close()
                    raise DataLinkError(
                        f"Timeout after partial read ({received}/{n} bytes); "
                        "connection closed"
                    )
                raise
            except OSError:
                self.close()
                raise
            if not chunk:
                self.close()
                raise DataLinkError("Connection closed")
            buf.append(chunk)
            received += len(chunk)
        return b"".join(buf)

    def _send_packet(self, header: str, data: bytes | None = None) -> None:
        if self._sock is None:
            raise DataLinkError("Not connected")
        header_bytes = header.encode("ascii")
        if len(header_bytes) > MAX_HEADER_LEN:
            raise DataLinkError(
                f"Header length {len(header_bytes)} exceeds {MAX_HEADER_LEN}"
            )
        preheader = DL_MAGIC + bytes([len(header_bytes)])
        try:
            if data is not None:
                self._sock.sendall(preheader + header_bytes + data)
            else:
                self._sock.sendall(preheader + header_bytes)
        except OSError:
            self.close()
            raise

    def _recv_packet(self) -> tuple[str, bytes | None]:
        if self._sock is None:
            raise DataLinkError("Not connected")
        pre = self._recv_all(PREHEADER_LEN)
        if pre[:2] != DL_MAGIC:
            raise DataLinkError(f"Invalid preheader magic: {pre[:2]!r}")
        header_len = pre[2]
        header_bytes = self._recv_all(header_len)
        header = header_bytes.decode("ascii")
        parts = header.split(None, 1)
        packet_type = parts[0] if parts else ""
        data: bytes | None = None
        data_size = 0
        if packet_type == "OK" or packet_type == "ERROR":
            tokens = header.split()
            if len(tokens) >= 3:
                try:
                    data_size = int(tokens[2])
                except ValueError:
                    pass
        elif packet_type == "PACKET":
            tokens = header.split()
            if len(tokens) >= 7:
                try:
                    data_size = int(tokens[6])
                except ValueError:
                    pass
        elif packet_type == "INFO":
            tokens = header.split()
            if len(tokens) >= 3:
                try:
                    data_size = int(tokens[2])
                except ValueError:
                    pass
        elif packet_type not in ("ID", "ENDSTREAM"):
            raise DataLinkError(
                f"Unrecognized packet type {packet_type!r}; "
                "cannot determine data payload size, connection may be desynchronized"
            )
        if data_size > 0:
            data = self._recv_all(data_size)
        return header, data

    def _parse_response(self, header: str, data: bytes | None) -> DataLinkResponse:
        parts = header.split(None, 2)
        status = parts[0] if parts else ""
        value = 0
        if len(parts) >= 2:
            try:
                value = int(parts[1])
            except ValueError:
                pass
        message = data.decode("utf-8", errors="replace") if data else None
        return DataLinkResponse(status=status, value=value, message=message)

    def _expect_ok(self, header: str, data: bytes | None) -> DataLinkResponse:
        resp = self._parse_response(header, data)
        if resp.status == "ERROR":
            raise DataLinkError(resp.message or "Server returned ERROR", resp.value)
        return resp

    @staticmethod
    def _parse_packet(header: str, data: bytes | None) -> DataLinkPacket:
        tokens = header.split()
        if len(tokens) < 7:
            raise DataLinkError(f"Invalid PACKET header: {header}")
        try:
            streamid = tokens[1]
            pktid = int(tokens[2])
            pkttime = int(tokens[3])
            datastart = int(tokens[4])
            dataend = int(tokens[5])
            size = int(tokens[6])
        except (ValueError, IndexError) as e:
            raise DataLinkError(f"Invalid PACKET header: {e}") from e
        payload = data[:size] if data is not None else b""
        return DataLinkPacket(
            streamid=streamid,
            pktid=pktid,
            pkttime=pkttime,
            datastart=datastart,
            dataend=dataend,
            data=payload,
        )

    @staticmethod
    def _generate_client_id(program_name: str | None = None) -> str:
        if program_name is None:
            main_module = sys.modules["__main__"]
            if hasattr(main_module, "__file__"):
                program_name = os.path.basename(main_module.__file__)
            else:
                program_name = "DataLink Client"
        try:
            import getpass
            user = getpass.getuser()
        except Exception:
            user = "unknown"
        pid = os.getpid()
        arch = platform.platform(terse=True) or platform.system()
        return f"{program_name}:{user}:{pid}:{arch}"

    def identify(self, clientid: str | None = None) -> str:
        """Exchange identification with the server and return the server ID string."""
        cid = self._generate_client_id(clientid)
        self._send_packet(f"ID {cid}")
        header, data = self._recv_packet()
        if not header.startswith("ID "):
            raise DataLinkError(f"Expected ID reply, got: {header[:50]}")
        raw = header[3:].strip()
        self.server_id = raw
        self.server_capabilities = {}
        if "::" in raw:
            caps_str = raw.split("::", 1)[1].strip()
            for token in caps_str.split():
                if ":" in token:
                    key, value = token.split(":", 1)
                    self.server_capabilities[key] = value
                else:
                    self.server_capabilities[token] = True
        return raw

    def auth_userpass(self, username: str, password: str) -> DataLinkResponse:
        payload = f"{username}\r{password}".encode("utf-8")
        self._send_packet(f"AUTH USERPASS {len(payload)}", payload)
        header, data = self._recv_packet()
        return self._expect_ok(header, data)

    def auth_jwt(self, token: str) -> DataLinkResponse:
        payload = token.encode("utf-8")
        self._send_packet(f"AUTH JWT {len(payload)}", payload)
        header, data = self._recv_packet()
        return self._expect_ok(header, data)

    def position_set(self, pktid: str | int, uspkttime: int | str) -> DataLinkResponse:
        if isinstance(uspkttime, str):
            uspkttime = timestring_to_ustime(uspkttime)
        self._send_packet(f"POSITION SET {pktid} {uspkttime}")
        header, data = self._recv_packet()
        return self._expect_ok(header, data)

    def position_after(self, ustime: int | str) -> DataLinkResponse:
        if isinstance(ustime, str):
            ustime = timestring_to_ustime(ustime)
        self._send_packet(f"POSITION AFTER {ustime}")
        header, data = self._recv_packet()
        return self._expect_ok(header, data)

    def last_pktid(self) -> int:
        resp = self.position_set("LATEST", 0)
        return resp.value

    def match(self, pattern: str) -> DataLinkResponse:
        payload = pattern.encode("utf-8")
        self._send_packet(f"MATCH {len(payload)}", payload)
        header, data = self._recv_packet()
        return self._expect_ok(header, data)

    def reject(self, pattern: str) -> DataLinkResponse:
        payload = pattern.encode("utf-8")
        self._send_packet(f"REJECT {len(payload)}", payload)
        header, data = self._recv_packet()
        return self._expect_ok(header, data)

    @overload
    def write(
        self,
        streamid: str,
        datastart: int,
        dataend: int,
        data: bytes,
        ack: Literal[True],
        pktid: int | None = ...,
    ) -> DataLinkResponse: ...

    @overload
    def write(
        self,
        streamid: str,
        datastart: int,
        dataend: int,
        data: bytes,
        ack: Literal[False] = ...,
        pktid: int | None = ...,
    ) -> None: ...

    def write(
        self,
        streamid: str,
        datastart: int,
        dataend: int,
        data: bytes,
        ack: bool = False,
        pktid: int | None = None,
    ) -> DataLinkResponse | None:
        flags = ""
        if pktid is not None:
            flags += "I"
        flags += "A" if ack else "N"
        size = len(data)
        header = f"WRITE {streamid} {datastart} {dataend} {flags} {size}"
        if pktid is not None:
            header += f" {pktid}"
        self._send_packet(header, data)
        if ack:
            header_r, data_r = self._recv_packet()
            return self._expect_ok(header_r, data_r)
        return None

    def read(self, pktid: int) -> DataLinkPacket:
        self._send_packet(f"READ {pktid}")
        header, data = self._recv_packet()
        if header.startswith("ERROR"):
            resp = self._parse_response(header, data)
            raise DataLinkError(resp.message or "READ failed", resp.value)
        if not header.startswith("PACKET "):
            raise DataLinkError(f"Expected PACKET reply, got: {header[:50]}")
        return self._parse_packet(header, data)

    def stream(self) -> None:
        self._send_packet("STREAM")
        self._streaming = True

    def endstream(self, timeout: float | None = None) -> None:
        if timeout is None:
            timeout = self._timeout if self._timeout is not None else 30.0
        deadline = time.monotonic() + timeout
        self._send_packet("ENDSTREAM")
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DataLinkError(
                    f"Timed out after {timeout:.1f}s waiting for ENDSTREAM confirmation"
                )
            prev_timeout = self._sock.gettimeout() if self._sock else None
            try:
                if self._sock is not None:
                    self._sock.settimeout(remaining)
                header, _ = self._recv_packet()
            except socket.timeout:
                raise DataLinkError(
                    f"Timed out after {timeout:.1f}s waiting for ENDSTREAM confirmation"
                )
            finally:
                if self._sock is not None:
                    self._sock.settimeout(prev_timeout)
            packet_type = header.split(None, 1)[0] if header else ""
            if packet_type == "ENDSTREAM":
                self._streaming = False
                return
            if packet_type == "PACKET":
                continue
            if packet_type == "ERROR":
                resp = self._parse_response(header, _)
                raise DataLinkError(resp.message or "ENDSTREAM failed", resp.value)
            logger.debug("Draining unexpected packet during ENDSTREAM: %s", header[:80])

    def info(self, info_type: str, match: str | None = None) -> str:
        if match is not None:
            match_bytes = match.encode("utf-8")
            self._send_packet(f"INFO {info_type} {len(match_bytes)}", match_bytes)
        else:
            self._send_packet(f"INFO {info_type}")
        header, data = self._recv_packet()
        if header.startswith("ERROR"):
            resp = self._parse_response(header, data)
            raise DataLinkError(resp.message or "INFO failed", resp.value)
        if not header.startswith("INFO "):
            raise DataLinkError(f"Expected INFO reply, got: {header[:50]}")
        return (data or b"").decode("utf-8", errors="replace")

    @staticmethod
    def _parse_info_xml(xml_string: str) -> dict[str, Any]:
        root = ET.fromstring(xml_string)
        result = typed_attrs(root)
        status_el = root.find("Status")
        if status_el is not None:
            result["Status"] = typed_attrs(status_el)
        threads_el = root.find("ServerThreads")
        if threads_el is not None:
            threads_info = typed_attrs(threads_el)
            threads_info["Thread"] = [typed_attrs(t) for t in threads_el.findall("Thread")]
            result["ServerThreads"] = threads_info
        slist_el = root.find("StreamList")
        if slist_el is not None:
            slist_info = typed_attrs(slist_el)
            slist_info["Stream"] = [typed_attrs(s) for s in slist_el.findall("Stream")]
            result["StreamList"] = slist_info
        clist_el = root.find("ConnectionList")
        if clist_el is not None:
            clist_info = typed_attrs(clist_el)
            clist_info["Connection"] = [typed_attrs(c) for c in clist_el.findall("Connection")]
            result["ConnectionList"] = clist_info
        return result

    def info_status(self, match: str | None = None) -> dict[str, Any]:
        return self._parse_info_xml(self.info("STATUS", match=match))

    def info_streams(self, match: str | None = None) -> dict[str, Any]:
        return self._parse_info_xml(self.info("STREAMS", match=match))

    def info_connections(self, match: str | None = None) -> dict[str, Any]:
        return self._parse_info_xml(self.info("CONNECTIONS", match=match))

    def collect(self) -> Generator[DataLinkPacket, None, None]:
        """Streaming generator: yields DataLinkPacket for each received PACKET."""
        while True:
            header, data = self._recv_packet()
            packet_type = header.split(None, 1)[0] if header else ""
            if packet_type == "ENDSTREAM":
                self._streaming = False
                return
            if packet_type == "PACKET":
                try:
                    yield self._parse_packet(header, data)
                except DataLinkError as e:
                    logger.warning("Invalid PACKET in stream: %s — %s", header[:80], e)
                continue
            if packet_type == "ERROR":
                resp = self._parse_response(header, data)
                raise DataLinkError(resp.message or "Stream error", resp.value)
            logger.debug("Unexpected packet in stream: %s", header[:80])
