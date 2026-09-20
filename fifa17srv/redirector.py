"""Fake EA 'redirector': answers redirector/getServerInstance with our own Blaze address.

The response body format follows what other EA Blaze redirectors return; it is UNVERIFIED for
FIFA 17 until we see a real client request in logs/captures/redirector_*.txt.
"""
from __future__ import annotations

import socket
import ssl

from .config import Config
from .server import Capture, negotiate


def server_instance_xml(host: str, port: int, secure: bool) -> bytes:
    ip_int = int.from_bytes(socket.inet_aton(host), "big") if _is_ipv4(host) else 0
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<serverinstanceinfo>"
        '<address member="0"><valu>'
        f"<hostname>{host}</hostname><ip>{ip_int}</ip><port>{port}</port>"
        "</valu></address>"
        f"<secure>{1 if secure else 0}</secure>"
        "<trialservicename></trialservicename>"
        "<defaultdnsaddress>0</defaultdnsaddress>"
        "</serverinstanceinfo>"
    )
    return xml.encode("utf-8")


def _is_ipv4(text: str) -> bool:
    try:
        socket.inet_aton(text)
        return text.count(".") == 3
    except OSError:
        return False


def _read_request(stream, cap: Capture, limit: int = 65536):
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < limit:
        chunk = stream.recv(4096)
        if not chunk:
            break
        cap.data("C->S", chunk)
        buf += chunk
    head, sep, body = buf.partition(b"\r\n\r\n")
    if not sep:
        return None
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2:
        return None
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    try:
        want = int(headers.get("content-length", "0") or 0)
    except ValueError:
        want = 0
    while len(body) < want and len(body) < limit:
        chunk = stream.recv(4096)
        if not chunk:
            break
        cap.data("C->S", chunk)
        body += chunk
    return parts[0], parts[1], headers, body


def handle(conn: socket.socket, addr, cfg: Config, ctx: ssl.SSLContext) -> None:
    cap = Capture(cfg, "redirector", addr)
    stream = None
    try:
        stream = negotiate(conn, ctx, cap)
        if stream is None:
            return
        stream.settimeout(15)
        req = _read_request(stream, cap)
        if req is None:
            cap.note("no valid HTTP request received (client may speak something else)")
            return
        method, path, headers, body = req
        cap.note(f"HTTP {method} {path}")
        cap.note("request body: " + body.decode("utf-8", "replace")[:2000])
        payload = server_instance_xml(cfg.blaze_advertise_host, cfg.blaze_port, cfg.blaze_secure)
        resp = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n"
            + f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
            + payload
        )
        stream.sendall(resp)
        cap.note(f"answered with {cfg.blaze_advertise_host}:{cfg.blaze_port} secure={cfg.blaze_secure}")
    except (ssl.SSLError, OSError) as exc:
        cap.note(f"connection error: {exc}")
    finally:
        try:
            if stream is not None:
                stream.close()
        finally:
            cap.close()
