"""Atrapa uslugi POW / EASFC (EA SPORTS Football Club) -- tylko NAGRYWA zadania HTTP.

Z analizy EBOOT (2026-10-08): klasa POWService buduje adres z klucza konfiguracji serwera
FIFA_POW_URL (domyslnie http://pas.gt.easfc.ea.com:8094) i FIFA_POW_CONTENT_SERVER_URL
(domyslnie http://content.lt.easfc.ea.com:8080). Gdy serwer nie poda tych kluczy, adres jest pusty
(RPCS3 loguje "DnsHook: DNS query for " z pusta nazwa) i gra pokazuje "...servers are unavailable".
Ta atrapa przyjmuje polaczenia na tych portach, zapisuje pelne zadanie (metoda, sciezka, naglowki EASW-*,
cialo) do logs/captures i odpowiada 200 z pustym JSON-em, zeby poznac protokol. Nie udaje prawdziwej uslugi.
"""
from __future__ import annotations

import socket

from .config import Config
from .server import Capture


def _read_request(conn: socket.socket, cap: Capture):
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 65536:
        chunk = conn.recv(4096)
        if not chunk:
            return None, b""
        cap.data("C->S", chunk)
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    length = 0
    for line in head.decode("latin-1").split("\r\n")[1:]:
        k, _, v = line.partition(":")
        if k.strip().lower() == "content-length":
            try:
                length = int(v.strip())
            except ValueError:
                length = 0
    body = rest
    while len(body) < length and len(body) < 1_000_000:
        chunk = conn.recv(4096)
        if not chunk:
            break
        cap.data("C->S", chunk)
        body += chunk
    return head.decode("latin-1"), body


def handle(conn: socket.socket, addr, cfg: Config, label: str = "pow") -> None:
    cap = Capture(cfg, label, addr)
    try:
        conn.settimeout(10)
        while True:
            head, body = _read_request(conn, cap)
            if head is None:
                break
            lines = head.split("\r\n")
            cap.note(f"{label} zadanie: {lines[0]}")
            for h in lines[1:]:
                name, _, val = h.partition(":")
                cap.note(f"  naglowek {name.strip()}: {val.strip()[:300]}")
            if body:
                cap.note(f"  cialo ({len(body)}B): {body[:600]!r}")
            payload = b"{}"
            resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    + f"Content-Length: {len(payload)}\r\n".encode()
                    + b"Connection: close\r\n\r\n" + payload)
            conn.sendall(resp)
            cap.note(f"{label} odpowiedz: 200 OK {{}}")
            break
    except OSError as exc:
        cap.note(f"blad polaczenia {label}: {exc}")
    finally:
        cap.close()
