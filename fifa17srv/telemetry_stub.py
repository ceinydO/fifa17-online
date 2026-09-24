"""Stub for EA telemetry hosts (rl.data.ea.com, pin-river.data.ea.com, ...).

These hostnames get redirected to 127.0.0.1 via RPCS3's IP/Hosts switches (DNS Swap List),
and the game tries to reach them over HTTPS on port 443.

Wersja 1 (WYKLUCZONA -- patrz HANDOFF sesja 9, Tor 2): accept+close natychmiast, bez
odczytania czegokolwiek. To dawalo klientowi RST/FIN zamiast polowicznie otwartego socketu,
ale najwyrazniej gra ROBI cos wiecej z ta polaczeniem niz tylko heartbeat -- prawdopodobnie
SeasonalPlayDownloader czeka na udana transakcje HTTP (200 OK) zanim odpyta komponent Stats.

Wersja 2 (ta): robimy prawdziwy handshake TLS (jak qos.py) i odpowiadamy realnym
"HTTP/1.1 200 OK" z pustym cialem, zamiast zrywac polaczenie od razu. Jesli to byl
rzeczywiscie blocker, po tej zmianie w Cup Match powinno pojawic sie NOWE zadanie Blaze
(np. do komponentu Stats) zamiast tylko keepalive pingow.
"""
from __future__ import annotations

import logging
import socket

from .config import Config
from .server import Capture, negotiate

log = logging.getLogger("fifa17srv")


def handle(conn: socket.socket, addr, cfg: Config, ctx=None) -> None:
    cap = Capture(cfg, "telemetry", addr)
    try:
        stream = conn
        if ctx is not None:
            stream = negotiate(conn, ctx, cap)
            if stream is None:
                return
        stream.settimeout(5)
        buf = b""
        try:
            while b"\r\n\r\n" not in buf and len(buf) < 65536:
                chunk = stream.recv(4096)
                if not chunk:
                    break
                cap.data("C->S", chunk)
                buf += chunk
        except OSError as exc:
            cap.note(f"telemetry: blad przy odczycie zadania: {exc}")
        if buf:
            line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            cap.note(f"telemetry zadanie: {line}")
        else:
            cap.note("telemetry: klient nawiazal polaczenie ale nie przyslal zadania HTTP")
        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        try:
            stream.sendall(resp)
            cap.note("telemetry odpowiedz: 200 OK, 0B")
        except OSError as exc:
            cap.note(f"telemetry: nie udalo sie wyslac odpowiedzi: {exc}")
    except OSError as exc:
        cap.note(f"blad polaczenia telemetry: {exc}")
    finally:
        cap.close()
