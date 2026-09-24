"""Atrapa Nucleusa (logowanie konsolowe): loguje zadanie klienta i odpowiada kodem autoryzacji.

Klient (LoginStateMachineConsole) sklada adres  <nucleusConnect>/connect/auth?response_type=code&
display=..&redirect_uri=..&client_id=..  i wysyla go przez HTTP z naglowkiem `psn_ticket: ...`.
Nie wiemy jeszcze, jakiej odpowiedzi oczekuje: na razie odsylamy 302 z Location =
<redirect_uri>?code=<kod> (klient ma ustawione 'rmax'=0, czyli nie idzie za przekierowaniem, tylko
czyta z niego wartosci z query stringa). Kazde zadanie jest zapisywane w logs/captures/nucleus_*.txt.
Bilet PSN z naglowka nie jest wypisywany na konsole (tylko jego dlugosc); pelne bajty sa w pliku .bin.
"""
from __future__ import annotations

import socket
from urllib.parse import parse_qs, urlsplit

from .config import Config
from .server import Capture

FAKE_CODE = "FAKE_AUTH_CODE_FIFA17"


def build_response(target: str):
    """Zwraca (status_line, extra_headers_dict, body_bytes)."""
    u = urlsplit(target)
    if u.path.endswith("/connect/auth"):
        q = parse_qs(u.query)
        redirect = (q.get("redirect_uri") or [""])[0]
        sep = "&" if "?" in redirect else "?"
        location = f"{redirect}{sep}code={FAKE_CODE}"
        return "302 Found", {"Location": location}, b""
    return "404 Not Found", {}, b"not found\n"


def handle(conn: socket.socket, addr, cfg: Config) -> None:
    cap = Capture(cfg, "nucleus", addr)
    try:
        conn.settimeout(10)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            cap.data("C->S", chunk)
            buf += chunk
        if b"\r\n" not in buf:
            cap.note("brak poprawnego zadania HTTP")
            return
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        lines = head.split("\r\n")
        cap.note(f"Nucleus zadanie: {lines[0]}")
        for h in lines[1:]:
            name, _, val = h.partition(":")
            val = val.strip()
            shown = f"<{len(val)} znakow>" if name.strip().lower() == "psn_ticket" else val
            cap.note(f"  naglowek {name.strip()}: {shown}")
        parts = lines[0].split(" ")
        target = parts[1] if len(parts) > 1 else ""
        status, headers, body = build_response(target)
        out = f"HTTP/1.1 {status}\r\n"
        for k, v in headers.items():
            out += f"{k}: {v}\r\n"
        out += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        conn.sendall(out.encode() + body)
        cap.note(f"Nucleus odpowiedz: {status}" + (f", Location={headers['Location']}" if headers else ""))
    except OSError as exc:
        cap.note(f"blad polaczenia Nucleus: {exc}")
    finally:
        cap.close()
