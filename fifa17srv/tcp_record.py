"""Atrapa TCP, ktora tylko NAGRYWA, co klient wysyla (np. serwer ticker -- gorny pasek gry).

Polaczenie jest trzymane otwarte do 60 s (klient nie widzi natychmiastowego zerwania), wszystko co
przyjdzie trafia do logs/captures/<label>_*.txt/.bin. Niczego nie odpowiada -- to tylko diagnostyka.
"""
from __future__ import annotations

import socket
import time

from .config import Config
from .server import Capture


def handle(conn: socket.socket, addr, cfg: Config, label: str = "ticker") -> None:
    cap = Capture(cfg, label, addr)
    try:
        conn.settimeout(5)
        deadline = time.time() + 60
        total = 0
        cap.note(f"{label}: polaczenie od {addr}")
        while time.time() < deadline:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                cap.note(f"{label}: klient zamknal polaczenie (odebrano {total}B)")
                break
            total += len(chunk)
            cap.data("C->S", chunk)
            cap.note(f"{label}: {len(chunk)}B od klienta: {chunk[:200]!r}")
    except OSError as exc:
        cap.note(f"blad polaczenia {label}: {exc}")
    finally:
        cap.close()
