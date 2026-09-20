"""Capture probe for the main Blaze port. Records everything the game sends; answers nothing yet.

Once we have real captures we replace this with a proper Blaze handler.
"""
from __future__ import annotations

import socket
import ssl

from .config import Config
from .server import Capture, negotiate


def handle(conn: socket.socket, addr, cfg: Config, ctx: ssl.SSLContext) -> None:
    cap = Capture(cfg, "blaze", addr)
    stream = None
    total = 0
    try:
        stream = negotiate(conn, ctx, cap)
        if stream is None:
            return
        stream.settimeout(cfg.idle_timeout)
        while True:
            try:
                chunk = stream.recv(65536)
            except socket.timeout:
                cap.note(f"idle for {cfg.idle_timeout}s, closing")
                break
            if not chunk:
                cap.note("client closed the connection")
                break
            total += len(chunk)
            cap.data("C->S", chunk)
    except (ssl.SSLError, OSError) as exc:
        cap.note(f"connection error: {exc}")
    finally:
        cap.note(f"total received: {total} bytes -> {cap.bin_path}")
        try:
            if stream is not None:
                stream.close()
        finally:
            cap.close()
