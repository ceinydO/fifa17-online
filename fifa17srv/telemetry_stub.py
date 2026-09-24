"""Stub for EA telemetry hosts (rl.data.ea.com, pin-river.data.ea.com, ...).

These hostnames get redirected to 127.0.0.1 via RPCS3's IP/Hosts switches (DNS Swap List),
and the game tries to reach them over HTTPS on port 443. We don't implement the actual
telemetry protocol -- we just want the connection to fail *fast* and *cleanly* instead of
sitting around waiting for a timeout that never resolves cleanly on Windows (observed as
sys_net_bnet_connect -> EINPROGRESS, then ~1s later sys_net_bnet_shutdown -> ENOTCONN,
repeating roughly every 60 seconds from FEThread).

Accepting the TCP connection and closing it immediately gives the client an immediate
RST/FIN instead of a half-open socket, which should let it notice failure sooner and stop
retrying in a way that could be blocking UI progress.
"""
from __future__ import annotations

import logging
import os
import socket
import struct

log = logging.getLogger("fifa17srv")

# struct linger differs by platform: Windows (winsock) uses two u_short (4 bytes total),
# POSIX typically uses two int (8 bytes total). Pack the right one so SO_LINGER actually
# takes effect instead of silently failing/raising.
_LINGER_ON_ZERO = struct.pack("hh", 1, 0) if os.name == "nt" else struct.pack("ii", 1, 0)


def handle(conn: socket.socket, addr) -> None:
    log.info("[telemetry] connection from %s, closing immediately (stub, no real telemetry)", addr)
    try:
        # Reject rather than silently hang: SO_LINGER(on=1, timeout=0) makes close() send an
        # immediate RST instead of a graceful FIN, so the client notices failure right away.
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, _LINGER_ON_ZERO)
    except OSError:
        pass
    try:
        conn.close()
    except OSError:
        pass
