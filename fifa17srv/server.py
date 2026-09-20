"""Shared plumbing: capture logging, TLS-or-plaintext negotiation, threaded TCP server."""
from __future__ import annotations

import datetime
import logging
import os
import socket
import ssl
import threading
import time
from typing import Callable, Optional

from .config import Config
from .tls_hello import analyze_client_hello, classify, describe, summarize_records
from .util import hexdump

log = logging.getLogger("fifa17srv")


class Capture:
    """One capture per connection: a human-readable .txt log and the raw client bytes as .bin."""

    def __init__(self, cfg: Config, tag: str, peer):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        d = cfg.log_dir_path
        d.mkdir(parents=True, exist_ok=True)
        self.tag, self.peer = tag, peer
        self.base = d / f"{tag}_{ts}_{peer[1]}"
        self._txt = open(f"{self.base}.txt", "w", encoding="utf-8")
        self._bin = open(f"{self.base}_c2s.bin", "wb")
        self.txt_path = f"{self.base}.txt"
        self.bin_path = f"{self.base}_c2s.bin"

    def note(self, msg: str) -> None:
        self._txt.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self._txt.flush()
        log.info("[%s] %s", self.tag, msg.replace("\n", " | "))

    def data(self, direction: str, chunk: bytes) -> None:
        self.note(f"{direction} {len(chunk)} bytes")
        self._txt.write(hexdump(chunk) + "\n")
        self._txt.flush()
        if direction == "C->S":
            self._bin.write(chunk)
            self._bin.flush()

    def close(self) -> None:
        for f in (self._txt, self._bin):
            try:
                f.close()
            except OSError:
                pass


def make_tls_context(cfg: Config) -> ssl.SSLContext:
    """A deliberately permissive server context (old clients, local dev only)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        ctx.set_ciphers("ALL")
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (ValueError, ssl.SSLError):
        pass
    d = cfg.cert_dir_path
    cert_name = "server.pem" if cfg.cert_send_chain else "server_leaf.pem"
    ctx.load_cert_chain(certfile=str(d / cert_name), keyfile=str(d / "server.key"))
    return ctx


class TracedTLS:
    """Server-side TLS over a socket with the handshake pumped by hand.

    Same job as ssl.wrap_socket(), but every byte of the handshake is logged in both directions,
    so when a client hangs up we can see exactly what it received and what it answered.
    Exposes the small subset of the socket API the handlers use.
    """

    def __init__(self, sock: socket.socket, ctx: ssl.SSLContext, cap: Capture):
        self.sock, self.cap = sock, cap
        self._in, self._out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.obj = ctx.wrap_bio(self._in, self._out, server_side=True)
        self.sent_server_done = False
        self.client_replied = False
        self._first_recv = True

    def _flush(self) -> None:
        data = self._out.read()
        if not data:
            return
        summary = summarize_records(data)
        if "ServerHelloDone" in summary:
            self.sent_server_done = True
        self.cap.note(f"S->C [handshake] {len(data)} bytes: {summary}")
        self.sock.sendall(data)

    def _feed(self) -> None:
        chunk = self.sock.recv(16384)
        if not chunk:
            self._in.write_eof()
            raise ConnectionResetError("client closed the connection")
        if self._first_recv:
            self._first_recv = False          # the ClientHello, already analysed
        else:
            self.client_replied = True
            self.cap.note(f"C->S [handshake] {len(chunk)} bytes: {summarize_records(chunk)}")
            self.cap.data("C->S[hs]", chunk)
        self._in.write(chunk)

    def handshake(self) -> None:
        while True:
            try:
                self.obj.do_handshake()
                self._flush()
                return
            except ssl.SSLWantReadError:
                self._flush()
                self._feed()
            except ssl.SSLError:
                try:
                    self._flush()               # send our alert, if any
                except OSError:
                    pass
                raise

    # -- socket-like API used by the handlers --------------------------------------------
    def settimeout(self, value) -> None:
        self.sock.settimeout(value)

    def recv(self, n: int) -> bytes:
        while True:
            try:
                return self.obj.read(n)
            except ssl.SSLWantReadError:
                self._flush()
                try:
                    self._feed()
                except ConnectionResetError:
                    return b""
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                return b""

    def sendall(self, data: bytes) -> None:
        self.obj.write(data)
        self._flush()

    def version(self):
        return self.obj.version()

    def cipher(self):
        return self.obj.cipher()

    def close(self) -> None:
        try:
            self.obj.unwrap()
        except (ssl.SSLError, OSError, ValueError):
            pass
        try:
            self._flush()
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


def _peek_first_record(conn: socket.socket, timeout: float = 5.0) -> bytes:
    deadline = time.time() + timeout
    data = b""
    conn.settimeout(timeout)
    while time.time() < deadline:
        data = conn.recv(16384, socket.MSG_PEEK)
        if not data:
            return b""
        if classify(data) != "incomplete":
            break
        time.sleep(0.02)
    return data


def negotiate(conn: socket.socket, ctx: ssl.SSLContext, cap: Capture):
    """Return a stream (SSLSocket or the plain socket), or None if the handshake failed.

    Looks at the first bytes without consuming them, logs what the client offers,
    then either performs a TLS handshake or continues in plaintext.
    """
    first = _peek_first_record(conn)
    if not first:
        cap.note("client connected and closed without sending anything")
        return None
    kind = classify(first)
    if kind in ("tls", "sslv2"):
        cap.note(describe(analyze_client_hello(first)))
        conn.settimeout(15)
        tls = TracedTLS(conn, ctx, cap)
        try:
            tls.handshake()
        except (ssl.SSLError, OSError) as exc:
            cap.note(f"TLS handshake FAILED: {type(exc).__name__}: {exc}")
            text = str(exc).lower()
            if isinstance(exc, ssl.SSLError):
                if "unknown ca" in text or "bad certificate" in text or "certificate" in text:
                    cap.note("HINT: client rejected our certificate (it likely has its own CA list).")
                elif "no shared cipher" in text or "wrong version" in text or "unsupported" in text \
                        or "no protocols" in text or "version" in text:
                    cap.note("HINT: protocol/cipher mismatch; see the ClientHello above.")
            elif tls.sent_server_done and not tls.client_replied:
                cap.note(
                    "HINT: the client dropped the connection right after our ServerHelloDone without "
                    "sending anything (no ClientKeyExchange, no alert). It received our certificate and "
                    "did not like it: most likely it does not trust our CA, or cannot parse the "
                    "certificate. Try 'certs --force --sha1'; if it still happens, the game probably "
                    "checks certificates against a CA list built into the executable."
                )
            elif not tls.sent_server_done:
                cap.note("HINT: the client hung up before our server flight was complete; "
                         "see the S->C lines above.")
            else:
                cap.note("HINT: the client replied to our server flight and then hung up; "
                         "see the C->S [handshake] lines above.")
            try:
                tls.sock.close()
            except OSError:
                pass
            return None
        cap.note(f"TLS handshake OK: version={tls.version()} cipher={tls.cipher()[0]}")
        return tls
    cap.note(f"plaintext connection (first bytes: {first[:16].hex()})")
    return conn


class Server:
    """Tiny threaded TCP server. port=0 picks a free port (see .port)."""

    def __init__(self, name: str, bind: str, port: int, handler: Callable[[socket.socket, tuple], None]):
        self.name, self.handler = name, handler
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name != "nt":
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind, port))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self._stopped = False

    def start(self) -> "Server":
        threading.Thread(target=self._loop, name=self.name, daemon=True).start()
        return self

    def _loop(self) -> None:
        while not self._stopped:
            try:
                conn, addr = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._serve_one, args=(conn, addr), daemon=True).start()

    def _serve_one(self, conn: socket.socket, addr) -> None:
        try:
            self.handler(conn, addr)
        except Exception:  # keep the server alive whatever the client sends
            log.exception("[%s] handler crashed for %s", self.name, addr)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stopped = True
        try:
            self.sock.close()
        except OSError:
            pass
