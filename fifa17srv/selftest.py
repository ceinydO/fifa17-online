"""Self-test: proves the plumbing works using synthetic clients. Does NOT need FIFA 17.

It cannot prove the game behaves the same way -- that is what the real captures are for.
"""
from __future__ import annotations

import logging
import re
import socket
import ssl
import struct
import tempfile
import time
from pathlib import Path

from . import probe, redirector, tdf
from .certs import ensure_certs
from .config import Config
from .server import Server, make_tls_context
from .tls_hello import analyze_client_hello, describe

results = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail and not ok else ""))


def _latest(logdir: Path, prefix: str, suffix: str = ".txt") -> str:
    files = sorted(p for p in logdir.glob(f"{prefix}_*{suffix}") if not p.name.endswith("_c2s.bin"))
    return files[-1].read_text(encoding="utf-8") if files else ""


def _any_log(logdir: Path, prefix: str, needle: str) -> bool:
    """True if any capture log with this prefix contains needle (connections finish in any order)."""
    return any(needle in p.read_text(encoding="utf-8")
               for p in logdir.glob(f"{prefix}_*.txt"))


def _client_ctx(ca: Path, legacy: bool = False) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(str(ca))
    if legacy:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1
    return ctx


def run_selftest() -> int:
    logging.getLogger("fifa17srv").setLevel(logging.WARNING)
    tmp = Path(tempfile.mkdtemp(prefix="fifa17srv_test_"))
    cfg = Config(cert_dir=str(tmp / "certs"), log_dir=str(tmp / "logs"), idle_timeout=2.0)
    paths = ensure_certs(cfg)
    ctx = make_tls_context(cfg)
    check("certificates generated", all(p.exists() for p in paths.values()))

    psrv = Server("probe", "127.0.0.1", 0, lambda c, a: probe.handle(c, a, cfg, ctx)).start()
    cfg.blaze_port = psrv.port
    rsrv = Server("redir", "127.0.0.1", 0, lambda c, a: redirector.handle(c, a, cfg, ctx)).start()
    logs = cfg.log_dir_path

    # 1. HTTPS redirector request, verified against our CA
    body = b'<?xml version="1.0"?><serverinstancerequest><name>fifa-2017-pc</name></serverinstancerequest>'
    req = (b"POST /redirector/getServerInstance HTTP/1.1\r\nHost: " + cfg.redirector_host.encode()
           + b"\r\nContent-Type: application/xml\r\nContent-Length: " + str(len(body)).encode()
           + b"\r\n\r\n" + body)
    with socket.create_connection(("127.0.0.1", rsrv.port), timeout=5) as raw:
        with _client_ctx(paths["ca"]).wrap_socket(raw, server_hostname=cfg.redirector_host) as tls:
            tls.sendall(req)
            resp = b""
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                resp += chunk
    text = resp.decode()
    check("redirector answers over TLS", text.startswith("HTTP/1.1 200"), text[:80])
    check("redirector points at probe port", f"<port>{psrv.port}</port>" in text, text)
    check("redirector encodes 127.0.0.1 as integer", "<ip>2130706433</ip>" in text)
    check("redirector honours secure=0", "<secure>0</secure>" in text)
    time.sleep(0.3)
    rlog = _latest(logs, "redirector")
    check("redirector capture has ClientHello analysis", "ClientHello" in rlog and "cipher suites" in rlog, rlog[:300])
    check("redirector capture has request body", "serverinstancerequest" in rlog)

    # 2. plaintext client on the main port (what we hope the game does with secure=0)
    payload = bytes.fromhex("00000042") + b"\x00\x09PreAuth-test" + bytes(range(32))
    with socket.create_connection(("127.0.0.1", psrv.port), timeout=5) as s:
        s.sendall(payload)
        time.sleep(0.3)
    time.sleep(0.5)
    bins = sorted(logs.glob("blaze_*_c2s.bin"))
    plain_ok = any(b.read_bytes() == payload for b in bins)
    check("probe captures plaintext bytes exactly", plain_ok)
    check("probe detects plaintext", _any_log(logs, "blaze", "plaintext connection"))

    # 3. TLS client on the main port (secure=1 case)
    payload2 = b"\x00\x00\x00\x10" + b"tls-side-payload"
    with socket.create_connection(("127.0.0.1", psrv.port), timeout=5) as raw:
        with _client_ctx(paths["ca"]).wrap_socket(raw, server_hostname=cfg.redirector_host) as tls:
            tls.sendall(payload2)
            time.sleep(0.3)
    time.sleep(0.5)
    check("probe captures bytes through TLS", any(b.read_bytes() == payload2 for b in logs.glob("blaze_*_c2s.bin")))
    check("probe logs TLS handshake OK", _any_log(logs, "blaze", "TLS handshake OK"))

    # 4. legacy TLS 1.0 client (skipped if this OpenSSL cannot do it)
    try:
        payload3 = b"legacy-tls10-client"
        with socket.create_connection(("127.0.0.1", psrv.port), timeout=5) as raw:
            with _client_ctx(paths["ca"], legacy=True).wrap_socket(raw, server_hostname=cfg.redirector_host) as tls:
                ver = tls.version()
                tls.sendall(payload3)
                time.sleep(0.3)
        time.sleep(0.5)
        check(f"legacy {ver} handshake accepted", any(b.read_bytes() == payload3 for b in logs.glob("blaze_*_c2s.bin")))
    except (ssl.SSLError, ValueError, OSError) as exc:
        print(f"[SKIP] legacy TLS 1.0 client not possible on this system ({exc})")

    # 5. a client that rejects our cert: server must log the failure, not crash
    with socket.create_connection(("127.0.0.1", psrv.port), timeout=5) as raw:
        strict = ssl.create_default_context()  # does not trust our CA
        try:
            strict.wrap_socket(raw, server_hostname=cfg.redirector_host)
        except ssl.SSLError:
            pass
    time.sleep(0.5)
    check("failed handshake is logged", _any_log(logs, "blaze", "TLS handshake FAILED"))
    check("failed handshake gets a diagnostic hint", _any_log(logs, "blaze", "HINT: client rejected our certificate"))
    with socket.create_connection(("127.0.0.1", psrv.port), timeout=5) as s:
        s.sendall(b"still alive")
        time.sleep(0.3)
    time.sleep(0.4)
    check("server survives bad client", any(b.read_bytes() == b"still alive" for b in logs.glob("blaze_*_c2s.bin")))

    check("client alert is decoded in the log", _any_log(logs, "blaze", "Alert(fatal, unknown_ca)"))

    # 5b. a client that vanishes (TCP reset) right after our certificate, like a client that
    #     does not trust the CA. The log must say so explicitly.
    hello_ctx = ssl.create_default_context()
    hello_ctx.check_hostname = False
    hello_ctx.verify_mode = ssl.CERT_NONE
    hello_ctx.maximum_version = ssl.TLSVersion.TLSv1_2   # like the game: readable server flight
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = hello_ctx.wrap_bio(inc, out, server_hostname=cfg.redirector_host)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    raw_hello = out.read()
    s = socket.create_connection(("127.0.0.1", psrv.port), timeout=5)
    s.sendall(raw_hello)
    s.settimeout(3)
    got = b""
    try:
        while b"\x0e\x00\x00\x00" not in got:      # ServerHelloDone
            piece = s.recv(65536)
            if not piece:
                break
            got += piece
    except socket.timeout:
        pass
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()                                          # sends RST
    time.sleep(0.6)
    check("server flight seen by client", len(got) > 500)
    check("abrupt reset after certificate is diagnosed",
          _any_log(logs, "blaze", "dropped the connection right after our ServerHelloDone"))
    check("server flight is logged", _any_log(logs, "blaze", "S->C [handshake]") and _any_log(logs, "blaze", "ServerHelloDone"))

    # 5c. SHA-1 signed certificates (built by hand) must also work end to end
    cfg_sha1 = Config(cert_dir=str(tmp / "certs_sha1"), log_dir=str(tmp / "logs_sha1"), cert_sig_hash="sha1")
    paths_sha1 = ensure_certs(cfg_sha1)
    ctx_sha1 = make_tls_context(cfg_sha1)
    ssrv = Server("probe-sha1", "127.0.0.1", 0, lambda c, a: probe.handle(c, a, cfg_sha1, ctx_sha1)).start()
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.set_ciphers("ALL:@SECLEVEL=0")
    cctx.load_verify_locations(str(paths_sha1["ca"]))
    try:
        with socket.create_connection(("127.0.0.1", ssrv.port), timeout=5) as raw:
            with cctx.wrap_socket(raw, server_hostname=cfg_sha1.redirector_host) as tls:
                tls.sendall(b"sha1-cert-client")
                time.sleep(0.3)
        time.sleep(0.5)
        check("SHA-1 signed certificate is accepted by a verifying client",
              any(b.read_bytes() == b"sha1-cert-client" for b in cfg_sha1.log_dir_path.glob("blaze_*_c2s.bin")))
    except ssl.SSLError as exc:
        check("SHA-1 signed certificate is accepted by a verifying client", False, str(exc))
    ssrv.stop()

    # 6. ClientHello parser on a real hello produced by Python's ssl
    a, b = socket.socketpair()
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = c.wrap_bio(inc, out, server_hostname="example.test")
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = out.read()
    info = analyze_client_hello(hello)
    check("ClientHello parser reads a real hello", info is not None and len(info.cipher_suites) > 3
          and info.sni == "example.test", describe(info))
    a.close(); b.close()

    # 7. TDF codec round trip
    sample = [
        ("NAME", tdf.STRING, "hello"),
        ("NUM", tdf.VARINT, 300000),
        ("ZERO", tdf.VARINT, 0),
        ("BLOB", tdf.BLOB, b"\x01\x02\x03"),
        ("SUB", tdf.STRUCT, [("A1", tdf.VARINT, 5), ("B2", tdf.STRING, "x")]),
        ("LST", tdf.LIST, (tdf.STRING, ["a", "bb"])),
        ("SLST", tdf.LIST, (tdf.STRUCT, [[("Q", tdf.VARINT, 1)], [("Q", tdf.VARINT, 2)]])),
        ("MAP", tdf.MAP, (tdf.STRING, tdf.VARINT, [("k", 1), ("j", 2)])),
        ("UNI", tdf.UNION, (2, ("INNR", tdf.VARINT, 9))),
        ("UNS", tdf.UNION, (tdf.UNION_UNSET, None)),
        ("ILST", tdf.INTLIST, [1, 2, 1000]),
        ("OTYP", tdf.OBJTYPE, (30722, 1)),
        ("OID", tdf.OBJID, (1, 2, 3)),
        ("FLT", tdf.FLOAT, 1.5),
    ]
    encoded = tdf.encode(sample)
    decoded = tdf.decode(encoded)
    check("TDF encode/decode round trip", decoded == sample, str(decoded)[:200])
    check("TDF varint edge cases", all(
        tdf.Reader(tdf.enc_varint(v)).varint() == v for v in (0, 1, 63, 64, 127, 128, 8191, 8192, 2**32, 2**63)))
    check("TDF tag round trip", all(tdf.decode_tag(tdf.encode_tag(t)) == t for t in ("NAME", "ZZZZ", "AB", "X1", "1234")))
    fields, reached, err = tdf.decode_partial(b"\xff\xff\xff\xff")
    check("TDF decoder rejects garbage without crashing", err is not None and fields == [])

    psrv.stop()
    rsrv.stop()
    passed, total = sum(results), len(results)
    print(f"\n{passed}/{total} checks passed  (temp dir: {tmp})")
    return 0 if passed == total else 1
