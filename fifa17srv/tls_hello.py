"""Parse a TLS/SSLv2-format ClientHello so we can see *why* a handshake with the game fails.

Old EA clients use their own TLS stack (ProtoSSL). It may offer only SSLv3/TLS1.0 and legacy
ciphers that modern OpenSSL refuses. This module tells us exactly what the client offers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

VERSIONS = {0x0002: "SSLv2", 0x0300: "SSLv3", 0x0301: "TLS1.0", 0x0302: "TLS1.1",
            0x0303: "TLS1.2", 0x0304: "TLS1.3"}

CIPHERS = {
    0x0001: "RSA_NULL_MD5", 0x0002: "RSA_NULL_SHA", 0x0004: "RSA_RC4_128_MD5",
    0x0005: "RSA_RC4_128_SHA", 0x000A: "RSA_3DES_EDE_CBC_SHA", 0x0009: "RSA_DES_CBC_SHA",
    0x002F: "RSA_AES_128_CBC_SHA", 0x0035: "RSA_AES_256_CBC_SHA", 0x003C: "RSA_AES_128_CBC_SHA256",
    0x003D: "RSA_AES_256_CBC_SHA256", 0x009C: "RSA_AES_128_GCM_SHA256",
    0xC013: "ECDHE_RSA_AES_128_CBC_SHA", 0xC014: "ECDHE_RSA_AES_256_CBC_SHA",
    0xC02F: "ECDHE_RSA_AES_128_GCM_SHA256", 0xC030: "ECDHE_RSA_AES_256_GCM_SHA384",
    0x0033: "DHE_RSA_AES_128_CBC_SHA", 0x0039: "DHE_RSA_AES_256_CBC_SHA",
    0x00FF: "EMPTY_RENEGOTIATION_INFO_SCSV", 0x0003: "RSA_EXPORT_RC4_40_MD5",
    0x0008: "RSA_EXPORT_DES40_CBC_SHA", 0x0006: "RSA_EXPORT_RC2_CBC_40_MD5",
}


@dataclass
class HelloInfo:
    fmt: str                      # "TLS" or "SSLv2-compatible"
    record_version: str = "?"
    client_version: str = "?"
    cipher_suites: list = field(default_factory=list)
    sni: Optional[str] = None
    extension_types: list = field(default_factory=list)


def _u16(b: bytes, p: int) -> int:
    return int.from_bytes(b[p : p + 2], "big")


def classify(data: bytes) -> str:
    """'tls' | 'sslv2' | 'plain' | 'incomplete' -- based on the first bytes on the wire."""
    if not data:
        return "incomplete"
    if data[0] == 0x16:
        if len(data) < 5:
            return "incomplete"
        return "tls" if len(data) >= 5 + _u16(data, 3) else "incomplete"
    if data[0] == 0x80:
        if len(data) < 2:
            return "incomplete"
        return "sslv2" if len(data) >= 2 + data[1] else "incomplete"
    return "plain"


def analyze_client_hello(data: bytes) -> Optional[HelloInfo]:
    try:
        if data[:1] == b"\x16":
            return _parse_tls(data)
        if data[:1] == b"\x80":
            return _parse_sslv2(data)
    except (IndexError, ValueError):
        pass
    return None


def _parse_tls(data: bytes) -> Optional[HelloInfo]:
    info = HelloInfo(fmt="TLS")
    info.record_version = VERSIONS.get(_u16(data, 1), hex(_u16(data, 1)))
    body = data[5 : 5 + _u16(data, 3)]
    if not body or body[0] != 1:
        return None
    p = 4
    info.client_version = VERSIONS.get(_u16(body, p), hex(_u16(body, p)))
    p += 2 + 32
    p += 1 + body[p]                      # session id
    cs_len = _u16(body, p); p += 2
    info.cipher_suites = [_u16(body, p + i) for i in range(0, cs_len, 2)]
    p += cs_len
    p += 1 + body[p]                      # compression methods
    if p + 2 <= len(body):
        ext_total = _u16(body, p); p += 2
        end = min(len(body), p + ext_total)
        while p + 4 <= end:
            et, el = _u16(body, p), _u16(body, p + 2)
            info.extension_types.append(et)
            if et == 0 and el >= 5:       # server_name
                nl = _u16(body, p + 7)
                info.sni = body[p + 9 : p + 9 + nl].decode("ascii", "replace")
            p += 4 + el
    return info


def _parse_sslv2(data: bytes) -> Optional[HelloInfo]:
    if data[2] != 1:
        return None
    info = HelloInfo(fmt="SSLv2-compatible")
    info.record_version = "SSLv2 framing"
    info.client_version = VERSIONS.get(_u16(data, 3), hex(_u16(data, 3)))
    cs_len, sid_len, ch_len = _u16(data, 5), _u16(data, 7), _u16(data, 9)
    p = 11
    for i in range(0, cs_len, 3):
        spec = data[p + i : p + i + 3]
        if len(spec) == 3 and spec[0] == 0:
            info.cipher_suites.append(int.from_bytes(spec[1:], "big"))
    return info


def describe(info: Optional[HelloInfo]) -> str:
    if info is None:
        return "ClientHello: could not parse"
    names = [CIPHERS.get(c, f"0x{c:04X}") for c in info.cipher_suites]
    out = [
        f"ClientHello ({info.fmt}): record={info.record_version} client_version={info.client_version}",
        f"  cipher suites ({len(names)}): " + ", ".join(names),
    ]
    if info.sni:
        out.append(f"  SNI: {info.sni}")
    if info.extension_types:
        out.append("  extensions: " + ", ".join(str(e) for e in info.extension_types))
    return "\n".join(out)


ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 21: "decryption_failed",
          22: "record_overflow", 30: "decompression_failure", 40: "handshake_failure",
          41: "no_certificate", 42: "bad_certificate", 43: "unsupported_certificate",
          44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
          47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied", 50: "decode_error",
          51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
          80: "internal_error", 90: "user_canceled", 100: "no_renegotiation"}

HANDSHAKE_TYPES = {1: "ClientHello", 2: "ServerHello", 11: "Certificate", 12: "ServerKeyExchange",
                   13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify",
                   16: "ClientKeyExchange", 20: "Finished"}


def summarize_records(data: bytes) -> str:
    """One-line description of the TLS records in `data`, e.g.
    'Handshake[ServerHello, Certificate, ServerHelloDone]' or 'Alert(fatal, unknown_ca)'."""
    out = []
    p = 0
    encrypted = False        # after ChangeCipherSpec, handshake records are opaque
    while p + 5 <= len(data):
        rtype, length = data[p], _u16(data, p + 3)
        body = data[p + 5 : p + 5 + length]
        if rtype == 0x15 and len(body) >= 2 and not encrypted:
            level = "fatal" if body[0] == 2 else "warning"
            out.append(f"Alert({level}, {ALERTS.get(body[1], body[1])})")
        elif rtype == 0x14:
            out.append("ChangeCipherSpec")
            encrypted = True
        elif rtype == 0x16 and not encrypted:
            names, q = [], 0
            while q + 4 <= len(body):
                mlen = int.from_bytes(body[q + 1 : q + 4], "big")
                names.append(HANDSHAKE_TYPES.get(body[q], f"type{body[q]}"))
                q += 4 + mlen
            out.append("Handshake[" + ", ".join(names) + "]")
        elif rtype == 0x16:
            out.append("Handshake(encrypted, probably Finished)")
        elif rtype == 0x17:
            out.append("ApplicationData")
        else:
            out.append(f"record type 0x{rtype:02x}")
        if p + 5 + length > len(data):
            out[-1] += "(truncated)"
        p += 5 + length
    if p < len(data):
        out.append(f"+{len(data) - p} stray bytes")
    return ", ".join(out) if out else "(nothing)"
