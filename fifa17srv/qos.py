"""Lokalny serwer QoS (Quality of Service) dla klienta Blaze -- proste odpowiedzi XML po HTTP.

Wzorowany na PocketRelay (src/routes/qos.rs), ktory ma tez komentarz, ze to zadanie
"must succeed or the client doesn't seem to know its external IP". Klient laczy sie tu
pod adres z PreAuthResponse (QOSS.BWPS.PSA:PSP oraz wpisy LTPS).

Wszystkie odpowiedzi maja numprobes=0, wiec klient nie powinien wysylac probek UDP
(nie mamy odpowiadacza UDP). Kazde zadanie jest logowane do logs/captures/qos_*.txt --
to tez dowod, czy gra w ogole probuje sie tu polaczyc.
"""
from __future__ import annotations

import socket
from urllib.parse import parse_qs, urlsplit

from .config import Config
from .server import Capture, negotiate

QOS_PORT = 17502
_IP_U32 = int.from_bytes(socket.inet_aton("127.0.0.1"), "big")  # 2130706433


def _qos_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<qos>\n"
        "    <numprobes>0</numprobes>\n"
        f"    <qosport>{QOS_PORT}</qosport>\n"
        "    <probesize>0</probesize>\n"
        f"    <qosip>{_IP_U32}</qosip>\n"
        "    <requestid>1</requestid>\n"
        "    <reqsecret>0</reqsecret>\n"
        "</qos>\n"
    )


def _firewall_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<firewall>\n"
        "    <ips>\n"
        f"        <ips>{_IP_U32}</ips>\n"
        f"        <ips>{_IP_U32}</ips>\n"
        "    </ips>\n"
        "    <numinterfaces>2</numinterfaces>\n"
        "    <ports>\n"
        "        <ports>17500</ports>\n"
        "        <ports>17501</ports>\n"
        "    </ports>\n"
        "    <requestid>747</requestid>\n"
        "    <reqsecret>502</reqsecret>\n"
        "</firewall>\n"
    )


def _firetype_xml() -> str:
    """firetype=0 -- HIPOTEZA: 0=Open w typowym oznaczeniu EA/DirtySDK (0=Open, 1=Moderate,
    2=Strict). Bylo 2 (Strict); klient moze na tej podstawie uznawac, ze P2P jest niemozliwe
    i nigdy nie probowac GameManager::createGame/joinGame -- co pasuje do obserwacji: po
    Stats i drugim updateNetworkInfo klient milknie i pokazuje "PRESS START TO RE-CONNECT"."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<firetype>\n"
        "    <firetype>0</firetype>\n"
        "</firetype>\n"
    )


def build_response(path_and_query: str):
    """Zwraca (status_line, body_bytes) dla danej sciezki."""
    u = urlsplit(path_and_query)
    if u.path == "/qos/qos":
        body = _qos_xml()
    elif u.path == "/qos/firewall":
        body = _firewall_xml()
    elif u.path == "/qos/firetype":
        body = _firetype_xml()
    else:
        return "404 Not Found", b"not found\n"
    return "200 OK", body.encode("utf-8")


def handle(conn: socket.socket, addr, cfg: Config, ctx=None) -> None:
    """Obsluguje polaczenie QoS. Klient laczy sie tu przez TLS (pierwsze bajty to ClientHello z SNI = adres
    serwera QoS), wiec z `ctx` robimy handshake tak samo jak w przekierowaniu; bez `ctx` (albo gdy klient
    zacznie zwyklym tekstem) obslugujemy zwykly HTTP."""
    cap = Capture(cfg, "qos", addr)
    try:
        stream = conn
        if ctx is not None:
            stream = negotiate(conn, ctx, cap)
            if stream is None:
                return
        stream.settimeout(10)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = stream.recv(4096)
            if not chunk:
                break
            cap.data("C->S", chunk)
            buf += chunk
        if b"\r\n" not in buf:
            cap.note("brak poprawnego zadania HTTP")
            return
        line = buf.split(b"\r\n", 1)[0].decode("latin-1")
        parts = line.split(" ")
        target = parts[1] if len(parts) > 1 else ""
        cap.note(f"QoS zadanie: {line}")
        status, body = build_response(target)
        resp = (
            f"HTTP/1.1 {status}\r\nContent-Type: text/xml\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode() + body
        stream.sendall(resp)
        cap.note(f"QoS odpowiedz: {status}, {len(body)}B")
    except OSError as exc:
        cap.note(f"blad polaczenia QoS: {exc}")
    finally:
        cap.close()
