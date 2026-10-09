"""Messaging (komponent 0x000F) -- skrzynka wiadomosci miedzy graczami.

OSDK (warstwa zaproszen w FIFA 17) trzyma zaproszenia jako wiadomosci Blaze ("EVENT_INVITE_NEW_MAIL",
"EVENT_INVITE_MAIL_LOADED"); klient odpytuje skrzynke przez fetchMessages/getMessages (typ 'room' = zaproszenia do
pokoi). Serwer przechowuje wiadomosci w pamieci i dostarcza je jako NotifyMessage (powiadomienie 0x0001).

Ksztalty wg refleksji FIFA 17: SendMessageRequest/ClientMessage {ATTR, FLAG, STAT, TAG, TIDS, TTYP, TYPE},
ServerMessage {FLAG, MGID, PYLD{ATTR, FLAG, STAT, TAG, TYPE}, SRCE, TIME, USER}, SendMessageResponse {MGID, MIDS},
FetchMessagesResponse {MCNT}, GetMessagesResponse {MCNT, MSLT}.
"""
from __future__ import annotations

import threading
import time

from . import ids, tdf

MESSAGING_COMPONENT = 0x000F
CMD_SEND_MESSAGE = 0x0001
CMD_FETCH_MESSAGES = 0x0002
CMD_PURGE_MESSAGES = 0x0003
CMD_TOUCH_MESSAGES = 0x0004
CMD_GET_MESSAGES = 0x0005
NOTIFY_MESSAGE = 0x0001

USER_ENTITY_TYPE = (30722, 1)

_LOCK = threading.Lock()
_next_id = [1]
_MAILBOX: dict = {}          # uid odbiorcy -> [wiadomosc]


def reset() -> None:
    with _LOCK:
        _MAILBOX.clear()
        _next_id[0] = 1


def _field(fields, tag, default=None):
    tag = tag.rstrip()                 # tdf.decode zwraca tagi bez wyrownujacych spacji ("GID", nie "GID ")
    for t, _typ, v in fields:
        if t.rstrip() == tag:
            return v
    return default


def _server_message(msg: dict, sender_identity):
    from .blaze import build_user_identification     # unikamy cyklicznego importu na poziomie modulu
    payload = sorted([("ATTR", tdf.MAP, msg["attr"]), ("FLAG", tdf.VARINT, msg["flag"]),
                      ("STAT", tdf.VARINT, msg["stat"]), ("TAG ", tdf.VARINT, msg["tag"]),
                      ("TYPE", tdf.VARINT, msg["type"])], key=lambda f: f[0])
    fields = [("FLAG", tdf.VARINT, 0), ("MGID", tdf.VARINT, msg["id"]), ("PYLD", tdf.STRUCT, payload),
              ("SRCE", tdf.OBJID, USER_ENTITY_TYPE + (msg["src_uid"],)), ("TIME", tdf.VARINT, msg["time"]),
              ("USER", tdf.STRUCT, build_user_identification(sender_identity))]
    return sorted(fields, key=lambda f: f[0])


def send_message(sender: str, sender_identity, fields, names, identity_of):
    """Zapisuje i rozsyla wiadomosc. `names` = polaczeni gracze, `identity_of(nazwa)` -> (nazwa, ext, blob).
    Zwraca (pola_odpowiedzi, [(nazwa_odbiorcy, ramka_NotifyMessage)])."""
    targets = _field(fields, "TIDS", (0, [])) or (0, [])
    target_ids = list(targets[1]) if isinstance(targets, tuple) else list(targets)
    attr = _field(fields, "ATTR", (0, 1, [])) or (0, 1, [])
    stored_ids, outs = [], []
    with _LOCK:
        for tid in target_ids:
            mid = _next_id[0]
            _next_id[0] += 1
            msg = {"id": mid, "type": _field(fields, "TYPE", 0) or 0, "attr": attr,
                   "flag": _field(fields, "FLAG", 0) or 0, "stat": _field(fields, "STAT", 0) or 0,
                   "tag": _field(fields, "TAG", 0) or 0, "src": sender, "src_uid": ids.uid_for(sender),
                   "time": int(time.time())}
            _MAILBOX.setdefault(tid, []).append(msg)
            stored_ids.append(mid)
            for n in names:
                if ids.uid_for(n) == tid:
                    payload = tdf.encode(_server_message(msg, sender_identity))
                    outs.append((n, _frame(NOTIFY_MESSAGE, payload, 2)))
    first = stored_ids[0] if stored_ids else 0
    reply = sorted([("MGID", tdf.VARINT, first), ("MIDS", tdf.LIST, (tdf.VARINT, stored_ids))], key=lambda f: f[0])
    return reply, outs


def _matching(uid: int, fields):
    wanted_type = _field(fields, "TYPE", 0) or 0
    type_list = _field(fields, "TYPL")
    allowed = set(type_list[1]) if isinstance(type_list, tuple) else set()
    if wanted_type:
        allowed.add(wanted_type)
    with _LOCK:
        box = list(_MAILBOX.get(uid, []))
    return [m for m in box if not allowed or m["type"] in allowed]


def fetch_messages(name: str, fields, identity_of):
    """fetchMessages -> {MCNT} + NotifyMessage dla kazdej pasujacej wiadomosci."""
    msgs = _matching(ids.uid_for(name), fields)
    outs = [_frame(NOTIFY_MESSAGE, tdf.encode(_server_message(m, identity_of(m["src"]))), 2) for m in msgs]
    return [("MCNT", tdf.VARINT, len(msgs))], outs


def get_messages(name: str, fields, identity_of):
    """getMessages -> {MCNT, MSLT}: lista ServerMessage w odpowiedzi."""
    msgs = _matching(ids.uid_for(name), fields)
    items = [_server_message(m, identity_of(m["src"])) for m in msgs]
    return sorted([("MCNT", tdf.VARINT, len(msgs)), ("MSLT", tdf.LIST, (tdf.STRUCT, items))],
                  key=lambda f: f[0])


def _frame(command: int, payload: bytes, msg_type: int, msg_num: int = 0) -> bytes:
    return (len(payload).to_bytes(4, "big") + (0).to_bytes(2, "big") + MESSAGING_COMPONENT.to_bytes(2, "big")
            + command.to_bytes(2, "big") + msg_num.to_bytes(3, "big") + bytes([(msg_type & 7) << 5, 0, 0]) + payload)
