"""Best-effort codec for the TDF payload encoding used by EA's Blaze protocol.

IMPORTANT: written from knowledge of other Blaze games, NOT yet validated against real
FIFA 17 traffic. The self-test only proves encode/decode are consistent with each other.
Treat every decode result on real captures as a hypothesis.

Field layout:  tag (3 bytes = 4 chars x 6 bits) + type (1 byte) + value
Types: 0 varint, 1 string, 2 blob, 3 struct, 4 list, 5 map, 6 union,
       7 varint-list, 8 object-type, 9 object-id, 10 float, 11 time-value
"""
from __future__ import annotations

import re
import struct
from typing import Any, List, Optional, Tuple

VARINT, STRING, BLOB, STRUCT, LIST, MAP, UNION, INTLIST, OBJTYPE, OBJID, FLOAT, TIME = range(12)
TYPE_NAMES = ["varint", "string", "blob", "struct", "list", "map", "union",
              "intlist", "objtype", "objid", "float", "time"]
UNION_UNSET = 0x7F

# A decoded field: (tag, type_id, value)
Field = Tuple[str, int, Any]


class TdfError(Exception):
    pass


# ---------------------------------------------------------------- tags
def encode_tag(tag: str) -> bytes:
    tag = tag.upper().ljust(4)[:4]
    value = 0
    for i, ch in enumerate(tag):
        c = ord(ch)
        if ch == " ":
            s = 0
        elif 0x40 < c <= 0x5F:
            s = c - 0x40
        elif 0x20 < c < 0x40:
            s = c
        else:
            raise TdfError(f"cannot encode tag character {ch!r}")
        value |= s << (18 - 6 * i)
    return value.to_bytes(3, "big")


def decode_tag(raw: bytes) -> str:
    v = int.from_bytes(raw, "big")
    chars = []
    for i in range(4):
        s = (v >> (18 - 6 * i)) & 0x3F
        if s == 0:
            chars.append(" ")
        elif s < 0x20:
            chars.append(chr(0x40 + s))
        else:
            chars.append(chr(s))
    return "".join(chars).rstrip()


# ---------------------------------------------------------------- reader
class Reader:
    def __init__(self, data: bytes, pos: int = 0):
        self.d, self.p = data, pos

    def eof(self) -> bool:
        return self.p >= len(self.d)

    def u8(self) -> int:
        if self.p >= len(self.d):
            raise TdfError("unexpected end of data")
        b = self.d[self.p]
        self.p += 1
        return b

    def take(self, n: int) -> bytes:
        if n < 0 or self.p + n > len(self.d):
            raise TdfError(f"need {n} bytes at offset {self.p}, only {len(self.d) - self.p} left")
        out = self.d[self.p : self.p + n]
        self.p += n
        return out

    def varint(self) -> int:
        first = self.u8()
        result, shift, byte = first & 0x3F, 6, first
        while byte >= 0x80:
            if shift > 70:
                raise TdfError("varint too long")
            byte = self.u8()
            result |= (byte & 0x7F) << shift
            shift += 7
        return result


def _read_value(r: Reader, t: int, depth: int = 0) -> Any:
    if depth > 32:
        raise TdfError("nesting too deep")
    if t == VARINT or t == TIME:
        return r.varint()
    if t == STRING:
        n = r.varint()
        raw = r.take(n)
        return raw[:-1].decode("utf-8", "replace") if raw.endswith(b"\x00") else raw.decode("utf-8", "replace")
    if t == BLOB:
        return r.take(r.varint())
    if t == STRUCT:
        return _read_struct(r, depth + 1)
    if t == LIST:
        sub = r.u8()
        n = r.varint()
        if n > 100000:
            raise TdfError("implausible list length")
        return (sub, [_read_value(r, sub, depth + 1) for _ in range(n)])
    if t == MAP:
        kt, vt = r.u8(), r.u8()
        n = r.varint()
        if n > 100000:
            raise TdfError("implausible map length")
        items = []
        for _ in range(n):
            k = _read_value(r, kt, depth + 1)
            items.append((k, _read_value(r, vt, depth + 1)))
        return (kt, vt, items)
    if t == UNION:
        disc = r.u8()
        if disc == UNION_UNSET:
            return (disc, None)
        return (disc, _read_field(r, depth + 1))
    if t == INTLIST:
        n = r.varint()
        if n > 100000:
            raise TdfError("implausible list length")
        return [r.varint() for _ in range(n)]
    if t == OBJTYPE:
        return (r.varint(), r.varint())
    if t == OBJID:
        return (r.varint(), r.varint(), r.varint())
    if t == FLOAT:
        return struct.unpack(">f", r.take(4))[0]
    raise TdfError(f"unknown TDF type {t}")


_PLAUSIBLE_TAG = re.compile(r"[A-Z0-9_]+")


def _read_field(r: Reader, depth: int = 0) -> Field:
    tag = decode_tag(r.take(3))
    if not _PLAUSIBLE_TAG.fullmatch(tag):
        raise TdfError(f"implausible tag {tag!r} at offset {r.p - 3}")
    t = r.u8()
    if t > TIME:
        raise TdfError(f"invalid type byte {t} for tag {tag!r} at offset {r.p - 1}")
    return (tag, t, _read_value(r, t, depth))


def _read_struct(r: Reader, depth: int) -> List[Field]:
    fields: List[Field] = []
    while True:
        if r.eof():
            raise TdfError("struct not terminated")
        if r.d[r.p] == 0:
            r.p += 1
            return fields
        fields.append(_read_field(r, depth))


def decode_partial(data: bytes, pos: int = 0) -> Tuple[List[Field], int, Optional[str]]:
    """Decode consecutive top-level fields from pos. Returns (fields, offset_reached, error)."""
    r = Reader(data, pos)
    out: List[Field] = []
    err = None
    while not r.eof():
        start = r.p
        try:
            out.append(_read_field(r))
        except TdfError as exc:
            err = f"{exc} (field starting at offset {start})"
            r.p = start
            break
    return out, r.p, err


def decode(data: bytes) -> List[Field]:
    fields, reached, err = decode_partial(data)
    if err:
        raise TdfError(err)
    return fields


# ---------------------------------------------------------------- writer
def enc_varint(v: int) -> bytes:
    if v < 0:
        v &= (1 << 64) - 1
    if v < 0x40:
        return bytes([v])
    out = bytearray([(v & 0x3F) | 0x80])
    v >>= 6
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def _enc_value(t: int, v: Any) -> bytes:
    if t == VARINT or t == TIME:
        return enc_varint(v)
    if t == STRING:
        raw = v.encode("utf-8") + b"\x00"
        return enc_varint(len(raw)) + raw
    if t == BLOB:
        return enc_varint(len(v)) + bytes(v)
    if t == STRUCT:
        return b"".join(encode_field(*f) for f in v) + b"\x00"
    if t == LIST:
        sub, items = v
        return bytes([sub]) + enc_varint(len(items)) + b"".join(_enc_value(sub, i) for i in items)
    if t == MAP:
        kt, vt, items = v
        body = b"".join(_enc_value(kt, k) + _enc_value(vt, x) for k, x in items)
        return bytes([kt, vt]) + enc_varint(len(items)) + body
    if t == UNION:
        disc, inner = v
        return bytes([disc]) if inner is None else bytes([disc]) + encode_field(*inner)
    if t == INTLIST:
        return enc_varint(len(v)) + b"".join(enc_varint(i) for i in v)
    if t == OBJTYPE:
        return b"".join(enc_varint(i) for i in v)
    if t == OBJID:
        return b"".join(enc_varint(i) for i in v)
    if t == FLOAT:
        return struct.pack(">f", v)
    raise TdfError(f"cannot encode type {t}")


def encode_field(tag: str, t: int, v: Any) -> bytes:
    return encode_tag(tag) + bytes([t]) + _enc_value(t, v)


def encode(fields: List[Field]) -> bytes:
    return b"".join(encode_field(*f) for f in fields)


# ---------------------------------------------------------------- pretty printing
def pretty(fields: List[Field], indent: int = 0) -> str:
    pad = "  " * indent
    lines = []
    for tag, t, v in fields:
        name = TYPE_NAMES[t]
        if t == STRUCT:
            lines.append(f"{pad}{tag} <struct>")
            lines.append(pretty(v, indent + 1))
        elif t == LIST:
            sub, items = v
            lines.append(f"{pad}{tag} <list of {TYPE_NAMES[sub]}> ({len(items)})")
            for item in items:
                if sub == STRUCT:
                    lines.append(f"{pad}  -")
                    lines.append(pretty(item, indent + 2))
                else:
                    lines.append(f"{pad}  - {item!r}")
        elif t == MAP:
            kt, vt, items = v
            lines.append(f"{pad}{tag} <map {TYPE_NAMES[kt]}->{TYPE_NAMES[vt]}> ({len(items)})")
            for k, x in items:
                lines.append(f"{pad}  {k!r}: {x!r}" if vt != STRUCT else f"{pad}  {k!r}:\n{pretty(x, indent + 2)}")
        elif t == UNION:
            disc, inner = v
            lines.append(f"{pad}{tag} <union disc={disc}>")
            if inner is not None:
                lines.append(pretty([inner], indent + 1))
        else:
            shown = v.hex() if t == BLOB else repr(v)
            lines.append(f"{pad}{tag} <{name}> {shown}")
    return "\n".join(x for x in lines if x != "")
