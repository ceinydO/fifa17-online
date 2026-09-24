#!/usr/bin/env python3
"""Zrzut slow z pamieci danych PS3 ELF (ELF64 BE) z adnotacjami: napisy, wskazniki, tagi TDF.

Uzycie:
    python dump_words.py EBOOT.ELF ADRES[,ADRES2,...] [--count N] [--follow D] [--per M]
      --count N   ile slow zrzucic spod kazdego adresu (domyslnie 40)
      --follow D  jak gleboko isc za wskaznikami do danych (domyslnie 1; 0 = wcale)
      --per M     ile slow pokazac spod wskaznika przy --follow (domyslnie 10)
Adnotacje:  "tekst" = wskaznik na napis ASCII;  code 0x.. = wskaznik na kod;  -> 0x.. = wskaznik na dane;
            <TAG XXXX typ n> = slowo wyglada jak tag TDF (kod 24-bit + typ).
"""
import struct
import sys


def main():
    args = sys.argv[1:]

    def opt(name, default):
        if name in args:
            k = args.index(name)
            v = args[k + 1]
            del args[k:k + 2]
            return int(v, 0)
        return default

    count = opt("--count", 40)
    follow = opt("--follow", 1)
    per = opt("--per", 10)
    if len(args) < 2:
        print(__doc__)
        sys.exit(1)
    path = args[0]
    addrs = [int(a, 0) for a in args[1].split(",")]

    data = open(path, "rb").read()
    e_phoff = struct.unpack(">Q", data[0x20:0x28])[0]
    e_phentsize, e_phnum = struct.unpack(">HH", data[0x36:0x3A])
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags, p_off, p_va, _, p_fsz, _, _ = struct.unpack(">IIQQQQQQ", data[o:o + 56])
        if p_type == 1 and p_fsz:
            segs.append((p_flags, p_off, p_va, p_fsz))

    def seg_of(v):
        for f, so, sv, sz in segs:
            if sv <= v < sv + sz:
                return f, so, sv, sz
        return None

    def word(v):
        s = seg_of(v)
        if not s or v + 4 > s[2] + s[3]:
            return None
        _, so, sv, _ = s
        return struct.unpack(">I", data[so + v - sv: so + v - sv + 4])[0]

    def text_at(v):
        s = seg_of(v)
        if not s:
            return None
        _, so, sv, _ = s
        t = data[so + v - sv: so + v - sv + 80].split(b"\0", 1)[0]
        if len(t) >= 2 and all(0x20 <= c < 0x7F for c in t):
            return t.decode("ascii")
        return None

    def tag_text(w):
        t, typ = w >> 8, w & 0xFF
        if typ > 0xB or t < 0x100000:
            return None
        chars = [((t >> (18 - 6 * i)) & 0x3F) + 0x20 for i in range(4)]
        s = "".join(chr(c) for c in chars)
        if s[0].isalpha() and s[0].isupper() and all(ch.isupper() or ch.isdigit() or ch == " " for ch in s):
            return f"<TAG {s} typ {typ}>"
        return None

    def note(w):
        if w is None:
            return ""
        tt = tag_text(w)
        if tt:
            return "  " + tt
        s = seg_of(w) if w > 0x10000 else None
        if s:
            if s[0] & 1:
                return f"  code 0x{w:08X}"
            tx = text_at(w)
            return f'  "{tx}"' if tx else f"  -> 0x{w:08X}"
        return f"  ({w})" if w < 0x10000 else ""

    seen = set()

    def dump(a, n, indent, depth):
        for i in range(n):
            w = word(a + 4 * i)
            if w is None:
                break
            print(f"{indent}0x{a + 4 * i:08X}: {w:08X}{note(w)}")
            if depth < follow and w > 0x10000:
                s = seg_of(w)
                if s and not (s[0] & 1) and not text_at(w) and w not in seen:
                    seen.add(w)
                    print(f"{indent}    [{w:08X}]")
                    dump(w, per, indent + "      ", depth + 1)

    for a in addrs:
        print(f"\n=== 0x{a:08X}")
        seen.add(a)
        dump(a, count, "  ", 0)


if __name__ == "__main__":
    main()
