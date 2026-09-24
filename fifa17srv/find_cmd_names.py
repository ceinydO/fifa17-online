#!/usr/bin/env python3
"""Szuka w PS3 ELF napisow z nazwami komend Blaze (np. login, logout) i wypisuje slowa otaczajace kazdy wskaznik
do takiego napisu w danych -- w tabelach komponentow obok nazwy zwykle stoi identyfikator komendy.

Uzycie:
    python find_cmd_names.py EBOOT.ELF nazwa1 nazwa2 ... [--before 0x20] [--after 0x30]
Kazda nazwa musi byc calym napisem zakonczonym bajtem 0 (i poprzedzonym bajtem 0).
Bez zaleznosci zewnetrznych.
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

    before, after = opt("--before", 0x20), opt("--after", 0x30)
    if len(args) < 2:
        print(__doc__)
        sys.exit(1)
    path, names = args[0], args[1:]
    data = open(path, "rb").read()
    e_phoff = struct.unpack(">Q", data[0x20:0x28])[0]
    e_phentsize, e_phnum = struct.unpack(">HH", data[0x36:0x3A])
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags, p_off, p_va, _, p_fsz, _, _ = struct.unpack(">IIQQQQQQ", data[o:o + 56])
        if p_type == 1 and p_fsz:
            segs.append((p_flags, p_off, p_va, p_fsz))

    def word(v):
        for _, so, sv, sz in segs:
            if sv <= v < sv + sz - 3:
                return struct.unpack(">I", data[so + v - sv: so + v - sv + 4])[0]
        return None

    def cstr(v):
        for _, so, sv, sz in segs:
            if sv <= v < sv + sz:
                t = data[so + v - sv: so + v - sv + 60].split(b"\0", 1)[0]
                if 2 <= len(t) and all(0x20 <= c < 0x7F for c in t):
                    return t.decode("ascii")
        return None

    def vaddr_of(off):
        for _, so, sv, sz in segs:
            if so <= off < so + sz:
                return sv + off - so
        return None

    for nm in names:
        pat = b"\0" + nm.encode() + b"\0"
        pos, addrs = 0, []
        while True:
            pos = data.find(pat, pos)
            if pos < 0:
                break
            va = vaddr_of(pos + 1)
            if va is not None:
                addrs.append(va)
            pos += 1
        if not addrs:
            print(f"\n=== {nm}: brak napisu")
            continue
        for a in addrs:
            print(f"\n=== {nm}  napis @ 0x{a:08X}")
            ptr = struct.pack(">I", a)
            hits = []
            for f, so, sv, sz in segs:
                if f & 1:
                    continue
                p = 0
                blob = data[so:so + sz]
                while True:
                    p = blob.find(ptr, p)
                    if p < 0:
                        break
                    if p % 4 == 0:
                        hits.append(sv + p)
                    p += 4
            if not hits:
                print("    (brak wskaznikow w danych)")
            for h in hits[:6]:
                print(f"  wskaznik w 0x{h:08X}:")
                for x in range(h - before, h + after, 4):
                    w = word(x)
                    if w is None:
                        continue
                    t = cstr(w) if w > 0x10000 else None
                    note = f'  "{t}"' if t else (f"  ({w})" if w < 0x10000 else "")
                    mark = "  <==" if x == h else ""
                    print(f"    0x{x:08X}: {w:08X}{note}{mark}")


if __name__ == "__main__":
    main()
