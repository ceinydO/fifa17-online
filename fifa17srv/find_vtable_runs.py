#!/usr/bin/env python3
"""Szuka tablic wirtualnych (vtable) w PS3 ELF: ciagow slow, z ktorych kazde wskazuje na deskryptor funkcji
{adres kodu, TOC}. Dla kazdego ciagu liczy, ile wpisow trafia w zadany zakres kodu (np. plik zrodlowy maszyny
stanow logowania) i rozwiazuje wybrane sloty na adresy kodu.

Uzycie:
    python find_vtable_runs.py EBOOT.ELF [--toc 0x025273D8] [--min 20] [--gap 3] [--range 0x00D00000,0x00D09000]
                               [--minhits 1] [--slots 14,31,39,40,41,42,43,44,45]
      --min   minimalna dlugosc ciagu (w slowach, wliczajac dozwolone luki)
      --gap   ile kolejnych slow, ktore NIE sa deskryptorami (np. zera), tolerowac wewnatrz ciagu
Bez zaleznosci zewnetrznych. Wynik: kandydaci na vtable, posortowani malejaco po liczbie trafien w zakresie.
Gdy nic nie spelnia --minhits, wypisuje 10 najdluzszych ciagow, zeby bylo widac, co w ogole jest w danych.
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
            return v
        return default

    toc = int(opt("--toc", "0x025273D8"), 0)
    min_len = int(opt("--min", "20"), 0)
    max_gap = int(opt("--gap", "3"), 0)
    lo, hi = [int(x, 0) for x in opt("--range", "0x00D00000,0x00D09000").split(",")]
    min_hits = int(opt("--minhits", "1"), 0)
    slots = [int(x, 0) for x in opt("--slots", "14,31,39,40,41,42,43,44,45").split(",") if x]
    if not args:
        print(__doc__)
        sys.exit(1)

    data = open(args[0], "rb").read()
    e_phoff = struct.unpack(">Q", data[0x20:0x28])[0]
    e_phentsize, e_phnum = struct.unpack(">HH", data[0x36:0x3A])
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags, p_off, p_va, _, p_fsz, _, _ = struct.unpack(">IIQQQQQQ", data[o:o + 56])
        if p_type == 1 and p_fsz:
            segs.append((p_flags, p_off, p_va, p_fsz))
    text = [(sv, sz) for f, _, sv, sz in segs if f & 1]
    dat = [(so, sv, sz) for f, so, sv, sz in segs if not f & 1]

    def word(v):
        for _, so, sv, sz in segs:
            if sv <= v < sv + sz - 3:
                return struct.unpack(">I", data[so + v - sv: so + v - sv + 4])[0]
        return None

    def is_code(v):
        return v is not None and any(sv <= v < sv + sz for sv, sz in text)

    desc_cache = {}

    def descriptor_code(w):
        """Jesli w wskazuje na {kod, toc}, zwraca kod, inaczej None."""
        if w in desc_cache:
            return desc_cache[w]
        res = None
        if w & 3 == 0 and w > 0x10000:
            c, t = word(w), word(w + 4)
            if t == toc and is_code(c):
                res = c
        desc_cache[w] = res
        return res

    runs = []
    for so, sv, sz in dat:
        n = sz // 4
        words = struct.unpack(">%dI" % n, data[so:so + n * 4])
        start, last_ok, gap = None, None, 0
        for i in range(n + 1):
            ok = i < n and descriptor_code(words[i]) is not None
            if ok:
                if start is None:
                    start = i
                last_ok, gap = i, 0
            elif start is not None:
                gap += 1
                if gap > max_gap or i >= n:
                    ln = last_ok - start + 1
                    if ln >= min_len:
                        runs.append((sv + 4 * start, ln))
                    start, last_ok, gap = None, None, 0

    rows = []
    for addr, ln in runs:
        codes = [descriptor_code(word(addr + 4 * k)) for k in range(ln)]     # None = luka
        hits = sum(1 for c in codes if c is not None and lo <= c < hi)
        if hits >= min_hits:
            rows.append((hits, addr, ln, codes))
    rows.sort(reverse=True)
    print(f"ciagow >= {min_len} slow (luki do {max_gap}): {len(runs)}, z >= {min_hits} trafieniami w zakresie "
          f"0x{lo:08X}..0x{hi:08X}: {len(rows)}")
    if not rows:
        print("\nNajdluzsze znalezione ciagi (bez trafien w zakresie):")
        for addr, ln in sorted(runs, key=lambda r: -r[1])[:10]:
            print(f"    0x{addr:08X}  dlugosc {ln}")
    for hits, addr, ln, codes in rows[:8]:
        print(f"\n=== vtable? 0x{addr:08X}  dlugosc {ln} slow, trafien w zakresie: {hits}")
        for k in slots:
            if k < ln:
                c = codes[k]
                if c is None:
                    print(f"    slot {k:3d} (+0x{4 * k:03X}): (luka/zero)")
                    continue
                mark = "  <== w zakresie" if lo <= c < hi else ""
                print(f"    slot {k:3d} (+0x{4 * k:03X}): kod 0x{c:08X}{mark}")
            else:
                print(f"    slot {k:3d}: poza ciagiem")


if __name__ == "__main__":
    main()
