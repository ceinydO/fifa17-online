#!/usr/bin/env python3
"""Skanuje zakres kodu PS3 ELF w poszukiwaniu konstruktorow: instrukcji `stw rS,0(rA)`, gdzie rS ma znana stala
wartosc (z lis/addic/ori) wskazujaca na tablice deskryptorow funkcji {kod, TOC}. To wskaznik do vtable
instalowany w obiekcie. Wypisuje kazda taka tablice, adres zapisu i wybrane sloty rozwiazane na adresy kodu.

Uzycie:
    python find_vtable_stores.py EBOOT.ELF [--range 0x00D00000,0x00D09000] [--toc 0x025273D8]
                                 [--slots 14,31,39,40,41,42,43,44,45] [--minslots 8]
Bez zaleznosci zewnetrznych. Sledzenie rejestrow jest uproszczone (reset na prologu funkcji i po `bl`).
"""
import struct
import sys


def sext16(v):
    return v - 0x10000 if v & 0x8000 else v


def main():
    args = sys.argv[1:]

    def opt(name, default):
        if name in args:
            k = args.index(name)
            v = args[k + 1]
            del args[k:k + 2]
            return v
        return default

    lo, hi = [int(x, 0) for x in opt("--range", "0x00D00000,0x00D09000").split(",")]
    toc = int(opt("--toc", "0x025273D8"), 0)
    slots = [int(x, 0) for x in opt("--slots", "14,31,39,40,41,42,43,44,45").split(",") if x]
    min_slots = int(opt("--minslots", "8"), 0)
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

    def word(v):
        for _, so, sv, sz in segs:
            if sv <= v < sv + sz - 3:
                return struct.unpack(">I", data[so + v - sv: so + v - sv + 4])[0]
        return None

    def is_code(v):
        return v is not None and any(f & 1 and sv <= v < sv + sz for f, _, sv, sz in segs)

    def desc_code(w):
        if w is None or w & 3 or w < 0x10000:
            return None
        c, t = word(w), word(w + 4)
        return c if t == toc and is_code(c) else None

    found = {}    # vtable -> list of (adres zapisu)
    regs = {}
    for addr in range(lo, hi, 4):
        w = word(addr)
        if w is None:
            break
        if (w & 0xFFFF0003) == 0xF8210001 and (w & 0x8000):        # prolog funkcji
            regs = {}
            continue
        op, rt, ra, imm = w >> 26, (w >> 21) & 31, (w >> 16) & 31, w & 0xFFFF
        if op == 15:
            base = 0 if ra == 0 else regs.get(ra)
            regs[rt] = None if base is None else (base + (sext16(imm) << 16)) & 0xFFFFFFFF
        elif op in (12, 14):
            base = (0 if ra == 0 else regs.get(ra)) if op == 14 else regs.get(ra)
            regs[rt] = None if base is None else (base + sext16(imm)) & 0xFFFFFFFF
        elif op in (24, 25):
            src = regs.get(rt)
            regs[ra] = None if src is None else (src | (imm if op == 24 else imm << 16)) & 0xFFFFFFFF
        elif op == 36 and imm == 0 and regs.get(rt):
            cand = regs[rt]
            if desc_code(word(cand)) is not None:
                found.setdefault(cand, []).append(addr)
        elif op == 18 and (w & 1):
            for r in range(3, 13):
                regs.pop(r, None)

    print(f"zapisow wskaznika do vtable w zakresie 0x{lo:08X}..0x{hi:08X}: "
          f"{sum(len(v) for v in found.values())}, roznych tablic: {len(found)}")
    for vt, sites in sorted(found.items()):
        n = 0
        while desc_code(word(vt + 4 * n)) is not None and n < 200:
            n += 1
        if n < min_slots:
            continue
        in_range = sum(1 for k in range(n) if lo <= (desc_code(word(vt + 4 * k)) or 0) < hi)
        print(f"\n=== vtable 0x{vt:08X}  kolejnych slotow z deskryptorami: {n}  (w zakresie: {in_range})"
              f"  zapis w: " + ", ".join(f"0x{a:08X}" for a in sites[:4]))
        for k in slots:
            if k < n:
                c = desc_code(word(vt + 4 * k))
                print(f"    slot {k:3d} (+0x{4 * k:03X}): kod 0x{c:08X}" + ("  <== w zakresie" if lo <= c < hi else ""))
            else:
                print(f"    slot {k:3d}: poza pierwszym ciagiem ({n} slotow)")


if __name__ == "__main__":
    main()
