#!/usr/bin/env python3
"""Znajduje miejsca w kodzie PS3 ELF, ktore wolaja metode wirtualna o zadanym numerze slotu.

W tym ABI wywolanie wirtualne wyglada tak:
    lwz rA, 0(rObj)         ; vtable
    lwz rB, OFFSET(rA)      ; wpis slotu (OFFSET = 4 * slot)  -> wskaznik na deskryptor
    lwz rC, 0(rB)           ; kod
    mtctr rC ; bdnzctrl
Skrypt szuka trojki `lwz rB,OFFSET(rA)` -> `lwz rC,0(rB)` -> `mtctr rC` w niewielkim oknie i wypisuje
adres, funkcje (heurystycznie) i dwie instrukcje przed (zwykle zaladowanie vtable / obiektu).

Uzycie:
    python find_vcalls.py EBOOT.ELF --slot 10 [--range 0x00D00000,0x00D0C000] [--window 4]
Mozna podac kilka slotow: --slot 10 --slot 30
Bez zaleznosci zewnetrznych.
"""
import struct
import sys


def main():
    args = sys.argv[1:]
    slots = []
    lo, hi, window = 0x00D00000, 0x00D0C000, 4
    i = 1
    while i < len(args):
        if args[i] == "--slot":
            slots.append(int(args[i + 1], 0)); i += 2
        elif args[i] == "--range":
            a, b = args[i + 1].split(",")
            lo, hi = int(a, 0), int(b, 0); i += 2
        elif args[i] == "--window":
            window = int(args[i + 1], 0); i += 2
        else:
            i += 1
    if not args or not slots:
        print(__doc__)
        sys.exit(1)
    data = open(args[0], "rb").read()
    e_phoff = struct.unpack(">Q", data[0x20:0x28])[0]
    e_phentsize, e_phnum = struct.unpack(">HH", data[0x36:0x3A])
    segs = []
    for k in range(e_phnum):
        o = e_phoff + k * e_phentsize
        p_type, p_flags, p_off, p_va, _, p_fsz, _, _ = struct.unpack(">IIQQQQQQ", data[o:o + 56])
        if p_type == 1 and p_fsz and p_flags & 1:
            segs.append((p_off, p_va, p_fsz))

    def word(v):
        for so, sv, sz in segs:
            if sv <= v < sv + sz - 3:
                return struct.unpack(">I", data[so + v - sv: so + v - sv + 4])[0]
        return None

    def prologue(w):
        return w is not None and (w & 0xFFFF0003) == 0xF8210001 and bool(w & 0x8000)

    offsets = {4 * s: s for s in slots}
    hits = []
    for addr in range(lo, hi, 4):
        w = word(addr)
        if w is None:
            break
        if (w >> 26) != 32:                       # lwz
            continue
        rt, ra, d = (w >> 21) & 31, (w >> 16) & 31, w & 0xFFFF
        if d not in offsets or ra in (1, 2):      # r1 = stos, r2 = TOC: to nie jest vtable
            continue
        # w oknie: lwz rC,0(rt) ... mtctr rC
        found = False
        for j in range(1, window + 1):
            w2 = word(addr + 4 * j)
            if w2 is None:
                break
            if (w2 >> 26) == 32 and ((w2 >> 16) & 31) == rt and (w2 & 0xFFFF) == 0:
                rc = (w2 >> 21) & 31
                for k in range(1, window + 1):
                    w3 = word(addr + 4 * (j + k))
                    if w3 is not None and (w3 & 0xFC1FFFFF) == 0x7C0903A6 and ((w3 >> 21) & 31) == rc:
                        found = True
                        break
                break
        if found:
            hits.append((addr, offsets[d]))
    print(f"wywolan wirtualnych slotow {sorted(slots)} w zakresie 0x{lo:08X}..0x{hi:08X}: {len(hits)}")
    for addr, s in hits:
        f = addr
        while f > lo and not prologue(word(f)):
            f -= 4
        print(f"  slot {s:3d}  wywolanie 0x{addr:08X}  funkcja ~0x{f:08X}")


if __name__ == "__main__":
    main()
