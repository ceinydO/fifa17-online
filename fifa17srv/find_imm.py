#!/usr/bin/env python3
"""Szuka w kodzie PS3 ELF instrukcji, ktore uzywaja zadanej stalej 16-bitowej (np. 30000 = 0x7530 ms): li/addi,
addic, ori, cmpwi, cmplwi. Do wyszukiwania limitow czasu.

Uzycie:
    python find_imm.py EBOOT.ELF --value 0x7530 [--value 0x1E ...] [--range 0x00C00000,0x00E00000] [--max 200]
Wynik: adres instrukcji, jej rodzaj i rejestr oraz funkcja (heurystycznie). Bez zaleznosci zewnetrznych.
"""
import struct
import sys


def main():
    args = sys.argv[1:]
    values, lo, hi, mx = [], 0, 0xFFFFFFFF, 200
    i = 1
    while i < len(args):
        if args[i] == "--value":
            values.append(int(args[i + 1], 0) & 0xFFFF); i += 2
        elif args[i] == "--range":
            a, b = args[i + 1].split(",")
            lo, hi = int(a, 0), int(b, 0); i += 2
        elif args[i] == "--max":
            mx = int(args[i + 1], 0); i += 2
        else:
            i += 1
    if not args or not values:
        print(__doc__)
        sys.exit(1)
    kinds = {14: "li/addi", 12: "addic", 24: "ori", 11: "cmpwi", 10: "cmplwi"}
    data = open(args[0], "rb").read()
    e_phoff = struct.unpack(">Q", data[0x20:0x28])[0]
    e_phentsize, e_phnum = struct.unpack(">HH", data[0x36:0x3A])
    rows = []
    for k in range(e_phnum):
        o = e_phoff + k * e_phentsize
        p_type, p_flags, p_off, p_va, _, p_fsz, _, _ = struct.unpack(">IIQQQQQQ", data[o:o + 56])
        if p_type != 1 or not p_fsz or not p_flags & 1:
            continue
        n = p_fsz // 4
        words = struct.unpack(">%dI" % n, data[p_off:p_off + n * 4])
        last = None
        for j, w in enumerate(words):
            addr = p_va + 4 * j
            if (w & 0xFFFF0003) == 0xF8210001 and (w & 0x8000):
                last = addr
            op = w >> 26
            if op in kinds and (w & 0xFFFF) in values and lo <= addr < hi:
                ra = (w >> 16) & 31
                if op == 14 and ra != 0:
                    kind = "addi"
                else:
                    kind = kinds[op]
                rt = (w >> 21) & 31
                rows.append((addr, kind, rt, w & 0xFFFF, last))
    print(f"trafien: {len(rows)}")
    for addr, kind, rt, v, fn in rows[:mx]:
        print(f"0x{addr:08X}  {kind:8s} r{rt:<2d} imm=0x{v:X}  funkcja ~0x{(fn or 0):08X}")


if __name__ == "__main__":
    main()
