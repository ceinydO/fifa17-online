#!/usr/bin/env python3
"""Znajduje w PS3 ELF wszystkie zapisy do pola struktury o zadanym offsecie: stb / sth / stw rS, DISP(rA).
Jesli tuz przed zapisem rejestr rS dostaje stala (`li rS,imm`), pokazuje ja -- widac wtedy, gdzie pole jest
ustawiane na 1 lub 0.

Uzycie:
    python find_byte_stores.py EBOOT.ELF --disp 0xBEC [--width b,h,w] [--range 0x00000000,0x01F00000]
      --width  ktore zapisy: b (stb), h (sth), w (stw); domyslnie b,h,w
      --range  ogranicz do zakresu kodu
Bez zaleznosci zewnetrznych. Wynik: adres zapisu, funkcja (heurystycznie), instrukcja i stala, jesli znana.
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

    disp = int(opt("--disp", "0"), 0)
    widths = set(opt("--width", "b,h,w").split(","))
    rng = opt("--range", "")
    lo, hi = (int(x, 0) for x in rng.split(",")) if rng else (0, 0xFFFFFFFF)
    if not args or not disp:
        print(__doc__)
        sys.exit(1)
    ops = {}
    if "b" in widths:
        ops[38] = "stb"
    if "h" in widths:
        ops[44] = "sth"
    if "w" in widths:
        ops[36] = "stw"

    data = open(args[0], "rb").read()
    e_phoff = struct.unpack(">Q", data[0x20:0x28])[0]
    e_phentsize, e_phnum = struct.unpack(">HH", data[0x36:0x3A])
    total = 0
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags, p_off, p_va, _, p_fsz, _, _ = struct.unpack(">IIQQQQQQ", data[o:o + 56])
        if p_type != 1 or not p_fsz or not p_flags & 1:
            continue
        n = p_fsz // 4
        words = struct.unpack(">%dI" % n, data[p_off:p_off + n * 4])
        last_prologue = None
        for k, w in enumerate(words):
            addr = p_va + 4 * k
            if (w & 0xFFFF0003) == 0xF8210001 and (w & 0x8000):
                last_prologue = addr
            op = w >> 26
            if op not in ops or (w & 0xFFFF) != (disp & 0xFFFF) or not lo <= addr < hi:
                continue
            rs, ra = (w >> 21) & 31, (w >> 16) & 31
            const = None
            for j in range(1, 9):
                if k - j < 0:
                    break
                p = words[k - j]
                if (p >> 26) == 14 and ((p >> 16) & 31) == 0 and ((p >> 21) & 31) == rs:   # li rS,imm
                    const = sext16(p & 0xFFFF)
                    break
                if ((p >> 21) & 31) == rs and (p >> 26) in (32, 34, 40, 42, 31, 24, 25, 12, 15):
                    break                                                                    # rS przeliczone inaczej
            total += 1
            cs = f"  stala={const}" if const is not None else ""
            print(f"0x{addr:08X}  funkcja ~0x{(last_prologue or 0):08X}  {ops[op]} r{rs}, 0x{disp:X}(r{ra}){cs}")
    print(f"\nrazem zapisow: {total}")


if __name__ == "__main__":
    main()
