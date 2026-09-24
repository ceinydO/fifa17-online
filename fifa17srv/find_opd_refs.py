#!/usr/bin/env python3
"""Dla podanych adresow kodu (wejsc funkcji) znajduje ich deskryptory {kod, TOC} w danych, a potem wszystkie
odwolania do tych deskryptorow: sloty vtable / wskazniki metod (4-bajtowe slowa w danych) oraz kod, ktory
ladowal adres deskryptora (para lis + addic/addi).

Uzycie:
    python find_opd_refs.py EBOOT.ELF --toc 0x025273D8 --code 0x00D041EC --code 0x00D02F64 ...
Wynik dla kazdego deskryptora: adres, potem lista miejsc w danych (z sasiednimi slowami) i w kodzie.
Bez zaleznosci zewnetrznych.
"""
import struct
import sys


def sext16(v):
    return v - 0x10000 if v & 0x8000 else v


def main():
    args = sys.argv[1:]
    toc, codes = 0x025273D8, []
    i = 1
    while i < len(args):
        if args[i] == "--toc":
            toc = int(args[i + 1], 0); i += 2
        elif args[i] == "--code":
            codes.append(int(args[i + 1], 0)); i += 2
        else:
            i += 1
    if not args or not codes:
        print(__doc__)
        sys.exit(1)
    data = open(args[0], "rb").read()
    e_phoff = struct.unpack(">Q", data[0x20:0x28])[0]
    e_phentsize, e_phnum = struct.unpack(">HH", data[0x36:0x3A])
    segs = []
    for k in range(e_phnum):
        o = e_phoff + k * e_phentsize
        p_type, p_flags, p_off, p_va, _, p_fsz, _, _ = struct.unpack(">IIQQQQQQ", data[o:o + 56])
        if p_type == 1 and p_fsz:
            segs.append((p_flags, p_off, p_va, p_fsz))

    def word(v):
        for _, so, sv, sz in segs:
            if sv <= v < sv + sz - 3:
                return struct.unpack(">I", data[so + v - sv: so + v - sv + 4])[0]
        return None

    def find_words(value):
        pat = struct.pack(">I", value)
        out = []
        for f, so, sv, sz in segs:
            blob = data[so:so + sz]
            p = 0
            while True:
                p = blob.find(pat, p)
                if p < 0:
                    break
                if p % 4 == 0:
                    out.append(sv + p)
                p += 4
        return out

    # kod: pary lis+addic/addi
    code_words = []
    for f, so, sv, sz in segs:
        if f & 1:
            n = sz // 4
            code_words.append((sv, struct.unpack(">%dI" % n, data[so:so + n * 4])))

    def code_refs(value):
        res = []
        for sv, words in code_words:
            n = len(words)
            for i, w in enumerate(words):
                if (w >> 26) != 15 or ((w >> 16) & 31) != 0:
                    continue
                rt, hi = (w >> 21) & 31, sext16(w & 0xFFFF)
                for j in range(1, 41):
                    if i + j >= n:
                        break
                    w2 = words[i + j]
                    if (w2 >> 26) in (12, 14) and ((w2 >> 16) & 31) == rt:
                        if (((hi << 16) + sext16(w2 & 0xFFFF)) & 0xFFFFFFFF) == value:
                            res.append(sv + 4 * (i + j))
                        break
        return res

    for c in codes:
        print(f"\n=== kod 0x{c:08X}")
        descs = [a for a in find_words(c) if word(a + 4) == toc]
        if not descs:
            print("    brak deskryptora {kod, TOC} w danych")
            continue
        for d in descs:
            print(f"  deskryptor @0x{d:08X}")
            for h in find_words(d)[:8]:
                near = " ".join(f"{word(h + 4 * k):08X}" if word(h + 4 * k) is not None else "--------"
                                for k in range(-2, 3))
                print(f"    dane  0x{h:08X}: [.. {near} ..]")
            for r in code_refs(d)[:8]:
                print(f"    kod   0x{r:08X}: laduje adres deskryptora")


if __name__ == "__main__":
    main()
