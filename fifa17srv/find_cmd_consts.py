#!/usr/bin/env python3
"""Dla kazdego napisu z zadanego zakresu adresow znajduje miejsca w kodzie, ktore ladowaly jego adres
(para lis + addic/addi), i wypisuje stale calkowite (`li rX,imm`) oraz zapisy stw/sth/stb w poblizu.
W kodzie definicji komponentow Blaze nazwa komendy jest zapisywana obok jej identyfikatora, wiec z tego
wychodzi tabela  nazwa -> id.

Uzycie:
    python find_cmd_consts.py EBOOT.ELF --range 0x01FA3E00,0x01FA4200 [--minlen 3] [--near 14]
      --near  ile instrukcji przed/po wczytaniu adresu napisu brac pod uwage (domyslnie 14)
Bez zaleznosci zewnetrznych.
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

    rng = opt("--range", "")
    minlen = int(opt("--minlen", "3"), 0)
    near = int(opt("--near", "14"), 0)
    if not args or not rng:
        print(__doc__)
        sys.exit(1)
    lo, hi = (int(x, 0) for x in rng.split(","))
    data = open(args[0], "rb").read()
    e_phoff = struct.unpack(">Q", data[0x20:0x28])[0]
    e_phentsize, e_phnum = struct.unpack(">HH", data[0x36:0x3A])
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags, p_off, p_va, _, p_fsz, _, _ = struct.unpack(">IIQQQQQQ", data[o:o + 56])
        if p_type == 1 and p_fsz:
            segs.append((p_flags, p_off, p_va, p_fsz))

    # 1) napisy w zakresie
    strings = {}
    for f, so, sv, sz in segs:
        if not (sv <= lo < sv + sz):        # napisy moga lezec takze w segmencie wykonywalnym (rodata razem z tekstem)
            continue
        a = max(lo, sv)
        end = min(hi, sv + sz)
        blob = data[so + a - sv: so + end - sv]
        i = 0
        while i < len(blob):
            j = blob.find(b"\0", i)
            if j < 0:
                break
            t = blob[i:j]
            if len(t) >= minlen and all(0x20 <= c < 0x7F for c in t) and (i == 0 or blob[i - 1] == 0):
                strings[a + i] = t.decode("ascii")
            i = j + 1
    print(f"napisow w zakresie 0x{lo:08X}..0x{hi:08X}: {len(strings)}")

    # 2) referencje w kodzie
    refs = {}    # adres napisu -> lista (adres pary, adres uzupelnienia, indeks segmentu kodu, indeks slowa)
    code = []
    for f, so, sv, sz in segs:
        if f & 1:
            n = sz // 4
            code.append((sv, struct.unpack(">%dI" % n, data[so:so + n * 4])))
    for ci, (sv, words) in enumerate(code):
        n = len(words)
        for i, w in enumerate(words):
            if (w >> 26) != 15 or ((w >> 16) & 31) != 0:
                continue
            rt, hi16 = (w >> 21) & 31, sext16(w & 0xFFFF)
            for j in range(1, 41):
                if i + j >= n:
                    break
                w2 = words[i + j]
                if (w2 >> 26) in (12, 14) and ((w2 >> 16) & 31) == rt:
                    val = ((hi16 << 16) + sext16(w2 & 0xFFFF)) & 0xFFFFFFFF
                    if val in strings:
                        refs.setdefault(val, []).append((ci, i + j))
                    break

    # 3) wypisz stale w poblizu
    for addr in sorted(strings):
        for ci, k in refs.get(addr, []):
            sv, words = code[ci]
            lis_ = []
            for d in range(-near, near + 1):
                if not 0 <= k + d < len(words):
                    continue
                w = words[k + d]
                op, rt, ra, imm = w >> 26, (w >> 21) & 31, (w >> 16) & 31, w & 0xFFFF
                if op == 14 and ra == 0:
                    lis_.append(f"li r{rt}={sext16(imm)} (0x{sext16(imm) & 0xFFFF:X})")
                elif op in (36, 44, 38):
                    lis_.append(f"{ {36: 'stw', 44: 'sth', 38: 'stb'}[op] } r{rt},0x{imm:X}(r{ra})")
            print(f"\n{strings[addr]!r} @0x{addr:08X}  kod 0x{sv + 4 * k:08X}: " + "; ".join(lis_))


if __name__ == "__main__":
    main()
