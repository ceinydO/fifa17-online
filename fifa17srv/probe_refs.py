#!/usr/bin/env python3
"""Lista WSZYSTKICH odwolan, ktore trafiaja w okno wokol adresu/stringu w PS3 ELF (ELF64 BE).

find_str_refs.py szuka odwolan do DOKLADNEGO adresu stringa. Jesli kompilator adresuje
stringi jako "baza puli + offset", takie odwolanie nie trafi w dokladny adres. Ten skrypt
pokazuje kazde odwolanie, ktore laduje sie gdziekolwiek w oknie [cel-R, cel+R].

Uzycie:
    python probe_refs.py EBOOT.ELF 0x025273D8 <cel> [promien_hex]
gdzie <cel> to adres (0x01FB0DC0) albo nazwa stringa (LoginStateMachineConsole).
Domyslny promien: 0x400.

Sprawdza:
  A) para w kodzie:  lis/addis rX,0 ,hi ; addi/ori/load ..,lo   (adres bezwzgledny)
  B) para w kodzie:  addis rX,r2,hi ; addi/load ..,lo           (adres wzgledem TOC)
  C) 4-bajtowe wskazniki w danych, ktore wskazuja w okno, oraz kod ladujacy taki
     wskaznik:  lwz rX,off(r2)   albo   addis rX,r2,hi ; lwz rY,lo(rX)
Bez zaleznosci zewnetrznych.
"""
import struct
import sys

WINDOW_INSNS = 400
MAX_LINES = 300


def sext16(v):
    return v - 0x10000 if v & 0x8000 else v


def redefines(w, reg):
    """Czy instrukcja nadpisuje rejestr reg (przyblizenie, wystarczajace do ucinania fałszywych trafien)."""
    op = w >> 26
    rt, ra = (w >> 21) & 31, (w >> 16) & 31
    if op in (12, 13, 14, 15, 32, 33, 34, 35, 40, 41, 42, 43, 46, 58):
        return rt == reg
    if op in (20, 21, 22, 23, 24, 25, 26, 27, 28, 29):
        return ra == reg
    if op == 31 and ((w >> 1) & 0x3FF) == 444:              # or / mr
        return ra == reg
    return False


def live_window(words, i, reg, limit):
    """Kolejne (j, slowo) po indeksie i, dopoki rejestr reg zyje: konczy sie na nadpisaniu reg,
    na bl (dla rejestrow ulotnych r3-r12), na blr i na prologu nastepnej funkcji."""
    n = len(words)
    for j in range(1, limit + 1):
        if i + j >= n:
            return
        w = words[i + j]
        if w == 0x4E800020 or (w & 0xFFFF0003) == 0xF8210001:      # blr / stdu r1,-N(r1)
            return
        yield j, w
        if redefines(w, reg):
            return
        if (w >> 26) == 18 and (w & 1) and 3 <= reg <= 12:         # bl niszczy r3-r12
            return


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)
    path, toc, target = sys.argv[1], int(sys.argv[2], 0), sys.argv[3]
    radius = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x400
    data = open(path, "rb").read()

    e_phoff = struct.unpack(">Q", data[0x20:0x28])[0]
    e_phentsize, e_phnum = struct.unpack(">HH", data[0x36:0x3A])
    segs = []  # (flags, off, vaddr, size)
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags, p_off, p_va, _, p_fsz, _, _ = struct.unpack(">IIQQQQQQ", data[o:o + 56])
        if p_type == 1 and p_fsz:
            segs.append((p_flags, p_off, p_va, p_fsz))

    def to_vaddr(off):
        for _, so, sv, sz in segs:
            if so <= off < so + sz:
                return sv + off - so
        return None

    if target.lower().startswith("0x"):
        center = int(target, 0)
    else:
        pos = data.find(b"\0" + target.encode() + b"\0")
        if pos < 0:
            print(f"nie znaleziono stringa {target!r}")
            sys.exit(1)
        center = to_vaddr(pos + 1)
    lo_w, hi_w = center - radius, center + radius
    print(f"okno: 0x{lo_w:08X} .. 0x{hi_w:08X}  (srodek 0x{center:08X})")

    def inside(a):
        return lo_w <= (a & 0xFFFFFFFF) <= hi_w

    # C1) wskazniki w danych
    ptr_locs = {}   # vaddr komorki -> wartosc
    for flags, so, sv, sz in segs:
        if flags & 1:
            continue
        n = sz // 4
        for i, w in enumerate(struct.unpack(">%dI" % n, data[so:so + n * 4])):
            if lo_w <= w <= hi_w:
                ptr_locs[sv + 4 * i] = w
    print(f"\n[dane] {len(ptr_locs)} wskaznik(ow) 4B w oknie:")
    for loc, val in sorted(ptr_locs.items())[:60]:
        print(f"  komorka 0x{loc:08X} -> 0x{val:08X}  (cel{val - center:+#x})")

    toc_short = {}
    for loc in ptr_locs:
        off = loc - toc
        if -0x8000 <= off < 0x8000:
            toc_short[off & 0xFFFF] = loc

    lines = []
    for flags, so, sv, sz in segs:
        if not flags & 1:
            continue
        n = sz // 4
        words = struct.unpack(">%dI" % n, data[so:so + n * 4])
        for i, w in enumerate(words):
            op = w >> 26
            here = sv + 4 * i
            if op == 32 and ((w >> 16) & 31) == 2 and (w & 0xFFFF) in toc_short:
                loc = toc_short[w & 0xFFFF]
                lines.append((here, f"C  lwz r{(w >> 21) & 31},off(r2) laduje wskaznik z 0x{loc:08X}"
                                    f" -> 0x{ptr_locs[loc]:08X}"))
            if op != 15:
                continue
            ra, rt, hi = (w >> 16) & 31, (w >> 21) & 31, w & 0xFFFF
            if ra not in (0, 2):
                continue
            for j, w2 in live_window(words, i, rt, WINDOW_INSNS):
                op2, ra2, rs2, imm = w2 >> 26, (w2 >> 16) & 31, (w2 >> 21) & 31, w2 & 0xFFFF
                base = 0 if ra == 0 else toc
                if op2 in (12, 14) and ra2 == rt:                # addi / addic
                    val = base + (sext16(hi) << 16) + sext16(imm)
                    kind = "addi"
                elif op2 == 24 and rs2 == rt and ra == 0:        # ori (tylko z lis)
                    val = (hi << 16) | imm
                    kind = "ori"
                elif 32 <= op2 < 56 and ra2 == rt:               # load/store z offsetem
                    val = base + (sext16(hi) << 16) + sext16(imm)
                    kind = f"op{op2}"
                else:
                    continue
                val &= 0xFFFFFFFF
                tag = "A abs" if ra == 0 else "B TOC"
                if inside(val):
                    lines.append((here, f"{tag} {kind:5s} -> 0x{val:08X} (cel{val - center:+#x})"))
                elif kind == "op32" and ra == 2 and val in ptr_locs:
                    lines.append((here, f"C  addis+lwz laduje wskaznik z 0x{val:08X}"
                                        f" -> 0x{ptr_locs[val]:08X}"))
                break
    lines.sort()
    print(f"\n[kod] {len(lines)} odwolanie(a):")
    for addr, text in lines[:MAX_LINES]:
        print(f"  0x{addr:08X}: {text}")
    if len(lines) > MAX_LINES:
        print(f"  ... (obcieto, jeszcze {len(lines) - MAX_LINES})")


if __name__ == "__main__":
    main()
