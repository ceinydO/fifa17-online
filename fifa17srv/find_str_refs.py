#!/usr/bin/env python3
"""Find references to strings in a PS3 PPU ELF (ELF64, big-endian).

Usage:
    python find_str_refs.py [-w OKNO] EBOOT.ELF 0x025273D8 nazwa1 nazwa2 ...
    -w OKNO  ile instrukcji za lis/addis szukac drugiej polowki adresu (domyslnie 400,
             bo kompilator czesto trzyma `lis` wiele instrukcji przed uzyciem)

Checks, for every string that starts right after a NUL byte:
  1. absolute:      lis rX,hi ; addi/ADDIC/ori/load rY,lo(rX)    (RA = 0)   [ten kompilator uzywa addic!]
  2. TOC-relative:  addis rX,r2,hi ; addi/addic/load rY,lo(rX)     (RA = 2)
  3. raw 4-byte pointers to the string in any segment, and then references
     to that pointer: lwz rX,off(r2)  or  addis rX,r2,hi ; lwz rY,lo(rX)
  4. li/ori + oris:  oris rX,rS,hi ; ori rY,rX,lo   (albo odwrotnie)
No external dependencies.
"""
import struct
import sys

WINDOW = 400  # ile instrukcji po addis/lis szukamy dopelnienia (zmienia -w)


def split(v):
    """Split a 32-bit value into (hi, lo) for addis+addi (lo is signed)."""
    v &= 0xFFFFFFFF
    lo = v & 0xFFFF
    hi = ((v >> 16) + (1 if lo & 0x8000 else 0)) & 0xFFFF
    return hi, lo


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
    global WINDOW
    argv = sys.argv[1:]
    if len(argv) >= 2 and argv[0] == "-w":
        WINDOW = int(argv[1])
        argv = argv[2:]
    if len(argv) < 3:
        print(__doc__)
        sys.exit(1)
    path, toc, names = argv[0], int(argv[1], 0), argv[2:]
    data = open(path, "rb").read()

    e_phoff = struct.unpack(">Q", data[0x20:0x28])[0]
    e_phentsize, e_phnum = struct.unpack(">HH", data[0x36:0x3A])
    segs = []  # (flags, file_off, vaddr, filesz)
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags, p_off, p_vaddr, _, p_filesz, _, _ = struct.unpack(
            ">IIQQQQQQ", data[o:o + 56])
        if p_type == 1 and p_filesz:
            segs.append((p_flags, p_off, p_vaddr, p_filesz))

    def to_vaddr(off):
        for _, so, sv, sz in segs:
            if so <= off < so + sz:
                return sv + off - so
        return None

    # 1) locate strings and raw pointers to them
    targets = []  # (label, vaddr)
    for name in names:
        b = name.encode()
        pos, found = 0, 0
        while True:
            pos = data.find(b, pos)
            if pos < 0:
                break
            if pos > 0 and data[pos - 1] == 0:
                s = to_vaddr(pos)
                if s is not None:
                    found += 1
                    targets.append((name, s))
                    print(f"[string ] {name} @ 0x{s:08X}")
                    ptr = struct.pack(">I", s)
                    p = 0
                    while True:
                        p = data.find(ptr, p)
                        if p < 0:
                            break
                        pv = to_vaddr(p)
                        if pv is not None and pv % 4 == 0:
                            print(f"[pointer] {name}: 0x{pv:08X} -> 0x{s:08X}")
                            targets.append((f"*{name}", pv))
                        p += 1
            pos += 1
        if not found:
            print(f"[string ] {name}: not found (as start of a NUL-terminated string)")

    # 2) build lookup tables
    oris_tab = {}  # hi16 -> [(label, lo16, vaddr)]  (dla par oris/ori)
    for label, t in targets:
        oris_tab.setdefault((t >> 16) & 0xFFFF, []).append((label, t & 0xFFFF, t))
    table = {}     # (ra, hi) -> [(label, lo, vaddr)]
    toc_short = {}  # off16 -> [(label, vaddr)]   for single-instruction lwz off(r2)
    for label, t in targets:
        for ra, val in ((0, t), (2, t - toc)):
            hi, lo = split(val)
            table.setdefault((ra, hi), []).append((label, lo, t))
        if label.startswith("*"):
            off = t - toc
            if -0x8000 <= off < 0x8000:
                toc_short.setdefault(off & 0xFFFF, []).append((label, t))

    # 3) scan executable segments
    hits = 0
    for flags, so, sv, sz in segs:
        if not flags & 1:
            continue
        n = sz // 4
        words = struct.unpack(">%dI" % n, data[so:so + n * 4])
        for i, w in enumerate(words):
            op = w >> 26
            if op == 32 and ((w >> 16) & 31) == 2 and (w & 0xFFFF) in toc_short:
                for label, t in toc_short[w & 0xFFFF]:
                    print(f"[REF    ] 0x{sv + 4 * i:08X}: lwz r{(w >> 21) & 31},"
                          f"off(r2) -> {label} (0x{t:08X})")
                    hits += 1
            if op == 25 and (w & 0xFFFF) in oris_tab:            # oris
                dst, srcr = (w >> 16) & 31, (w >> 21) & 31
                for label, lo16, t in oris_tab[w & 0xFFFF]:
                    for j in range(-WINDOW, WINDOW + 1):
                        k = i + j
                        if j == 0 or k < 0 or k >= n:
                            continue
                        w2 = words[k]
                        if (w2 >> 26) != 24 or (w2 & 0xFFFF) != lo16:      # ori
                            continue
                        d2, s2 = (w2 >> 16) & 31, (w2 >> 21) & 31
                        # oris -> ori: zrodlo ori == cel oris ; ori -> oris: zrodlo oris == cel ori
                        if (j > 0 and s2 == dst) or (j < 0 and srcr == d2):
                            print(f"[REF    ] 0x{sv + 4 * i:08X}: oris+ori (ori @0x{sv + 4 * k:08X}) "
                                  f"-> {label} (0x{t:08X})")
                            hits += 1
                            break
            if op != 15:
                continue
            ra = (w >> 16) & 31
            if ra not in (0, 2) or (ra, w & 0xFFFF) not in table:
                continue
            rt = (w >> 21) & 31
            for label, lo, t in table[(ra, w & 0xFFFF)]:
                for j, w2 in live_window(words, i, rt, WINDOW):
                    if (w2 & 0xFFFF) != lo:
                        continue
                    op2, ra2, rs2 = w2 >> 26, (w2 >> 16) & 31, (w2 >> 21) & 31
                    if (((op2 == 14 or op2 == 12) and ra2 == rt) or (op2 == 24 and rs2 == rt)
                            or (32 <= op2 < 56 and ra2 == rt)):
                        kind = "TOC" if ra == 2 else "abs"
                        print(f"[REF    ] 0x{sv + 4 * i:08X}: {kind} addis+op{op2} "
                              f"-> {label} (0x{t:08X})")
                        hits += 1
                        break
    print(f"done, {hits} reference(s) found")


if __name__ == "__main__":
    main()
