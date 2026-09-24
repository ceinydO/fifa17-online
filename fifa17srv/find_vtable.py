#!/usr/bin/env python3
"""Szuka tablic wirtualnych (vtable) ustawianych przez konstruktor w PS3 ELF i rozwiazuje ich sloty
do adresow kodu. Wymaga: pip install capstone (tylko dla zgodnosci; sama logika jej nie uzywa)

Uzycie:
    python find_vtable.py EBOOT.ELF ADRES_FUNKCJI [--depth N] [--slots M]
      --depth N  ile poziomow wywolan `bl` sledzic (domyslnie 2)
      --slots M  ile slotow vtable wypisac (domyslnie 16)

Dla kazdego `stw rS,0(rA)`, gdzie rS ma znana stala wartosc wskazujaca na tablice, wypisuje kandydata
na vtable i tabele slotow: slot -> deskryptor -> adres kodu. Slot o offsecie 0x2c to indeks 11.
Uproszczone sledzenie rejestrow (bez petli i galezi): traktuj wynik jako podpowiedz.
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
            return int(v, 0)
        return default

    depth = opt("--depth", 2)
    nslots = opt("--slots", 16)
    if len(args) < 2:
        print(__doc__)
        sys.exit(1)
    path, start = args[0], int(args[1], 0)

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

    def is_code(v):
        return v is not None and any(f & 1 and sv <= v < sv + sz for f, _, sv, sz in segs)

    def is_data(v):
        return v is not None and any(not f & 1 and sv <= v < sv + sz for f, _, sv, sz in segs)

    def prologue(w):
        return w is not None and (w & 0xFFFF0003) == 0xF8210001 and (w & 0x8000)

    seen = set()

    def analyze(fstart, level):
        if not is_code(fstart):
            return
        w0, w1 = word(fstart), word(fstart + 4)
        if w0 == 0x7C0802A6 and w1 is not None and (w1 >> 26) == 18 and (w1 & 1):
            fstart += 8                     # stub prologu (mflr r0 ; bl ...): cialo zaczyna sie dalej
        if fstart in seen:
            return
        seen.add(fstart)
        end = fstart + 4
        while end < fstart + 0x1800 and not prologue(word(end)):
            end += 4
        indent = "  " * level
        print(f"{indent}== funkcja 0x{fstart:08X} .. 0x{end:08X}")
        regs, calls = {}, []
        for addr in range(fstart, end, 4):
            w = word(addr)
            if w is None:
                break
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
            elif op == 36 and imm == 0 and regs.get(rt):          # stw rS,0(rA)
                cand = regs[rt]
                first = word(cand)
                if is_data(cand) and first is not None:
                    print(f"{indent}   vtable? 0x{cand:08X}  (zapis w 0x{addr:08X}: stw r{rt},0(r{ra}))")
                    for k in range(nslots):
                        slot = word(cand + 4 * k)
                        if slot is None:
                            break
                        desc = word(slot) if is_data(slot) else None
                        if is_code(slot):
                            info = f"kod 0x{slot:08X}"
                        elif desc is not None and is_code(desc):
                            info = f"deskryptor 0x{slot:08X} -> kod 0x{desc:08X}"
                        else:
                            info = "?"
                        mark = "   <== offset 0x2c (indeks 11)" if k == 11 else ""
                        print(f"{indent}     slot {k:2d} (+0x{4 * k:02X}): 0x{slot:08X}  {info}{mark}")
            elif op == 18 and (w & 1):                              # bl
                tgt = (addr + ((w & 0x03FFFFFC) - ((w & 0x02000000) << 1))) & 0xFFFFFFFF
                calls.append(tgt)
                for r in range(3, 13):
                    regs.pop(r, None)
        if level < depth:
            for tgt in calls:
                analyze(tgt, level + 1)

    analyze(start, 0)


if __name__ == "__main__":
    main()
