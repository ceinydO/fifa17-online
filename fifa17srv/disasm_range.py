#!/usr/bin/env python3
"""Deasembler PPU (ELF64 BE) z podpisywaniem adresow stringow. Wymaga: pip install capstone

Uzycie:
    python disasm_range.py EBOOT.ELF POCZATEK [KONIEC]       # zakres adresow (hex)
    python disasm_range.py EBOOT.ELF ADRES --func            # cala funkcja zawierajaca ADRES
    python disasm_range.py EBOOT.ELF ADRES_VTABLE --vtable --slots 11,12,13
                                                            # funkcje z podanych slotow vtable
Opcje:  --max N   maksymalna liczba instrukcji na funkcje (domyslnie 400)
Adres wejscia funkcji zaczynajacy sie od `mflr r0 ; bl <stub>` jest pomijany (to stub prologu,
prawdziwe cialo zaczyna sie 8 bajtow dalej). Cienkie thunki (`addic r3,r3,imm` + `b`) sa przechodzone.

Sledzi wartosci rejestrow zbudowane z lis/li/addi/addic/ori/oris i przy kazdej instrukcji, ktorej
adres (albo adres efektywny load/store) wskazuje na tekst ASCII, dopisuje  ; "tekst".
To uproszczone sledzenie (bez petli i galezi): traktuj adnotacje jako podpowiedz.
"""
import struct
import sys

try:
    from capstone import CS_ARCH_PPC, CS_MODE_64, CS_MODE_BIG_ENDIAN, Cs
except ImportError:
    sys.exit("Brak modulu capstone. Zainstaluj:  pip install capstone")

MFLR_R0 = 0x7C0802A6


def sext16(v):
    return v - 0x10000 if v & 0x8000 else v


def main():
    args = list(sys.argv[1:])
    func_mode = "--func" in args
    vt_mode = "--vtable" in args
    args = [a for a in args if a not in ("--func", "--vtable")]

    def opt(name, default):
        if name in args:
            k = args.index(name)
            v = args[k + 1]
            del args[k:k + 2]
            return v
        return default

    max_insn = int(opt("--max", "400"), 0)
    slots = [int(x, 0) for x in opt("--slots", "").split(",") if x]
    if len(args) < 2:
        print(__doc__)
        sys.exit(1)
    path, start = args[0], int(args[1], 0)
    end = int(args[2], 0) if len(args) > 2 else start + 0x200

    data = open(path, "rb").read()
    e_phoff = struct.unpack(">Q", data[0x20:0x28])[0]
    e_phentsize, e_phnum = struct.unpack(">HH", data[0x36:0x3A])
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags, p_off, p_va, _, p_fsz, _, _ = struct.unpack(">IIQQQQQQ", data[o:o + 56])
        if p_type == 1 and p_fsz:
            segs.append((p_flags, p_off, p_va, p_fsz))

    def read(vaddr, n):
        for _, so, sv, sz in segs:
            if sv <= vaddr < sv + sz:
                take = min(n, sv + sz - vaddr)
                return data[so + vaddr - sv: so + vaddr - sv + take]
        return None

    def word(vaddr):
        b = read(vaddr, 4)
        return struct.unpack(">I", b)[0] if b and len(b) == 4 else None

    def is_code(v):
        return v is not None and any(f & 1 and sv <= v < sv + sz for f, _, sv, sz in segs)

    def text_at(vaddr):
        b = read(vaddr, 96)
        if not b:
            return None
        t = b.split(b"\0", 1)[0]
        if len(t) >= 3 and all(0x20 <= c < 0x7F for c in t):
            return t.decode("ascii")
        return None

    def prologue(w):
        return w is not None and (w & 0xFFFF0003) == 0xF8210001 and bool(w & 0x8000)

    def follow_thunks(a):
        """Jesli funkcja to cienki thunk (kilka `addic r3,r3,imm`/nop i skok `b`), idz za skokiem."""
        for _ in range(3):
            for k in range(4):
                w = word(a + 4 * k)
                if w is None:
                    return a
                if (w >> 26) == 18 and not (w & 1) and not (w & 2):          # b (bez LK, bez AA)
                    off = w & 0x03FFFFFC
                    off -= (w & 0x02000000) << 1
                    a = (a + 4 * k + off) & 0xFFFFFFFF
                    break
                if not ((w >> 26) == 12 and ((w >> 21) & 31) == 3 or w == 0x60000000):
                    return a
            else:
                return a
        return a

    def func_bounds(a):
        a = follow_thunks(a)
        w0, w1 = word(a), word(a + 4)
        if w0 == MFLR_R0 and w1 is not None and (w1 >> 26) == 18 and (w1 & 1):
            a += 8                                   # stub prologu: cialo zaczyna sie dalej
        lim = max(0, a - 0x3000)
        s0 = a
        while s0 > lim and not prologue(word(s0)):
            s0 -= 4
        if s0 <= lim:
            s0 = a - 0x100
        e0 = a + 4
        while e0 < a + 0x3000 and not prologue(word(e0)):
            e0 += 4
        return s0, e0

    md = Cs(CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN)

    def dump(fstart, fend):
        regs = {}
        shown = 0
        for addr in range(fstart, fend, 4):
            if shown >= max_insn:
                print(f"; ... obcieto po {max_insn} instrukcjach (uzyj --max)")
                break
            w = word(addr)
            if w is None:
                break
            shown += 1
            insns = list(md.disasm(struct.pack(">I", w), addr))
            txt = f"{insns[0].mnemonic} {insns[0].op_str}".strip() if insns else f".long 0x{w:08X}"

            op, rt, ra, imm = w >> 26, (w >> 21) & 31, (w >> 16) & 31, w & 0xFFFF
            note, val = "", None
            if op == 15:                                     # addis / lis
                base = 0 if ra == 0 else regs.get(ra)
                if base is not None:
                    val = (base + (sext16(imm) << 16)) & 0xFFFFFFFF
                    regs[rt] = val
                else:
                    regs.pop(rt, None)
            elif op in (12, 14):                             # addic (ten kompilator) / addi / li
                base = (0 if ra == 0 else regs.get(ra)) if op == 14 else regs.get(ra)
                if base is not None:
                    val = (base + sext16(imm)) & 0xFFFFFFFF
                    regs[rt] = val
                else:
                    regs.pop(rt, None)
            elif op in (24, 25):                             # ori / oris  (RS=rt, RA=dest)
                src = regs.get(rt)
                if src is not None:
                    val = (src | (imm if op == 24 else imm << 16)) & 0xFFFFFFFF
                    regs[ra] = val
                else:
                    regs.pop(ra, None)
            elif 32 <= op <= 55 and ra != 0 and regs.get(ra) is not None:
                ea = (regs[ra] + sext16(imm)) & 0xFFFFFFFF   # load/store: adres efektywny
                t = text_at(ea)
                note = f"  ; [0x{ea:08X}]" + (f' "{t}"' if t else "")
                if op in (32, 34, 40, 42):
                    regs.pop(rt, None)
            elif op == 18 and (w & 1):                       # bl: rejestry ulotne przestaja byc znane
                for r in range(3, 13):
                    regs.pop(r, None)
                tgt = (addr + ((w & 0x03FFFFFC) - ((w & 0x02000000) << 1))) & 0xFFFFFFFF
                note = f"  ; call 0x{tgt:08X}"
            if val is not None and op in (12, 14, 24, 25):   # nie podpisujemy samego lis
                t = text_at(val)
                if t:
                    note = f'  ; r{rt if op in (12, 14) else ra} = 0x{val:08X} "{t}"'
            print(f"0x{addr:08X}: {w:08X}  {txt:<34}{note}")

    if vt_mode:
        for k in slots:
            slot = word(start + 4 * k)
            desc = word(slot) if slot is not None and not is_code(slot) else None
            code = slot if is_code(slot) else (desc if is_code(desc) else None)
            print(f"\n; ===== slot {k} (+0x{4 * k:X}) vtable 0x{start:08X}: wpis "
                  f"0x{(slot or 0):08X} -> kod " + (f"0x{code:08X}" if code else "?"))
            if code:
                fs, fe = func_bounds(code)
                print(f"; funkcja: 0x{fs:08X} .. 0x{fe:08X}")
                dump(fs, fe)
        return

    if func_mode:
        start, end = func_bounds(start)
        print(f"; funkcja: 0x{start:08X} .. 0x{end:08X}  (heurystyka: od stdu r1,-N(r1) do nastepnego)")
    dump(start, end)


if __name__ == "__main__":
    main()
