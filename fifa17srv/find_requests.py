#!/usr/bin/env python3
"""Katalog miejsc w kodzie, ktore wysylaja zadania Blaze: wszystkie wywolania `bl <funkcja_wysylajaca>` razem ze
stalymi argumentami r5 (komponent) i r6 (komenda), jesli sa zaladowane instrukcja `li` tuz przed wywolaniem.

W EBOOT funkcja wysylajaca zadanie to 0x00CFAD54 (widac ja m.in. przy wysylaniu fetchClientConfig, komenda 1).

Uzycie:
    python find_requests.py EBOOT.ELF [--target 0x00CFAD54] [--window 16] [--cmd 0x46,0x0A,...] [--regs 4,5]
      --cmd   pokaz tylko wywolania z takimi wartosciami r6 (komenda)
      --regs  dodatkowo wypisz stale `li` zaladowane do tych rejestrow tuz przed wywolaniem (np. 4 = drugi argument)
Wynik: adres wywolania, funkcja (heurystycznie), r5, r6. Bez zaleznosci zewnetrznych.
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

    target = int(opt("--target", "0x00CFAD54"), 0)
    window = int(opt("--window", "16"), 0)
    cmds = opt("--cmd", "")
    want = {int(x, 0) for x in cmds.split(",") if x} if cmds else None
    regs_opt = opt("--regs", "")
    extra = [int(x) for x in regs_opt.split(",") if x]
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
        if p_type == 1 and p_fsz and p_flags & 1:
            segs.append((p_off, p_va, p_fsz))

    rows = []
    for so, sv, sz in segs:
        n = sz // 4
        words = struct.unpack(">%dI" % n, data[so:so + n * 4])
        last_prologue = None
        for i, w in enumerate(words):
            if (w & 0xFFFF0003) == 0xF8210001 and (w & 0x8000):
                last_prologue = sv + 4 * i
            if (w >> 26) != 18 or not (w & 1) or (w & 2):
                continue
            off = w & 0x03FFFFFC
            off -= (w & 0x02000000) << 1
            addr = sv + 4 * i
            if ((addr + off) & 0xFFFFFFFF) != target:
                continue
            r5 = r6 = None
            ex = {}
            for j in range(1, window + 1):
                if i - j < 0:
                    break
                p = words[i - j]
                if (p >> 26) == 14 and ((p >> 16) & 31) == 0:            # li rX,imm
                    rt = (p >> 21) & 31
                    if rt in extra and rt not in ex:
                        ex[rt] = sext16(p & 0xFFFF)
                    if rt == 6 and r6 is None:
                        r6 = sext16(p & 0xFFFF)
                    elif rt == 5 and r5 is None:
                        r5 = sext16(p & 0xFFFF)
                if (p >> 26) == 18 and (p & 1):                          # wczesniejszy bl konczy skanowanie wstecz
                    break
            rows.append((addr, last_prologue, r5, r6, ex))

    rows.sort()
    shown = 0
    for addr, fn, r5, r6, ex in rows:
        if want is not None and r6 not in want:
            continue
        shown += 1
        f5 = f"0x{r5:04X}" if r5 is not None else "  ?   "
        f6 = f"0x{r6:04X}" if r6 is not None else "  ?   "
        more = "".join(f"  r{r}={ex[r]}" if r in ex else f"  r{r}=?" for r in extra)
        print(f"wywolanie 0x{addr:08X}  funkcja ~0x{(fn or 0):08X}  r5(komponent)={f5}  r6(komenda)={f6}{more}")
    print(f"\nrazem wywolan: {len(rows)}, pokazano: {shown}")


if __name__ == "__main__":
    main()
