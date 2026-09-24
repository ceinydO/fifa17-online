#!/usr/bin/env python3
"""Znajduje wszystkie zapisy `stw rS, DISP(rA)` (przypisania pola struktury) w PS3 ELF i pokazuje
kontekst (kilka instrukcji przed zapisem). Wymaga: pip install capstone

Uzycie:
    python find_field_stores.py EBOOT.ELF 0x618 [--ctx N] [--max M] [--near ADRES --dist D]
      --ctx N        ile instrukcji przed zapisem pokazac (domyslnie 8)
      --max M        maksymalna liczba trafien do wydrukowania (domyslnie 60)
      --near ADRES   pokaz tylko zapisy w promieniu D bajtow od ADRES (domyslnie D=0x4000)
Na koncu drukuje liczbe wszystkich trafien.
"""
import struct
import sys

try:
    from capstone import CS_ARCH_PPC, CS_MODE_64, CS_MODE_BIG_ENDIAN, Cs
except ImportError:
    sys.exit("Brak modulu capstone. Zainstaluj:  pip install capstone")


def opt(args, name, default):
    if name in args:
        k = args.index(name)
        v = args[k + 1]
        del args[k:k + 2]
        return v
    return default


def main():
    args = sys.argv[1:]
    ctx = int(opt(args, "--ctx", "8"), 0)
    max_hits = int(opt(args, "--max", "60"), 0)
    near = opt(args, "--near", None)
    dist = int(opt(args, "--dist", "0x4000"), 0)
    if len(args) < 2:
        print(__doc__)
        sys.exit(1)
    path, disp = args[0], int(args[1], 0)
    near = int(near, 0) if near else None

    data = open(path, "rb").read()
    e_phoff = struct.unpack(">Q", data[0x20:0x28])[0]
    e_phentsize, e_phnum = struct.unpack(">HH", data[0x36:0x3A])
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags, p_off, p_va, _, p_fsz, _, _ = struct.unpack(">IIQQQQQQ", data[o:o + 56])
        if p_type == 1 and p_fsz and p_flags & 1:
            segs.append((p_off, p_va, p_fsz))

    md = Cs(CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN)

    def text(w, addr):
        ins = list(md.disasm(struct.pack(">I", w), addr))
        return f"{ins[0].mnemonic} {ins[0].op_str}".strip() if ins else f".long 0x{w:08X}"

    total, printed = 0, 0
    for so, sv, sz in segs:
        n = sz // 4
        words = struct.unpack(">%dI" % n, data[so:so + n * 4])
        for i, w in enumerate(words):
            if (w >> 26) != 36 or (w & 0xFFFF) != (disp & 0xFFFF):      # stw rS,DISP(rA)
                continue
            addr = sv + 4 * i
            total += 1
            if near is not None and abs(addr - near) > dist:
                continue
            if printed >= max_hits:
                continue
            printed += 1
            print(f"--- 0x{addr:08X}: {text(w, addr)}")
            for k in range(max(0, i - ctx), i + 3):
                if k >= n:
                    break
                mark = ">>" if k == i else "  "
                print(f"  {mark} 0x{sv + 4 * k:08X}: {text(words[k], sv + 4 * k)}")
    print(f"\nrazem zapisow stw ..., 0x{disp:X}(rA): {total}"
          + (f" (wypisano {printed})" if printed != total else ""))


if __name__ == "__main__":
    main()
