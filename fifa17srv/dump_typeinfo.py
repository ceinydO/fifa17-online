#!/usr/bin/env python3
"""Wyciaga z EBOOT definicje typow Blaze (nazwa, liczba czlonkow, tagi i nazwy pol).

Funkcje inicjalizujace typy (np. dla Blaze::Util::FetchConfigResponse) wypelniaja statyczna strukture:
  +0x08 pelna nazwa   +0x10 tablica funkcji   +0x14 nazwa krotka   +0x18 tablica czlonkow   +0x1C liczba czlonkow (u16)
Wpis czlonka ma 0x1C bajtow: [tablica funkcji typu][nazwa][0][0][tag<<8|x][w1][w2].

Uzycie:
    python dump_typeinfo.py EBOOT.ELF --name "Blaze::Authentication::LoginResponse" [--name ...]
    python dump_typeinfo.py EBOOT.ELF --tags AUTH,EXTB,EXTI       # znajdz typ, ktory ma te tagi
Wymaga tylko biblioteki standardowej.
"""
import struct
import sys


def sext16(v):
    return v - 0x10000 if v & 0x8000 else v


def enc(tag):
    v = 0
    for i, ch in enumerate(tag.ljust(4)[:4]):
        v |= ((ord(ch) - 0x20) & 0x3F) << (18 - 6 * i)
    return v


def main():
    args = sys.argv[1:]
    names, tags = [], None
    i = 1
    while i < len(args):
        if args[i] == "--name":
            names.append(args[i + 1]); i += 2
        elif args[i] == "--tags":
            tags = args[i + 1].split(","); i += 2
        else:
            i += 1
    if not args or (not names and not tags):
        print(__doc__)
        sys.exit(1)
    path = args[0]

    data = open(path, "rb").read()
    e_phoff = struct.unpack(">Q", data[0x20:0x28])[0]
    e_phentsize, e_phnum = struct.unpack(">HH", data[0x36:0x3A])
    segs = []
    for k in range(e_phnum):
        o = e_phoff + k * e_phentsize
        p_type, p_flags, p_off, p_va, _, p_fsz, _, _ = struct.unpack(">IIQQQQQQ", data[o:o + 56])
        if p_type == 1 and p_fsz:
            segs.append((p_flags, p_off, p_va, p_fsz))

    def seg_of(v):
        for s in segs:
            if s[2] <= v < s[2] + s[3]:
                return s
        return None

    def word(v):
        s = seg_of(v)
        if not s or v + 4 > s[2] + s[3]:
            return None
        return struct.unpack(">I", data[s[1] + v - s[2]: s[1] + v - s[2] + 4])[0]

    def cstr(v, n=100):
        s = seg_of(v)
        if not s:
            return None
        t = data[s[1] + v - s[2]: s[1] + v - s[2] + n].split(b"\0", 1)[0]
        return t.decode("latin-1") if t and all(0x20 <= c < 0x7F for c in t) else None

    def tag_str(w):
        t = w >> 8
        chars = [((t >> (18 - 6 * k)) & 0x3F) + 0x20 for k in range(4)]
        return "".join(chr(c) for c in chars)

    def prologue(w):
        return w is not None and (w & 0xFFFF0003) == 0xF8210001 and bool(w & 0x8000)

    def func_bounds(a):
        w0, w1 = word(a), word(a + 4)
        s0 = a
        while s0 > a - 0x1000 and not prologue(word(s0)):
            s0 -= 4
        e0 = a + 4
        while e0 < a + 0x1000 and not prologue(word(e0)):
            e0 += 4
        return s0, e0

    code_segs = [(s[1], s[2], s[3]) for s in segs if s[0] & 1]

    def scan_pairs(pred):
        """Zwraca listy (adres_lis, wartosc) dla par lis+addic/addi, ktorych wartosc spelnia pred."""
        out = []
        for so, sv, sz in code_segs:
            n = sz // 4
            words = struct.unpack(">%dI" % n, data[so:so + n * 4])
            for i, w in enumerate(words):
                if (w >> 26) != 15 or ((w >> 16) & 31) != 0:
                    continue
                rt, hi = (w >> 21) & 31, sext16(w & 0xFFFF)
                for j in range(1, 41):
                    if i + j >= n:
                        break
                    w2 = words[i + j]
                    op2 = w2 >> 26
                    if op2 in (12, 14) and ((w2 >> 16) & 31) == rt:
                        val = ((hi << 16) + sext16(w2 & 0xFFFF)) & 0xFFFFFFFF
                        if pred(val):
                            out.append((sv + 4 * i, val))
                        break
        return out

    def extract_typeinfo(fstart, fend):
        """Symuluje stale i zwraca {offset: wartosc} zapisow stw/sth do jednej bazy (r31 zwykle)."""
        regs, stores = {}, {}
        for addr in range(fstart, fend, 4):
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
            elif op in (36, 44):                       # stw / sth
                val = regs.get(rt)
                if val is not None:
                    stores.setdefault(ra, {})[sext16(imm)] = val
            elif op == 18 and (w & 1):
                for r in range(3, 13):
                    regs.pop(r, None)
        best = max(stores.values(), key=len) if stores else {}
        return best

    def show(fstart, fend, label=""):
        st = extract_typeinfo(fstart, fend)
        full = cstr(st.get(8, 0)) if st.get(8) else None
        short = cstr(st.get(0x14, 0)) if st.get(0x14) else None
        table, count = st.get(0x18), st.get(0x1C)
        print(f"\n=== {full or '?'}   (funkcja 0x{fstart:08X}){label}")
        print(f"    nazwa krotka: {short}   tablica czlonkow: " +
              (f"0x{table:08X}" if table else "?") + f"   liczba czlonkow: {count}")
        if not table or not count:
            return
        for m in range(min(count, 64)):
            e = table + 0x1C * m
            ftab, nptr, tagw, w1, w2 = word(e), word(e + 4), word(e + 0x10), word(e + 0x14), word(e + 0x18)
            print(f"    [{m:2d}] tag {tag_str(tagw or 0)!r:8}  nazwa {cstr(nptr) if nptr else None!s:28} "
                  f"typ-tablica 0x{(ftab or 0):08X}  w1=0x{(w1 or 0):X} w2=0x{(w2 or 0):X}")

    for nm in names:
        pat = b"\0" + nm.encode() + b"\0"
        pos = data.find(pat)
        if pos < 0:
            print(f"\n=== {nm}: nie znaleziono napisu")
            continue
        addr = None
        for s in segs:
            if s[1] <= pos + 1 < s[1] + s[3]:
                addr = s[2] + pos + 1 - s[1]
        hits = scan_pairs(lambda v, a=addr: v == a)
        if not hits:
            print(f"\n=== {nm} @ 0x{addr:08X}: brak odwolan w kodzie")
            continue
        done = set()
        for haddr, _ in hits:
            fs, fe = func_bounds(haddr)
            if fs in done:
                continue
            done.add(fs)
            show(fs, fe)

    if tags:
        wanted = {enc(t): t for t in tags}
        found = []
        for f, so, sv, sz in segs:
            if f & 1:
                continue
            n = sz // 4
            for i, w in enumerate(struct.unpack(">%dI" % n, data[so:so + n * 4])):
                if (w >> 8) in wanted and (w & 0xFF) <= 0xB and w > 0xFFFFFF:
                    found.append((sv + 4 * i, wanted[w >> 8]))
        print(f"\nwpisy z tagami {tags}: {len(found)}")
        for a, t in found:
            print(f"   0x{a:08X} {t}")
        # kandydaci na poczatek tablicy: wartosci 'lis+addic' w oknie przed pierwszym wpisem
        if found:
            first = found[0][0]
            cands = scan_pairs(lambda v: first - 0x1C * 40 <= v <= first - 0x10 and (first - 0x10 - v) % 0x1C == 0)
            seen = set()
            for haddr, val in cands:
                fs, fe = func_bounds(haddr)
                if fs in seen:
                    continue
                seen.add(fs)
                st = extract_typeinfo(fs, fe)
                if st.get(0x18) == val:
                    show(fs, fe, "  <- ma zadane tagi")


if __name__ == "__main__":
    main()
