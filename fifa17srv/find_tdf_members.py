#!/usr/bin/env python3
"""Szuka w danych PS3 ELF (ELF64 BE) tabel opisujacych pola typow TDF (tagi Blaze), zeby zobaczyc,
jakich tagow klient oczekuje w odpowiedzi (np. PreAuthResponse) i pod jakimi offsetami je trzyma.

Uzycie:
    python find_tdf_members.py EBOOT.ELF [--tags ASRC,CIDS,...] [--gap 0x80] [--min 5]
                               [--maxclusters 6] [--before 0x20] [--after 0x30]
Domyslne tagi: pola PreAuthResponse (ASRC,CIDS,CLID,CONF,ESRC,INST,MAID,MINR,NASP,PILD,PLAT,QOSS,RSRC,SVER).

Slowo w danych liczy sie jako trafienie, gdy jest:
  - kodem 24-bitowym tagu (0x00XXXXXX),
  - naglowkiem sieciowym: kod tagu w gornych 3 bajtach + typ (0..0xB) w dolnym,
  - tagiem jako 4 znaki ASCII (np. 'CONF' = 0x434F4E46),
  - wskaznikiem na napis ASCII rowny nazwie tagu.
Trafienia bliskie siebie (odstep <= --gap bajtow) tworza klaster; wypisywane sa klastry z co najmniej
--min roznymi tagami razem z zawartoscia tabeli (slowo po slowie, ze wskazaniem napisow).
"""
import struct
import sys

DEFAULT_TAGS = "ASRC,CIDS,CLID,CONF,ESRC,INST,MAID,MINR,NASP,PILD,PLAT,QOSS,RSRC,SVER"


def enc(tag):
    v = 0
    for i, ch in enumerate(tag.ljust(4)[:4]):
        v |= ((ord(ch) - 0x20) & 0x3F) << (18 - 6 * i)
    return v


def main():
    args = sys.argv[1:]

    def opt(name, default):
        if name in args:
            k = args.index(name)
            v = args[k + 1]
            del args[k:k + 2]
            return v
        return default

    tags = opt("--tags", DEFAULT_TAGS).split(",")
    gap = int(opt("--gap", "0x80"), 0)
    min_tags = int(opt("--min", "5"), 0)
    max_clusters = int(opt("--maxclusters", "6"), 0)
    before = int(opt("--before", "0x20"), 0)
    after = int(opt("--after", "0x30"), 0)
    if not args:
        print(__doc__)
        sys.exit(1)
    path = args[0]

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

    def text_at(v):
        for _, so, sv, sz in segs:
            if sv <= v < sv + sz:
                t = data[so + v - sv: so + v - sv + 64].split(b"\0", 1)[0]
                if 2 <= len(t) and all(0x20 <= c < 0x7F for c in t):
                    return t.decode("ascii")
                return None
        return None

    enc_map = {enc(t): t for t in tags}
    ascii_map = {int.from_bytes(t.ljust(4)[:4].encode(), "big"): t for t in tags}
    # adresy napisow "TAG\0"
    str_ptr = {}
    for t in tags:
        pos = 0
        pat = b"\0" + t.encode() + b"\0"
        while True:
            pos = data.find(pat, pos)
            if pos < 0:
                break
            for _, so, sv, sz in segs:
                if so <= pos + 1 < so + sz:
                    str_ptr[sv + pos + 1 - so] = t
            pos += 1

    hits = []   # (addr, tag, opis)
    for flags, so, sv, sz in segs:
        if flags & 1:
            continue
        n = sz // 4
        for i, w in enumerate(struct.unpack(">%dI" % n, data[so:so + n * 4])):
            addr = sv + 4 * i
            if w in enc_map:
                hits.append((addr, enc_map[w], "kod24"))
            elif (w >> 8) in enc_map and (w & 0xFF) <= 0xB and w > 0xFFFFFF:
                hits.append((addr, enc_map[w >> 8], f"naglowek(typ {w & 0xFF})"))
            elif w in ascii_map:
                hits.append((addr, ascii_map[w], "ascii4"))
            elif w in str_ptr:
                hits.append((addr, str_ptr[w], "wskaznik na napis"))
    hits.sort()
    print(f"trafien pojedynczych: {len(hits)}")

    clusters, cur = [], []
    for h in hits:
        if cur and h[0] - cur[-1][0] > gap:
            clusters.append(cur)
            cur = []
        cur.append(h)
    if cur:
        clusters.append(cur)
    good = [c for c in clusters if len({t for _, t, _ in c}) >= min_tags]
    good.sort(key=lambda c: -len({t for _, t, _ in c}))
    print(f"klastrow z >= {min_tags} roznymi tagami: {len(good)}")

    for c in good[:max_clusters]:
        lo, hi = c[0][0] - before, c[-1][0] + after
        distinct = sorted({t for _, t, _ in c})
        print(f"\n=== klaster 0x{c[0][0]:08X} .. 0x{c[-1][0]:08X}  ({len(distinct)} tagow: {','.join(distinct)})")
        marks = {a: (t, d) for a, t, d in c}
        lines = 0
        for a in range(lo, hi, 4):
            w = word(a)
            if w is None:
                continue
            note = ""
            if a in marks:
                note = f"  <== TAG {marks[a][0]} [{marks[a][1]}]"
            else:
                s = text_at(w) if w > 0x10000 else None
                if s:
                    note = f'  -> "{s}"'
                elif w < 0x10000:
                    note = f"  ({w})"
            print(f"  0x{a:08X}: {w:08X}{note}")
            lines += 1
            if lines >= 420:
                print("  ... (obcieto)")
                break


if __name__ == "__main__":
    main()
