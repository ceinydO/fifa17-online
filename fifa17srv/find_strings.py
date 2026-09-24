#!/usr/bin/env python3
"""Wypisuje napisy (zakonczone bajtem 0, drukowalne ASCII) zawierajace podany fragment, z adresami.

Uzycie:
    python find_strings.py EBOOT.ELF --contains Login [--contains State ...] [--range 0x01FA0000,0x01FC0000]
                           [--minlen 4] [--max 300]
Bez zaleznosci zewnetrznych.
"""
import struct
import sys


def main():
    args = sys.argv[1:]
    subs, lo, hi, minlen, mx = [], 0, 0xFFFFFFFF, 4, 300
    i = 1
    while i < len(args):
        if args[i] == "--contains":
            subs.append(args[i + 1].encode()); i += 2
        elif args[i] == "--range":
            a, b = args[i + 1].split(",")
            lo, hi = int(a, 0), int(b, 0); i += 2
        elif args[i] == "--minlen":
            minlen = int(args[i + 1], 0); i += 2
        elif args[i] == "--max":
            mx = int(args[i + 1], 0); i += 2
        else:
            i += 1
    if not args or not subs:
        print(__doc__)
        sys.exit(1)
    data = open(args[0], "rb").read()
    e_phoff = struct.unpack(">Q", data[0x20:0x28])[0]
    e_phentsize, e_phnum = struct.unpack(">HH", data[0x36:0x3A])
    found = []
    for k in range(e_phnum):
        o = e_phoff + k * e_phentsize
        p_type, p_flags, p_off, p_va, _, p_fsz, _, _ = struct.unpack(">IIQQQQQQ", data[o:o + 56])
        if p_type != 1 or not p_fsz:
            continue
        blob = data[p_off:p_off + p_fsz]
        start = 0
        while start < len(blob):
            end = blob.find(b"\0", start)
            if end < 0:
                break
            s = blob[start:end]
            va = p_va + start
            if (len(s) >= minlen and lo <= va < hi and all(0x20 <= c < 0x7F for c in s)
                    and any(sub in s for sub in subs) and (start == 0 or blob[start - 1] == 0)):
                found.append((va, s.decode("ascii")))
            start = end + 1
    found.sort()
    print(f"napisow: {len(found)}")
    for va, s in found[:mx]:
        print(f"0x{va:08X}  {s}")


if __name__ == "__main__":
    main()
