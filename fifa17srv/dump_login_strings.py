"""Wypisuje ciag napisow wokol podanych stringow w EBOOT.ELF (ELF64 BE), w kolejnosci pliku,
razem z adresem wirtualnym. Uzycie:
    python dump_login_strings.py [EBOOT.ELF] [nazwa1 nazwa2 ...]
Domyslnie: LoginStateMachineConsole nucleusConnect psn_ticket. Wynik: dump_login_strings.txt
"""
import pathlib
import re
import struct
import sys

args = sys.argv[1:]
path = args[0] if args and args[0].lower().endswith(".elf") else r"C:\fifa17-ps3\EBOOT.ELF"
names = [a for a in args if not a.lower().endswith(".elf")] or [
    "LoginStateMachineConsole", "nucleusConnect", "psn_ticket"]
BEFORE, AFTER = 700, 1500

data = pathlib.Path(path).read_bytes()
e_phoff = struct.unpack(">Q", data[0x20:0x28])[0]
e_phentsize, e_phnum = struct.unpack(">HH", data[0x36:0x3A])
segs = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, _f, p_off, p_va, _pa, p_fsz, _m, _al = struct.unpack(">IIQQQQQQ", data[o:o + 56])
    if p_type == 1 and p_fsz:
        segs.append((p_off, p_va, p_fsz))


def vaddr(off):
    for so, sv, sz in segs:
        if so <= off < so + sz:
            return sv + off - so
    return None


out, seen = [], set()
for name in names:
    pos = data.find(b"\0" + name.encode() + b"\0")
    if pos < 0:
        out.append(f"### {name}: nie znaleziono\n")
        continue
    lo, hi = max(0, pos - BEFORE), pos + AFTER
    if any(lo <= s0 < hi for s0 in seen):      # okno juz wypisane
        out.append(f"### {name}: w oknie wypisanym wyzej\n")
        continue
    seen.add(pos)
    out.append(f"### okno wokol {name} (plik 0x{pos:X}, vaddr 0x{(vaddr(pos + 1) or 0):08X})")
    for m in re.finditer(rb"[\x20-\x7e]{3,}", data[lo:hi]):
        off = lo + m.start()
        mark = "  <== " + name if off == pos + 1 else ""
        out.append(f"0x{(vaddr(off) or 0):08X}  {m.group().decode()}{mark}")
    out.append("")
pathlib.Path("dump_login_strings.txt").write_text("\n".join(out), encoding="utf-8")
print("\n".join(out))
