import pathlib

d = pathlib.Path("EBOOT.ELF").read_bytes()

# Blok wskaznikow zaraz po "...SetConnectionStateRequest\x00" + padding zer,
# odczytany z Twojego zrzutu (offset pliku 0x209FD68 -- 0x209FDB8 wg dumpa).
START = 0x209FD74  # pierwszy wskaznik "02 4e 3b 98" wg Twojego zrzutu (pierwszy blok)
COUNT = 40         # z zapasem -- wezmiemy wiecej niz 18, zobaczymy gdzie sie urywa

# stringi, ktorych szukamy w danych pod wskaznikami (jako podciag bajtow)
NEEDLE_SHORT = b"PreAuthResponse\x00"
NEEDLE_LONG = b"Blaze::Util::PreAuthResponse\x00"

def deref(vaddr, n=64):
    off = vaddr - 0x10000
    if off < 0 or off + n > len(d):
        return None
    return d[off:off+n]

print(f"Skanuje {COUNT} wskaznikow od file_off=0x{START:X}\n")
for i in range(COUNT):
    off = START + i * 4
    if off + 4 > len(d):
        break
    raw = d[off:off+4]
    vaddr = int.from_bytes(raw, "big")
    if vaddr == 0:
        print(f"[{i:2d}] file_off=0x{off:X} -> 0x00000000 (pusty)")
        continue
    blob = deref(vaddr, 96)
    if blob is None:
        print(f"[{i:2d}] file_off=0x{off:X} -> vaddr=0x{vaddr:08X} (POZA PLIKIEM)")
        continue
    txt = "".join(chr(b) if 32 <= b < 127 else "." for b in blob[:48])
    print(f"[{i:2d}] file_off=0x{off:X} -> vaddr=0x{vaddr:08X}")
    print(f"      bajty: {blob[:32].hex(' ')}")
    print(f"      tekst: {txt}")

# Dodatkowo: przeszukaj CALY plik pod katem wskaznikow do dlugiej nazwy
# "Blaze::Util::PreAuthResponse" (moze deskryptor wskazuje na nia, nie na krotka)
import re
long_hits = [m.start() for m in re.finditer(re.escape(NEEDLE_LONG), d)]
print(f"\nWystapienia samego stringa '{NEEDLE_LONG.decode()!r}': {len(long_hits)}")
for h in long_hits:
    vaddr = h + 0x10000
    refs = [m.start() for m in re.finditer(vaddr.to_bytes(4, "big"), d)]
    print(f"  file_off=0x{h:X} vaddr=0x{vaddr:08X} -> wskazniki na niego: {[hex(r) for r in refs][:10]}")
