import re, pathlib

d = pathlib.Path("EBOOT.ELF").read_bytes()


def dump_window(center, before=800, after=1800, label=""):
    lo = max(0, center - before)
    hi = min(len(d), center + after)
    blob = d[lo:hi]
    print(f"\n=== okno wokol 0x{center:X} ({label}) [0x{lo:X}-0x{hi:X}] ===")
    for i in range(0, len(blob), 16):
        c = blob[i:i+16]
        txt = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
        print(f"{lo+i:08X}  {c.hex(' '):<47}  {txt}")


def find_all(needle):
    return [m.start() for m in re.finditer(re.escape(needle), d)]


# 1) hexdump wokol pierwszego trafienia PreAuthResponse -- zobaczmy caly uklad tabeli
pa_hits = find_all(b"Blaze::Util::PreAuthResponse")
if pa_hits:
    dump_window(pa_hits[0], before=200, after=100, label="Blaze::Util::PreAuthResponse (waskie okno stringa)")

# 2) szersze okno -- caly blok od GetTelemetryServerResponse do TELEMETRY_OPT_IN
resp_hits = find_all(b"GetTelemetryServerResponse")
if resp_hits:
    dump_window(resp_hits[0], before=50, after=2500, label="cala tabela wokol GetTelemetryServerResponse")

# 3) Fire2Metadata -- zobaczmy co jest TUZ PRZED (czesto tam sa pola struct jako stringi)
fm_hits = find_all(b"Blaze::Fire2Metadata")
if fm_hits:
    dump_window(fm_hits[0], before=600, after=200, label="Blaze::Fire2Metadata + kontekst przed")

# 4) szukaj wskaznikow (4-bajtowych, big-endian, w zakresie tego segmentu ~0x1F00000-0x2100000)
# ktore trafiaja DOKLADNIE w adres (vaddr) stringa "PreAuthResponse" (nie "Blaze::Util::..." -- sam tag)
tag_hits = find_all(b"PreAuthResponse\x00")
print(f"\nSame trafienia 'PreAuthResponse\\x00' (bez Blaze::Util:: prefixu): {len(tag_hits)}")
for h in tag_hits:
    vaddr = h + 0x10000
    print(f"  file_off=0x{h:X} vaddr=0x{vaddr:08X}")
    refs = find_all(vaddr.to_bytes(4, "big"))
    print(f"    wskazniki na ten vaddr (big-endian 4B): {[hex(r) for r in refs][:10]}")
