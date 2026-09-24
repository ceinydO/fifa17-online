import pathlib, struct

d = pathlib.Path("EBOOT.ELF").read_bytes()

TARGETS = {
    0x020AFA4B: "PreAuthResponse (krotka nazwa)",
    0x020AFA5B: "Blaze::Util::PreAuthResponse (pelna nazwa)",
}

# wszystkie 18 deskryptorow funkcji znalezionych w poprzednim skanie
# (code_addr, toc) -- bierzemy code_addr do analizy
FUNC_DESCRIPTORS = [
    0x01A17278, 0x01A29D10, 0x00263130, 0x01C936FC, 0x01A23A6C,
    0x01A29C28, 0x01A23A10, 0x00A6DE28, 0x00A6DF2C, 0x00A6E150,
    0x01A23BEC, 0x00A6E3A0, 0x00A6E3A0, 0x01A23A8C, 0x01A23B98,
    0x01A239D8, 0x01C93804, 0x00A6E4F8,
]


def instrs_at(vaddr, n=64):
    off = vaddr - 0x10000
    if off < 0 or off + n * 4 > len(d):
        return []
    return [int.from_bytes(d[off + i*4: off + i*4 + 4], "big") for i in range(n)]


def find_constants(words):
    """Zwraca liste (indeks_instrukcji, rejestr, wartosc) dla par lis+addi/ori
    budujacych 32-bitowa stala (typowy sposob ladowania adresu w PPC)."""
    hi = {}  # rejestr -> (wartosc_hi, indeks)
    out = []
    for i, w in enumerate(words):
        op = w >> 26
        rD = (w >> 21) & 0x1F
        rA = (w >> 16) & 0x1F
        simm = w & 0xFFFF
        if op == 15:  # addis / lis (gdy rA==0)
            hi[rD] = (simm, i)
        elif op == 14 and rA in hi:  # addi
            hi_val, _ = hi[rA]
            signed = simm if simm < 0x8000 else simm - 0x10000
            val = ((hi_val << 16) + signed) & 0xFFFFFFFF
            out.append((i, rD, val))
        elif op == 24 and rA in hi:  # ori
            hi_val, _ = hi[rA]
            val = ((hi_val << 16) | simm) & 0xFFFFFFFF
            out.append((i, rD, val))
    return out


print(f"Analizuje {len(FUNC_DESCRIPTORS)} funkcji, szukam adresow: {[hex(t) for t in TARGETS]}\n")

for idx, code_addr in enumerate(FUNC_DESCRIPTORS):
    words = instrs_at(code_addr, 64)
    if not words:
        print(f"[{idx:2d}] 0x{code_addr:08X}: poza plikiem, pomijam")
        continue
    consts = find_constants(words)
    hits = [(i, r, v) for i, r, v in consts if v in TARGETS]
    if hits:
        print(f"[{idx:2d}] 0x{code_addr:08X}: ZNALEZIONO!")
        for i, r, v in hits:
            print(f"      instrukcja #{i} (offset +0x{i*4:X}): r{r} = 0x{v:08X}  <- {TARGETS[v]}")
    else:
        # pokaz wszystkie znalezione stale (moze cos bliskiego, offset o kilka bajtow)
        near = [(i, r, v) for i, r, v in consts if 0x020AF000 <= v <= 0x020B0000]
        tag = f" (stale w poblizu: {[(hex(v)) for _,_,v in near]})" if near else ""
        print(f"[{idx:2d}] 0x{code_addr:08X}: brak trafienia{tag}")

print("\nJesli 'brak trafienia' wszedzie: zwieksz n= w instrs_at (funkcja moze byc dluzsza)")
print("albo string moze byc ladowany posrednio (np. przez TOC-relative lwz, nie lis+addi wprost).")
