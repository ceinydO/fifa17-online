"""Offline helper: look at a captured .bin file and try to find structure in it."""
from __future__ import annotations

import re
import sys
from pathlib import Path

from .tdf import decode_partial, pretty
from .util import hexdump


def analyze_file(path: str, max_offset: int = 64) -> int:
    data = Path(path).read_bytes()
    print(f"File: {path}  ({len(data)} bytes)\n")
    print("--- hexdump (first 512 bytes) ---")
    print(hexdump(data[:512]))

    strings = re.findall(rb"[\x20-\x7e]{4,}", data)
    if strings:
        print("\n--- printable strings ---")
        for s in strings[:60]:
            print("  " + s.decode("ascii"))

    if len(data) >= 4:
        print("\n--- length-field hypotheses (big-endian) ---")
        for name, val in (("u16@0", int.from_bytes(data[0:2], "big")),
                          ("u32@0", int.from_bytes(data[0:4], "big"))):
            print(f"  {name} = {val}  (file is {len(data)} bytes)")

    print("\n--- where does TDF decoding look plausible? ---")
    scored = []
    for off in range(0, min(max_offset, len(data))):
        fields, reached, err = decode_partial(data, off)
        if fields:
            scored.append((reached - off, off, fields, err))
    # prefer decodes that reach the end of the data cleanly, then the most bytes explained
    scored.sort(key=lambda t: (t[3] is not None, -t[0], t[1]))
    if not scored:
        print("  nothing decodes as TDF (frame header may be different than assumed).")
        return 1
    for consumed, off, fields, err in scored[:3]:
        status = "clean to end" if err is None else f"stopped: {err}"
        print(f"\n  offset {off}: {len(fields)} fields, {consumed} bytes consumed, {status}")
        print("  " + pretty(fields).replace("\n", "\n  "))
    return 0


if __name__ == "__main__":
    raise SystemExit(analyze_file(sys.argv[1]))
