# fifa17-friendlies

An open-source **server emulator for FIFA 17 online friendlies** (PC), so two people can play a
1v1 match over the internet after EA shut the official servers down.

> **Status: protocol-discovery phase (v0.1).** This release gets the game talking to *your*
> machine and records everything it says. It does **not** yet play a match. The server logic
> comes after we have real captures. Nothing here has been run against FIFA 17 itself yet.

Not affiliated with, endorsed by, or connected to Electronic Arts. You need your own legitimate
copy of FIFA 17. This project does **not** bypass DRM or ownership checks and must not contain
or distribute any EA files, assets or keys.

## What is tested and what is not

Tested with the built-in self-test (`python -m fifa17srv selftest`, synthetic clients, no game):

- fake redirector answering `redirector/getServerInstance` over TLS,
- capture probe for plaintext **and** TLS connections, including TLS 1.0 clients,
- ClientHello analysis and a byte-level handshake trace (what we sent, what the client answered),
- SHA-1 signed certificates, built by hand because newer `cryptography` releases refuse to,
- graceful handling of clients that reject the certificate,
- TDF encoder/decoder round trip and the capture analyzer.

**Unverified until we see real traffic:** the exact redirector XML FIFA 17 wants, whether the
game's TLS stack accepts our certificate, whether `secure=0` is honoured, the frame header
format (Blaze/FIRE2) and everything about match creation. The TDF codec follows other Blaze
games and may need corrections.

## Quick start (Windows 10/11)

1. Install Python 3.11+ and this folder somewhere convenient.
2. Open **PowerShell as Administrator** in the project folder:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\tools\install_redirector.ps1
   ```
   (adds one hosts line and creates `certs/`; it does *not* touch your certificate store)
3. Run the tests (optional but recommended): `python -m fifa17srv selftest`
4. Start the server: `python -m fifa17srv run`
5. Start FIFA 17 and go to an online mode (e.g. Online Friendlies).
6. Look in `logs/captures/`. Zip that folder and share it (it contains only what the game sent
   to *your* machine, but glance through it first).
7. When done, undo the changes:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\tools\remove_redirector.ps1
   ```

## Reading the results

| What you see in `logs/captures/redirector_*.txt` | Meaning / next step |
|---|---|
| `TLS handshake OK` and an HTTP request | The game trusts our cert. Continue with the Blaze capture. |
| `TLS handshake FAILED ... unknown ca` / `bad certificate` | The game rejected the cert. Try `install_redirector.ps1 -InstallCA`, or `python -m fifa17srv certs --sha1`. If that fails, the game has its own CA list and we need a different approach (see below). |
| `HINT: the client dropped the connection right after our ServerHelloDone` | The game got our certificate and hung up without a word: it does not trust it (or cannot parse it). Try `certs --force --sha1`, then `-InstallCA`. If nothing helps, the game most likely validates against a CA list inside its executable. |
| `TLS handshake FAILED ... version/cipher` | Read the ClientHello lines: they list what the game offers (probably SSLv3/TLS1.0 with legacy ciphers modern OpenSSL dropped). |
| Nothing at all | Hosts entry not active, wrong port, or a firewall. Check `ping winter15.gosredirector.ea.com` resolves to 127.0.0.1. |

After a good redirector step you should also get `blaze_*.txt` and `blaze_*_c2s.bin`. Inspect the
binary with:

```
python -m fifa17srv analyze logs/captures/blaze_XXXX_c2s.bin
```

It hexdumps the data, lists strings and guesses the frame-header size by finding the offset from
which the payload decodes cleanly as TDF.

If the game refuses a plaintext main connection, retry with `python -m fifa17srv run --secure 1`.

## Playing with a friend (later)

Bind to `0.0.0.0`, set `blaze_advertise_host` in `config.json` to an address your friend can
reach (public IP with a forwarded port, or a VPN such as Tailscale/ZeroTier/Hamachi), and have
your friend put that address in *their* hosts file for `winter15.gosredirector.ea.com`.

## Configuration

Create `config.json` next to this file to override any field of `fifa17srv/config.py`, e.g.

```json
{ "bind_address": "0.0.0.0", "blaze_advertise_host": "26.1.2.3", "blaze_secure": false }
```

## Layout

```
fifa17srv/redirector.py   fake redirector (HTTPS)
fifa17srv/probe.py        capture probe for the main Blaze port
fifa17srv/server.py       threaded server, capture logs, TLS-or-plaintext negotiation
fifa17srv/tls_hello.py    ClientHello parser (explains handshake failures)
fifa17srv/tdf.py          TDF codec (best effort, see caveats)
fifa17srv/analyze.py      capture inspection helper
fifa17srv/certs.py        throwaway local CA + server cert
tools/*.ps1               hosts/CA install and removal (Windows, run as admin)
```

## Security notes

* `-InstallCA` makes Windows trust a CA whose private key lives in `certs/`. Use it only if
  needed, keep `certs/` private, and run `remove_redirector.ps1` afterwards.
* The server is meant for localhost or a trusted friend. Do not expose it to the open internet.
* Do not download "FIFA private server" builds from random sites; build from source.

## Roadmap

1. Capture redirector + first Blaze packets (this release).
2. Confirm frame format; implement PreAuth / Ping / Authentication responses.
3. Get the client to a logged-in main menu with a local fake profile.
4. Online friendlies: lobby, invite, matchmaking, session hand-off (P2P vs relayed to be determined).
5. Docs of the protocol (clean-room notes, no EA code).

## Related work

Other people are reviving old FIFA online modes (mostly Ultimate Team); this project focuses on
friendlies. Contributions and shared captures are welcome. License: MIT.
