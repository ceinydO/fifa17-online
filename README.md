# fifa17-friendlies

A from-scratch, MIT-licensed **server emulator for FIFA 17's EA Blaze online servers**, which EA
shut down. The concrete target being tested is the **PS3 build of FIFA 17, run under the RPCS3
emulator**, but nothing here is PS3-only by design (redirector/Blaze/QoS/Nucleus/telemetry are all
generic Blaze SDK 15.1.x infrastructure).

Not affiliated with, endorsed by, or connected to Electronic Arts. This is a preservation /
reverse-engineering project: **you need your own legitimate copy of FIFA 17**. This project does
**not** bypass DRM, Denuvo, or ownership/game-copy verification, does **not** help obtain pirated
game or firmware copies, and must not contain or distribute any EA files, assets, keys, or the
game itself.

> **Read this file before starting a new session on this project.** It is written to be the single
> source of truth for what is confirmed, what is a guess, and what is still broken — so a fresh
> session (human or Claude) does not have to re-derive it from scratch.

## Current status (as of 2026-09-24)

The full PS3 client login handshake **works end-to-end**: redirector → TLS → PreAuth → Ping →
fetchClientConfig → fake Nucleus OAuth → Blaze login → account/session notifications → main Online
menu is reachable and playable-looking (Continue → checkbox → OK gets you into the FIFA17 Online
menu with PLAY SEASON / ONLINE FRIENDLIES / CURRENT SEASON / TROPHY ROOM / PLAY CUP MATCH tiles).

**Open problem, unresolved:** selecting **"Play Cup Match"** takes the client to a stadium loading
screen that gets stuck forever on **"Loading Seasons information..."**. Selecting **"PLAY SEASON"**
instead shows a **blank screen** (a different failure mode, not yet investigated). See
"Current blocker" below for everything captured about this so far and the open theories.

## Architecture

```
FIFA17 (PS3, via RPCS3)
   |
   |--TLS--> redirector (fake, HTTPS) --------- winter15.gosredirector.ea.com, answers
   |                                             POST /redirector/getServerInstance with our
   |                                             blaze host:port
   |
   |--plaintext or TLS--> blaze (main game server, port 10051) -- PreAuth, Ping, fetchClientConfig,
   |                                             Authentication, UserSessions, Stats, ... (see below)
   |
   |--TLS--> qos (fake, HTTP-over-TLS, port 17502) -- NAT type / firewall / connectivity probing
   |
   |--plaintext--> nucleus (fake, HTTP, port 8081) -- fake OAuth: GET /connect/auth always succeeds
   |                                             with a 302 to a fixed FAKE_AUTH_CODE
   |
   \--TLS--> telemetry (fake, port 443) -- accepts rl.data.ea.com / pin-river.data.ea.com
                                            connections and immediately closes them (204/RST),
                                            just so the client doesn't hang retrying
```

All of this is driven by editing the PS3's hosts resolution (via `tools/install_redirector.ps1`,
which patches RPCS3's Windows hosts file) so `winter15.gosredirector.ea.com` and the telemetry
hostnames resolve to `127.0.0.1`.

## Blaze/Fire2 wire protocol (confirmed, not guessed)

### 16-byte frame header

Reconstructed from `grid-leak/blaze` (an open-source Blaze server for Mirror's Edge Catalyst, same
2016 Blaze SDK 15.1.x family — its advertised `SVER "Blaze 15.1.1.0.5"` is a near-exact match for
FIFA17's `BSDK "15.1.1.0.0"` from its CINF), and verified byte-for-byte against real FIFA17 PS3
captures:

```
offset  0-3   payload_size   u32 BE
offset  4-5   metadata_size  u16 BE  (always 0 in our captures -- no metadata section)
offset  6-7   component      u16 BE
offset  8-9   command        u16 BE
offset 10-12  msg_num        3 bytes BE (NOT 2 -- grows with each request in the same session)
offset 13     msg_type << 5  (Message=0, Reply=1, Notification=2, ErrorReply=3, Ping=4, PingReply=5)
offset 14     options        always 0 in our captures
offset 15     reserved       always 0 in our captures
```

A Reply has the **exact same** component/command/msg_num as the request it answers; only
`msg_type` changes to `Reply(1)`. A Notification is server-initiated (no matching request),
`msg_type=Notification(2)`, and its own independent msg_num sequence.

### TDF (Trusted Data Format) tag/value encoding

- Tag = 4 ASCII chars, 6 bits each (`code = char - 0x20`), packed big-endian into **3 bytes**.
  Implemented in `tdf.py`'s `encode_tag()` / equivalent decode.
- Field on the wire = 3-byte tag + 1 type byte + type-specific value encoding.
- Wire types (index = the byte written, in `tdf.py` order):
  `VARINT=0, STRING=1, BLOB=2, STRUCT=3, LIST=4, MAP=5, UNION=6, INTLIST=7, OBJTYPE=8, OBJID=9, FLOAT=10, TIME=11`.
  (Blaze TDF has no separate "bool" wire type — booleans are VARINT 0/1.)
- STRUCT ends with a `0x00` terminator byte after its fields.
- LIST = 1 byte subtype + varint count + that many encoded values.
- MAP = 1 byte key-type + 1 byte value-type + varint count + that many (key,value) pairs — the
  value type byte is written even when the map is empty (count=0), so an "empty map" reply still
  needs the correct key/value type bytes, not just a zero count.

Full codec: `fifa17srv/tdf.py`. `_enc_value()` / `encode_field()` / `encode()` are the ones that
matter; read them directly rather than trusting this summary if something looks off on the wire.

## What's implemented in `fifa17srv/blaze.py`, component by component

Legend: **[CONFIRMED]** = shape taken directly from EBOOT reflection data or matches a real
reference implementation 1:1. **[HYPOTHESIS]** = best guess from field names/types only, not
verified against any known implementation. **[UNHANDLED]** = falls through to the generic
empty-Reply fallback (`0` TDF fields) — this is very likely *wrong* for any command that isn't
purely a fire-and-forget notification, but the client has tolerated it so far for everything below
except possibly the current blocker.

- **`0x0009` Util** (`UTIL_COMPONENT`)
  - `0x0007` PreAuth **[CONFIRMED]** → `PreAuthResponse` (bisected field-by-field via
    `config.preauth_groups`; client only accepts CIDS as a type-4 LIST, not type-7 INTLIST)
  - `0x0002` Ping **[CONFIRMED]** → `PingResponse`
  - `0x0001` fetchClientConfig **[CONFIRMED]** → empty-ish typed reply per `CFID`
    (`OSDK_CORE`, `OSDK_CLIENT`, `OSDK_NUCLEUS`, `OSDK_WEBOFFER`, `OSDK_ABUSE_REPORTING`,
    `IdentityParams`, `OSDK_TICKER`, `OSDK_ROSTER` all observed)
  - `0x0004` (`LANG`, `LSID` = list of localization string ids, e.g.
    `SDB_ORIGIN_ACCT_WELCOME_BACK_HEADER`) **[UNHANDLED]** — looks like a batched localized-string
    fetch (welcome-back dialog, opt-in dialog copy). Client proceeds fine with an empty reply, so
    it's probably just falling back to baked-in English strings.
  - `0x0005` (`CMAC`, `SNAM`) **[UNHANDLED]** — unknown, sent once right after login with a MAC
    address and empty `SNAM`.
  - `0x0008` (`DSUI`, `MAC`, `UDID`) **[UNHANDLED]** — unknown, looks like device/session info.
  - `0x000A` (`KEY`, `UID`) **[UNHANDLED]** — looks like "get user setting by key". Observed keys:
    `FirstTimeFlag`, `AchievementCache`. Empty reply tolerated so far, but a real implementation
    should probably return the value or a proper NOT_FOUND, not zero fields — candidate suspect if
    Seasons-related state is fetched this way somewhere.
  - `0x000B` (`DATA`, `KEY`, `UID`) **[UNHANDLED]** — "set user setting by key", mirrors `0x000A`.
  - `0x000C` (no fields) **[UNHANDLED]** — unknown.

- **`0x0001` Authentication** (`AUTH_COMPONENT`)
  - `0x000A` login **[CONFIRMED]** → `LoginResponse` (bisected via `config.login_groups`)
  - `0x001E` getAccount **[HYPOTHESIS]** → `GetAccountResponse` — 16-field shape read from EBOOT's
    reflection table (function `0x00C75874`), but no code building a *real* response was found
    near it, only reflection metadata, so the field values themselves are guessed.
  - `0x0014` (`CPWD`, `CTRY`, `DOB`, `LANG`, `MAIL`, `OPT1`, `OPT3`, `PASS`, `PRNT`) **[UNHANDLED]**
    — looks like account creation / parental-consent data, all empty strings in the observed
    capture (opt-in dialog path). Client proceeds fine.
  - `0x0020` (`BUID`, `EPSN`, `EPSZ`, `FLAG`, `GNLS` = list of game names e.g. `FIFA17PS3BoxContent`,
    `FIFA17PS3`, `FIFA16PS3`, `FIFAWC14PS3`) **[UNHANDLED]** — looks like an entitlement/ownership
    check across a family of related titles. Client proceeds fine with an empty reply.
  - `0x00F2` (`CTRY`, `PTFM`) **[UNHANDLED]** — small country/platform check, sent a few times.

- **`0x0007` Stats** (`STATS_COMPONENT`) — standard EA Blaze SDK component, not FIFA-specific.
  Confirmed against `Mk0M/Impulsum14` (github.com/Mk0M/Impulsum14), an open-source Blaze backend
  for FIFA 14 PC on an older Blaze 13 SDK but the *same* SDK family/TDF layout — used as the
  "Rosetta stone" for tag names and command numbers that can't be derived from EBOOT alone.
  - `0x0004` getStatGroup **[CONFIRMED shape]** → `StatGroupResponse` (`CNAM/DESC/ETYP/KSUM/META/
    NAME/STAT`), real group name (`NAME`, e.g. `H2HSeasonalPlay`) echoed back, everything else
    empty since we have no real stat definitions.
  - `0x000F` getKeyScopesMap **[CONFIRMED shape]** → `KeyScopes { KSIT: map<string, KeyScopeItem> }`,
    sent as an empty map. **Added 2026-09-24** — previously fell through to the fully-empty
    fallback (not even a `KSIT` field), which is almost certainly wrong for a typed response.
    Confirmed on the wire afterwards, but did **not** fix the Cup Match freeze.
  - `0x0010` getStatsByGroupAsync **[CONFIRMED pattern]** → empty `Reply`, then a separate
    `GetStatsAsyncNotification` (`0x0007`/`0x0032`, `msg_type=Notification`) carrying
    `KeyScopedStatValues { GRNM, KEY, LAST, STS{AGGR,STAT}, VID }` with the real group name (tracked
    server-side across the connection as `last_stat_group`, since this request's own `NAME` field
    arrives empty) and empty stat lists. This two-step Reply-then-Notification pattern is how
    Impulsum14's server implements this exact RPC (`NotifyGetStatsAsyncNotificationAsync`).

- **`0x000F`** (component identity **not confirmed** — candidate: Association Lists, a stock Blaze
  component in other SDK versions)
  - `0x0002` (`FLAG`, `MGID`, `PIDX`, `PSIZ`, `SMSK`, `SORT`, `SRCE` objid, `STAT`, `TARG` objid,
    `TYPE`) **[UNHANDLED]** — `TYPE` decodes as a packed 4-char string: `1919905645 = "room"`. Looks
    like "get/list association list of type ROOM" (friends list, room list, or similar). Worth
    identifying properly — this and `0x08C9` below are the two unexplained components seen in the
    observed flow.
  - `0x0005` (same struct shape, `FLAG=0`, no readable `TYPE`) **[UNHANDLED]**.

- **`0x000A`** (component identity not confirmed) — `0x0001`, zero-field request, **[UNHANDLED]**.

- **`0x0015`** (component identity not confirmed) — `0x000A` (`UPDT` varint), **[UNHANDLED]**.

- **`0x08C9`** (component identity **not confirmed**, likely FIFA-specific since it's not in
  Impulsum14/any generic Blaze SDK component list) — `0x0001` and `0x0002`, both zero-payload
  requests, both **[UNHANDLED]**. Sent right after `getAccount` succeeds, *before* the persona
  lookup. Not yet identified via EBOOT static analysis — good candidate to check next, since it's
  FIFA-specific and untouched so far.

- **`0x7802` UserSessions** (`USER_SESSIONS_COMPONENT`)
  - `0x0032` lookupUsersByPersonaNames **[HYPOTHESIS]** → sends `ULST = LIST<UserData>` (tag name
    `ULST` confirmed via Impulsum14's `UserDataResponse.cs`; the `UserData` struct shape
    `EXBB/EXID/ID/NAME/NASP/FLGS` read directly from EBOOT reflection data next to
    `UserIdentification`'s) as the priority field, **plus** a shotgun fallback of
    `USER/VALU/DATA/LIST` tags with the older `UserIdentification` shape, in case the client
    actually wants one of those instead. This response format is the least confidently verified
    of the "working" pieces — it visibly works (client proceeds), but which of the two field sets
    the client is actually reading was never isolated.
  - `0x0014` updateNetworkInfo **[CONFIRMED pattern]** → empty `Reply` + `UserSessionExtendedDataUpdate`
    notification (`0x0001`). Observed **twice** per connection: once right after login with
    placeholder NAT info (`NATT=5`), once later after QoS probing on port 17502 with real results
    (`NATT=1` in the last capture).
  - Notifications, all **[CONFIRMED]** patterns (sent unprompted after login):
    `UserAuthenticated` (`0x0008`), `NotifyUserAdded` (`0x0002`), `UserUpdated` (`0x0005`),
    `UserSessionExtendedDataUpdate` (`0x0001`).

## Current blocker: "Loading Seasons information..." freeze

**Repro:** log in (Continue → tick checkbox → OK) → FIFA17 Online menu → **Play Cup Match** →
stadium loading screen → stuck forever on "Loading Seasons information...". (**PLAY SEASON**
instead shows a blank screen — a different, also-unfixed failure mode, not yet captured/analyzed
separately.)

**What the wire capture shows, most recent run (2026-09-24, after the `getKeyScopesMap` fix):**
everything from login through the full Stats burst completes cleanly, in order, with correct data
and no error/disconnect:

1. `lookupUsersByPersonaNames` (`0x7802/0x0032`) → our UserData reply
2. `Stats::getStatGroup` (`0x0007/0x0004`, `NAME='H2HSeasonalPlay'`) → `StatGroupResponse` with the
   real group name echoed
3. `Stats::getKeyScopesMap` (`0x0007/0x000F`) → `KeyScopes{KSIT: {}}`
4. `Stats::getStatsByGroupAsync` (`0x0007/0x0010`) → empty `Reply` + `GetStatsAsyncNotification`
   with the real group name, empty stat lists, `LAST=1`
5. Two rounds of QoS HTTP probing on port 17502 (`/qos/qos`, `/qos/firewall`, `/qos/firetype`) —
   all `200 OK`
6. `UserSessions::updateNetworkInfo` (`0x7802/0x0014`) sent a **second** time by the client, now
   with real NAT-detection results — answered with empty `Reply` + `UserSessionExtendedDataUpdate`
   notification

**After step 6, the client sends nothing further at all.** This is the key fact: it is not that a
later request gets mishandled — the client goes completely silent while the loading spinner keeps
spinning. That points to one of:

- **(a)** the client waiting on some other async Notification we never send, from a component
  whose role is still unidentified (`0x08C9` and `0x000F` above are the prime suspects, since
  they're the only pieces of the observed flow that are still a complete black box);
- **(b)** a client-side check against the *content* of one of our replies failing silently — e.g.
  something subtly wrong in `GetStatsAsyncNotification`'s byte layout that isn't visible just from
  the Python-level field list (Impulsum14 itself has never been observed on real FIFA17 wire
  traffic for this exact packet, only cross-referenced structurally);
- **(c)** the freeze has nothing to do with Stats at all, and is really about `0x08C9`/`0x000F`
  getting empty fallback replies earlier in the flow.

**Update 2026-09-24, second data point:** captured the "Play Cup Match" path again (same server
run, `getKeyScopesMap` fix in place). The Blaze wire trace is byte-for-byte identical in shape to
the first capture above. New information this time came from two places that aren't Blaze traffic
at all:

- **The stadium loading screen shows a banner: "⊗ PRESS THE START BUTTON TO RE-CONNECT"** (red
  no-globe icon, top right). This is the first concrete UI-level signal we've gotten — the client
  itself believes it has lost its online connection, it's not just a spinner with nothing behind
  it.
- **The raw Blaze TCP connection is provably still alive and healthy** the whole time: frame-level
  pings (`component=0x0000 command=0x0000 msg_type=4`, i.e. `Ping`/`PingReply` at the transport
  level, distinct from `Util::ping`) keep arriving every ~20s and get answered normally, for over
  a minute after the client goes silent at the application level. So this is **not** a dropped
  socket or a raw timeout — whatever decides to show "RE-CONNECT" is a higher-level client-side
  check.
- **`GameManager` (the standard Blaze component for creating/joining a game session, `0x0004` in
  most SDK versions) never appears anywhere in any capture we have**, including this one. Every
  other component in the observed flow up to this point (Util `0x0009`, Auth `0x0001`, Stats
  `0x0007`, UserSessions `0x7802`, the two unidentified `0x000F`/`0x08C9`) has shown up at least
  once. If Cup Match needs to create or join a game session, the client should eventually send
  *something* to a GameManager-shaped component — it never does, which means whatever it's
  waiting on happens **before** it would even attempt that.
- The RPCS3 native log around the same time shows the client's PSN layer doing an unrelated
  `sceNpCommerce2` store/DLC product-info check (`GetProductInfoListStart`, 26 product IDs) that
  fails with `SCE_NP_COMMERCE2_ERROR_INVALID_ARGUMENT` — this is PS3's real Store API, not Blaze,
  and RPCS3 marks its handler `TODO` (unimplemented stub). Almost certainly unrelated to the
  freeze (a real PS3 would talk to Sony's actual store for this), but noted here in case it turns
  out not to be.

**Working theory, unconfirmed:** the "RE-CONNECT" banner is most likely the client's own
watchdog/precondition check for entering online play — something it expects to have (a piece of
`UserSessionExtendedDataUpdate` state, a Notification from a component we haven't identified, or
a QoS/NAT result it doesn't like) never arrives or never satisfies it, so after some internal
timeout it gives up and shows the generic "lost connection" UI rather than proceeding to whatever
would call GameManager. This is different from "the server sent a malformed reply" — it looks more
like "the client is waiting for something the server never sends at all."

**Update 2026-09-24, EBOOT static analysis of GameManager (component `0x0004`, confirmed via
Impulsum14's `GameManagerBase.json`):** `find_requests.py` (backward-scans for `li r5,imm` /
`li r6,imm` right before each call to the request-send function `0x00CFAD54`) found **190 total
call sites in the whole EBOOT, and NOT ONE of them has a resolvable r5 (component)** — this
compiler doesn't load the component id via an immediate right before the call, for any component,
so this heuristic can't be used to prove or disprove a specific component is called. It's still
useful for r6 (command): clusters of known commands appear together (e.g. `0x01CA2E4C`-`0x01CA338C`
contains commands `0x0004/0x000F/0x0010`, matching Stats' `getStatGroup/getKeyScopesMap/
getStatsByGroupAsync` — the RPC stub functions for a component appear to be laid out contiguously
in the binary), but no such cluster of GameManager-shaped command values (createGame=1, joinGame,
etc., per Impulsum14) was found anywhere in the 190 call sites.

Confirmed via `find_str_refs.py` that GameManager **is** compiled into the client: literal strings
`createGame`, `joinGame`, `NotifyGameSetup`, `cancelMatchmaking`, `startMatchmaking`, etc. all
exist in EBOOT (`0x01FA90B8` onward), and `0x00C92400`-`0x00C92600` is a `getCommandName()`-style
switch (command number in r3 → name string) covering GameManager's full ~40-command RPC set. This
proves the component's code exists and isn't dead-code-eliminated, but a name lookup table doesn't
prove where (or whether) the client actually *calls* `createGame`/`joinGame` — that would require
finding callers of this command-name function or tracing the actual RPC dispatch, neither done yet.

**Tried and disproven:** changed `qos.py`'s `/qos/firetype` response from `2` to `0` (Open vs.
Strict in typical EA/DirtySDK NAT-type numbering), on the theory that the client refuses to attempt
P2P after concluding it has a bad NAT type. Confirmed the change **does** reach the client and
changes its own computed `NATT` value in the next `updateNetworkInfo` (was `1`, became `4`) — so
the QoS responses genuinely feed into the client's NAT-type math — but the Cup Match freeze was
**unaffected**: same "Loading Seasons information..." hang, no GameManager traffic, connection
otherwise unchanged. Don't retry this specific value swap; if NAT-type theories come up again,
the fact that `NATT` shifted 1→4 for a firetype 2→0 change is worth using to reverse-engineer what
the field actually encodes before guessing another value blindly.

**Tried and disproven:** `build_ext_data_update()` used to send `ADDR` as `UNSET` in the
`UserSessionExtendedDataUpdate` notification that follows `updateNetworkInfo`, even though the
client's own `updateNetworkInfo` request always shows `EXIP` as all-zero (it doesn't know its own
external address and appears to be asking for it back). Changed it to send a real
`NetworkAddress::IpPairAddress` (union disc=2, tag `VALU`, fields `EXIP`/`INIP`/`MACI` — shape
confirmed on the wire from the client's own request) echoing back the client's reported local
`INIP`/`MACI`/`PORT` as both `EXIP` and `INIP` (everything is loopback here, so "external" ==
"internal"). **This worked exactly as designed and is worth keeping**: the very next
`updateNetworkInfo` the client sends shows `EXIP: IP=127.0.0.1, PORT=3659` — the client accepted
and echoed back exactly the address we gave it. But the Cup Match freeze was **still unaffected**:
identical "Loading Seasons information..." hang immediately after. So a missing/unset session
address was not the (sole) gate either. Keep this fix (it's more correct than `UNSET` regardless,
and future components may depend on it), but stop looking at `UserSessionExtendedData`'s `ADDR`
field as the blocker.

**Update 2026-09-24, third data point + component IDs resolved, BPS/QDAT fix tried:** user
clarified the "freeze" is actually a **persistent spinning loading icon in the corner of the
screen**, not a hard hang — raw frame-level pings keep succeeding indefinitely, confirming the
client is alive and just idling/waiting, not crashed. Checked the RPCS3 native log (`sceNp*`
calls) around and after the freeze point: **no `sceNpMatching2`/signaling calls at all** — only
trophies, the known/unrelated `sceNpCommerce2` store-check failures, and a periodic
`sceNpBasicSetPresence` heartbeat. This rules out "client is stuck waiting on native PSN
matchmaking" as a cause — the blocker is confirmed to be Blaze-level, not RPCS3/PSN-level.

Resolved two previously-unidentified component IDs against Impulsum14
(`Components/*ComponentBase.json`, cross-checked against `PostLoginComponents.cs`, a working
reference server's post-login handler set):
- `0x000A` (10 decimal) = **CensusData** (`SubscribeToCensusDataAsync`) — our empty-Reply fallback
  is *correct* (Impulsum14's reference handler also just returns `EmptyMessage`).
- `0x000F` (15 decimal) = **Messaging** (`fetchMessages`=2, `getMessages`=5, confirmed by command
  numbers matching exactly) — NOT "Rooms" as previously guessed (that guess conflated hex/decimal).
  Empty-Reply fallback is correct here too (reference handler returns `EmptyMessage`).
- `0x0015` (21 decimal) = **Rooms** (`selectViewUpdates`=10, matches the observed `UPDT=1` field
  from `SelectViewUpdatesRequest.cs`) — empty-Reply fallback is *also correct*
  (`RoomsComponent.SelectViewUpdatesAsync` in the reference returns `EmptyMessage` too).
  So the earlier "`TYPE=room`" lead on component `0x000F` was based on a hex/decimal mixup and
  is a dead end; Rooms subscription itself needs no reply body.

None of these three were the blocker. But comparing our `updateNetworkInfo` handling against
`UserSessionExtendedData`'s full field list (`Address.cs` set: `ADDR`/`BPS`/`CMAP`/`CTY`/`CVAR`/
`DMAP`/`HWFG`/`PSLM`/`QDAT`/`UATT`/`ULST`) turned up a real gap: the client's second
`updateNetworkInfo` sends us `NLMP` (its own measured ping-site latencies, e.g. `'ea-sjc':
1601961990`) and `NQOS` (`DBPS`/`NATT`/`UBPS`, self-computed), but our
`UserSessionExtendedDataUpdate` notification only ever echoed `ADDR` — never `BPS`
(`BestPingSiteAlias`) or `QDAT` (`Util::NetworkQosData`). EA Sports' "connecting" spinner is
plausibly waiting on the server to confirm the best ping site / finalize QoS before it can
dismiss. **Tried (2026-09-24, not yet verified live):** `blaze.py`'s `updateNetworkInfo` handler
now parses `NLMP`/`NQOS` from the client's request and `build_ext_data_update()` echoes back
`BPS` (lowest-latency key from `NLMP`) and `QDAT` (mirroring the client's own `DBPS`/`NATT`/
`UBPS`) in the `UserSessionExtendedDataUpdate` notification. Unit-tested the encoder locally
(round-trips through `tdf.decode`/`pretty` correctly, shape matches `UserSessionExtendedData.cs`
+ `NetworkQosData.cs`). **Tested live: disproven.** The notification correctly grew from 24B to
128B (confirming `BPS`/`QDAT` were actually sent, `BPS='ea-sjc'`, `QDAT` mirroring the client's
own NATT=4/DBPS=0/UBPS=0), but the client's behavior was byte-for-byte identical to before: same
silence immediately after `updateNetworkInfo #2`/msg_num=40, same raw-ping-only tail. Keep the
BPS/QDAT fields (more correct regardless, matches the confirmed TDF shape) but this is not the
gate either.

Also ran `disasm_range.py` over `0x00C92300`-`0x00C92600`, confirming the GameManager
`getCommandName()`-style dispatch is a big `cmpwi`/`beq` chain covering the full command set
(`addAdminPlayer` through `setGameEntryCriteria` and beyond) with each branch loading a literal
string pointer — this is purely a name-lookup table (probably for logging/asserts), not evidence
of the RPC path being invoked. No new leads from this.

**Tried and inconclusive: literal search for component `0x08C9` as an `li`/`ori` immediate.**
Computed the PPU opcodes for `li rX,0x8C9` / `ori rX,r0,0x8C9` for X=3..10 and scanned the raw
EBOOT.ELF bytes. Important gotcha: raw file offsets are NOT the same as the virtual addresses
`disasm_range.py` takes — this EBOOT's first (and largest) `PT_LOAD` segment has
`vaddr - offset = 0x10000`, so a raw byte-search hit at file offset `X` corresponds to VA
`X + 0x10000` (confirmed via the ELF program headers: `phoff=0x40`, `phentsize=56`, `phnum=8`,
two real `PT_LOAD` segments both with that same `0x10000` delta, plus three degenerate
zero-size `PT_LOAD` entries to ignore). After correcting for this, found one genuine `li r4,
0x8C9` at VA `0x002991E0`, but it's followed by `bl 0x01A148A0` — not the known Blaze send
function (`0x00CFAD54`) — so it doesn't look related. Two other raw-offset hits
(`0x0030AA08`/`0x0030AAEC` → corrected VA `0x0030BA08`/`0x0030BAEC`) turned out to be false
positives on reinspection (the bytes at the corrected VA are not `38 80 08 C9` at all — likely a
bug in the ad-hoc scan script from this session, not re-derived). **Do not trust file-offset hits
from a quick byte-scan without applying the `+0x10000` VA correction and verifying with
`disasm_range.py` before acting on them.** This technique did not find component `0x08C9`'s
load site; abandon it in favor of a different approach (e.g. `find_str_refs.py`-style TOC/pointer
reference tracing, or capturing a different client flow that might reference it more directly).

**Next investigation ideas, in rough priority order:**

1. Find the actual **caller(s)** of the GameManager `getCommandName()` function at
   `0x00C92400`-`0x00C926C0ish` (its entry is somewhere before `0x00C92400`, likely right after
   the `cmpwi`/`beq` chain starts — hasn't been located precisely yet). Whatever calls this to
   build a display/log string for a *specific* command number would show us which command (if any)
   the client is actually working with when it decides to give up and show "RE-CONNECT" — this is
   more promising than guessing at r5 values that `find_requests.py` can't resolve here.
2. Identify the real `GameManager`-equivalent component in this SDK/build and what it expects to
   receive *unprompted* (server-initiated) versus what it expects the client to send — check
   whether Impulsum14 has a server-side "auto-invite to game" or "session ready" notification that
   fires without a matching client request, since the client here never asks for one.
3. Identify component `0x08C9` (2249 decimal) in EBOOT via static analysis (string/reflection-table
   cross-reference, the same method used to find the `Stats` component and `UserData` shape this
   session). It's FIFA-specific so it won't be in Impulsum14 — needs direct EBOOT work. Given it
   fires right after login and before persona lookup, it's plausibly session/entitlement setup
   that later steps depend on.
4. Capture and analyze the **PLAY SEASON → blank screen** path separately — a blank screen implies
   the client got further than a network stall (it's rendering *something*, just wrong/empty),
   which might be a more tractable lead than the frozen spinner.
5. Hex-dump-verify `GetStatsAsyncNotification`'s actual bytes on the wire against `tdf.py`'s
   encoder output line by line, rather than trusting the Python field-list source.

**Update 2026-09-24 (new session, PS3-side/binary-patch angle instead of Blaze-wire angle):**
this update is about the *exact same* "RE-CONNECT"/frozen-spinner blocker described above, but
approached from RPCS3-native-log + PS3-binary-patching instead of Blaze wire captures. Both symptom
descriptions ("Loading Seasons information...", "PRESS THE START BUTTON TO RE-CONNECT") are the
same underlying freeze; Play Cup Match and Play Season both exhibit it.

**Critical infrastructure discovery: how this user's RPCS3 actually boots the game.** The user's
RPCS3 does **not** boot `C:\fifa17-ps3\EBOOT.ELF` directly — it boots from an **ISO**
(`C:/rcps3/games/FIFA 17 (Europe) (En,Fr,De,Es,It,Nl,Pt,Sv,No,Da,Pl,Ru).iso`), with
`Elf path: /dev_bdvd/PS3_GAME/USRDIR/EBOOT.BIN` inside it (confirmed via `Elf path:` /
`Booting from gamelist...` lines in `RPCS3.log`). **Any direct byte-patch to the standalone
`C:\fifa17-ps3\EBOOT.ELF` file has zero effect on actual gameplay** — this was tried and confirmed
useless this session (a verified-correct byte patch produced no behavior change at all). Disc
serial (confirmed via `Serial:` lines in `RPCS3.log`, do not confuse with the `UP0006-BLUS31543_00`
/`UP0006-BLUS31593_00` strings seen in NP ticket/commerce calls, which are unrelated EA network
service IDs): **BLES02233**, version **01.00** (European edition).

**The correct way to apply a binary patch: RPCS3's Patch Manager (`patch.yml`).** Location on this
user's machine: `C:\rcps3\patches\patch.yml` (NOT `C:\rcps3\patch.yml` — confirmed by the user).
RPCS3 applies patches from this file to the executable **in memory at runtime**, keyed by PPU
executable hash + game title + serial + version, independent of which file on disk actually gets
booted — this is why it works where the direct file patch didn't. Confirmed working syntax (there
were already two working patches in the file under the same key when this session started, used as
the template):
```yaml
Version: 1.2
PPU-1243af2b292938038cdc3696755e82477122db3b:
  <Patch Name>:
    Games:
      FIFA 17:
        BLES02233: [ "01.00" ]
    Author: "custom"
    Notes: "..."
    Patch Version: "1.0"
    Patch:
          - [ be32, 0x<VA_hex>, 0x<value_hex> ]
```
Addresses are **VAs** (virtual addresses), same addressing scheme as everywhere else in this
project's disassembly work — not raw file offsets. New patches must be inserted as a new key under
the *same* `PPU-<hash>:` parent key (regex-insert before an existing sibling patch entry works
fine), and get picked up automatically by RPCS3's Patch Manager GUI (`FIFA 17 > BLES02233 v.01.00`)
without needing a restart — just enable the new patch's checkbox and relaunch the game.

**Patch #1 applied and confirmed effective: `NEW_THREAD_FOR_FE_INIT_STAGE3` default-value flip.**
Function `0x005C2BB8`-`0x005C2D44` gates creation of the "FIFA FE Second Initial Thread" (whose
endless recreation loop was the symptom investigated in earlier sessions) behind a config flag
whose *default* value (used when the key isn't found in an internal typed config store) is set by
`li r5, 1` (`38 A0 00 01`) at VA `0x005C2C10`. Patched via `patch.yml`:
```yaml
  Disable NEW_THREAD_FOR_FE_INIT_STAGE3 default (force off):
    Games:
      FIFA 17:
        BLES02233: [ "01.00" ]
    Author: "custom"
    Notes: "li r5,1 -> li r5,0 at 0x005C2C10, forces NEW_THREAD_FOR_FE_INIT_STAGE3 default to off"
    Patch Version: "1.0"
    Patch:
          - [ be32, 0x005C2C10, 0x38A00000 ]
```
**Confirmed effective**: after enabling this patch, `"FIFA FE Second Initial Thread"` no longer
appears **anywhere** in `RPCS3.log` during a full Cup Match/Play Season test — the first time in
the whole multi-session debugging effort this specific thread-creation loop has been eliminated.
**However, the on-screen symptom is unchanged** ("same as before" per user) — a *different*
mechanism has taken over the freeze.

**New blocker mechanism found: repeating "MoviePlayer2 Decode Thread" creation, NOT an actual
movie player.** There are two distinct things sharing this thread name in the log, easy to
conflate:
- A **real, legitimate** MoviePlayer2 thread (id `0x1000027`) plays the boot intro
  (`/dev_bdvd/PS3_GAME/USRDIR/data/movies/bootflowintro_MARKER.vp6`), reads real file data over
  ~3 seconds, and exits cleanly — log even shows `"PS3Shutdown, Movie player complete"` at the very
  end. **This is not the bug.**
- Starting **~2 seconds after** `cellGameDataCheck(): directory '/dev_hdd0/game/BLUS31543' not
  found` fails (this specific error has appeared in every test run all session, previously
  deprioritized), `FEThread` begins creating a new thread **every ~10.00-10.02 seconds, on the
  clock**, until the user closes the game window. These loop-threads do **no file I/O at all** —
  they're created, immediately do one `sys_mutex_unlock`, and exit in under 1ms. The
  "MoviePlayer2 Decode Thread" name on these is almost certainly a stale/reused thread-name-pointer
  artifact in RPCS3's thread-naming, not an actual video decoder — this is a generic polling/retry
  loop, structurally identical in behavior (fixed-interval, no-op, endless) to the now-fixed
  `FIFA FE Second Initial Thread` loop, just via a different code path.
- **Ruled out: not waiting on the network.** The `fifa17srv` console log for the same run shows the
  client closing its own Blaze TCP connection (`client closed the connection`) only ~19s after the
  last frame-level ping, with no further requests sent. RPCS3-log-side `sys_net_bnet_*` activity in
  the loop's time window is just polling an already-idle/closed socket. So whatever the 10-second
  loop is waiting for, it is **not** an unanswered Blaze request — it's a purely local/PS3-side
  wait (or a fixed timeout unrelated to any reply).
- **Tried, not yet verified live:** built and installed a synthetic `PARAM.SFO` at
  `C:\rcps3\dev_hdd0\game\BLUS31543\PARAM.SFO` (that directory existed on disk already but was
  completely empty — that's why `cellGameDataCheck` reported "not found"). Minimal PSF with keys
  `APP_VER=01.00`, `ATTRIBUTE=0` (int32), `CATEGORY=HG`, `PARENTAL_LEVEL=0` (int32),
  `TITLE=FIFA 17`, `TITLE_ID=BLUS31543`, `VERSION=01.00`. **`CATEGORY=HG` is a guess** — PS3
  category codes for this kind of supplementary/HDD game-data folder could plausibly also be `GD`;
  if this fix has no effect, try `GD` next before abandoning the idea. Built via a PowerShell script
  in this session's transcript (constructs the PSF header/index-table/key-table/data-table
  programmatically with correct offset math — regenerate from that script rather than hand-editing
  bytes if the category needs to change). **Not yet retested against a fresh RPCS3.log at the time
  of this README update** — next session should check whether (a) the "not found" message is gone
  and (b) the 10-second retry loop stopped.
- Given the loop isn't network-related, if the PARAM.SFO fix doesn't resolve it, the next lead
  should probably be identifying what specifically `FEThread` is polling for every 10 seconds —
  i.e., finding the actual calling function around the thread-creation call site (`func=*0xd9018`
  is a generic thread-trampoline, not useful on its own) via `find_callers.py` against whatever
  function issues these `_sys_ppu_thread_create` calls from `FEThread`, once that call site's VA is
  identified from a fresh disassembly pass.

## Reverse-engineering toolchain

The PS3 EBOOT.ELF static-analysis scripts (`find_str_refs.py`, `find_cmd_consts.py`,
`find_cmd_names.py`, `find_requests.py`, `disasm_range.py`, `dump_words.py`,
`find_tdf_members.py`, `find_callers.py`, ...) used to derive the confirmed facts above **are not
part of this git repository** — they live only on the Windows machine where the actual RE work
happens, alongside the (not-redistributed) EBOOT.ELF itself. If starting a fresh session without
that context, ask the user to run the relevant tool and paste its output rather than assuming the
tools are available locally; each tool prints its own usage/docstring on `--help` or bad args,
which is more reliable than remembering exact flags from a previous session.

- `find_callers.py <eboot.elf> <target_hex_va>`: dependency-free (no capstone), finds all `bl`/`b`
  instructions in `.text` whose branch target resolves to the given VA, by parsing ELF64 PT_LOAD
  program headers for VA↔file-offset mapping and decoding just the PPC primary-opcode-18 branch
  instruction. Useful for "who calls this function" when a targeted xref search is needed and
  heavier disassembly tooling is unavailable/slow. Confirmed working: found 9 callers of the config
  lookup function `0x143C4B8`; found 0 callers of `0x143C9D8` (a setter only reached indirectly via
  function pointer/vtable — a dead end for this specific technique, not a bug in the script).

**PS3 ELF VA↔file-offset mapping, important recurring gotcha:** this EBOOT's first (and largest)
`PT_LOAD` segment has `vaddr - file_offset = 0x10000` (confirmed via program headers: `phoff=0x40`,
`phentsize=56`, `phnum=8`, two real `PT_LOAD` segments sharing that same `0x10000` delta, plus
three degenerate zero-size `PT_LOAD` entries to ignore). A raw file-offset hit from a byte-level
scan is **not** the same as the VA that `disasm_range.py`/patch.yml/etc. expect — always add
`0x10000` and verify with `disasm_range.py` before trusting or acting on a raw-offset search hit.
(This bit this project once already: two apparent `li r4, 0x8C9` hits at raw offsets
`0x0030AA08`/`0x0030AAEC` turned out to be false positives on reinspection after correction.)

Known paths on the user's Windows machine (confirmed, not guessed -- ask the user to re-confirm
if a command against one of these fails, since setups can change):
- RE tool scripts: `C:\fifa17-friendlies-git\fifa17srv\` (run scripts from here, e.g.
  `python find_requests.py ...`)
- EBOOT.ELF (standalone file, disassembly target — **but NOT what RPCS3 actually boots**, see
  below): `C:\fifa17-ps3\EBOOT.ELF`
- **What RPCS3 actually boots**: an ISO,
  `C:/rcps3/games/FIFA 17 (Europe) (En,Fr,De,Es,It,Nl,Pt,Sv,No,Da,Pl,Ru).iso`, with
  `Elf path: /dev_bdvd/PS3_GAME/USRDIR/EBOOT.BIN` inside it. A byte-patch to the standalone
  `C:\fifa17-ps3\EBOOT.ELF` above has **no effect on gameplay** — confirmed this session. Use
  RPCS3's Patch Manager (`patch.yml`, below) for any patch meant to actually change behavior.
- RPCS3 install root: `C:\rcps3` (note the transposed letters, that's the real path). Native/HLE
  log: `C:\rcps3\log\RPCS3.log` (several MB, grep it rather than pasting whole). TTY log (game's
  own stdout/stderr, much smaller): `C:\rcps3\log\TTY.log`.
- RPCS3 Patch Manager database: `C:\rcps3\patches\patch.yml` (**not** `C:\rcps3\patch.yml` — a
  previous session guessed wrong, user corrected it). Applies `be32` (and other) in-memory patches
  keyed by PPU hash + game/serial/version, regardless of which file RPCS3 actually booted from.
  See the "Patch Manager" writeup in the "Current blocker" section above for exact working YAML
  syntax and a confirmed-effective example patch.
- RPCS3 patch-manager config (separate from `patches/`): `C:\rcps3\config`
- RPCS3 virtual filesystem root: `C:\rcps3\dev_hdd0`. Game-data-check directories live under
  `C:\rcps3\dev_hdd0\game\<DIRNAME>\` (e.g. `BLUS31543` — already existed as an empty dir this
  session, which is why `cellGameDataCheck` reported "not found"; needs a valid `PARAM.SFO` inside
  to be recognized). Savedata (useful as a real PARAM.SFO reference/template for the PSF binary
  format) lives under `C:\rcps3\dev_hdd0\home\00000001\savedata\<TITLE_ID+NN>\PARAM.SFO`, e.g.
  `C:\rcps3\dev_hdd0\home\00000001\savedata\BLES022330000\PARAM.SFO`.
- Confirmed disc serial: **BLES02233** (European edition), version **01.00** — found via `Serial:`
  lines in `RPCS3.log`. Do not confuse with `UP0006-BLUS31543_00`/`UP0006-BLUS31593_00` strings
  seen in NP ticket/commerce API calls elsewhere in the log — those are unrelated internal EA
  network service identifiers, not the disc serial.

Reference implementation used for cross-checking tag names / command numbers / TDF field layouts:
`github.com/Mk0M/Impulsum14` — an open-source, from-scratch C# Blaze backend for **FIFA 14 PC**
(older Blaze 13 SDK, same TDF/SDK family). Treat it as a strong hint for *shape*, not as ground
truth for FIFA 17 specifically — SDK versions drift, and nothing in it has ever been confirmed
against real FIFA 17 wire traffic.

## Quick start (Windows 10/11)

1. Install Python 3.11+ and this folder somewhere convenient.
2. Open **PowerShell as Administrator** in the project folder (one-time setup):
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\tools\install_redirector.ps1
   ```
   (adds one hosts line and creates `certs/`; it does *not* touch your certificate store)
3. Every time you want to test: `powershell -ExecutionPolicy Bypass -File .\update_and_run.ps1`
   (pulls the latest server code and starts it in one step — see below).
4. Start FIFA 17 (via RPCS3) and go to an online mode.
5. Look in `logs/captures/` and paste the server's console log back for analysis.
6. When permanently done, undo the redirector changes:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\tools\remove_redirector.ps1
   ```

`update_and_run.ps1` (repo root) just does `git pull origin claude/new-session-ab3wdx` followed by
`python -m fifa17srv run`, run from the repo root via `$PSScriptRoot`. It exists because
`logs/`, `certs/`, and `config.json` are all gitignored, so there is never anything local worth
preserving — no need for `git add`/`commit`/`push` before pulling.

## Playing with a friend (later)

Bind to `0.0.0.0`, set `blaze_advertise_host` in `config.json` to an address your friend can
reach (public IP with a forwarded port, or a VPN such as Tailscale/ZeroTier/Hamachi), and have
your friend put that address in *their* hosts file for `winter15.gosredirector.ea.com`.

## Configuration

Create `config.json` next to this file to override any field of `fifa17srv/config.py` (the
dataclass there is the source of truth — read it directly, it's short and every field has a
comment explaining what it's for and why it exists), e.g.

```json
{ "bind_address": "0.0.0.0", "blaze_advertise_host": "26.1.2.3", "blaze_secure": false }
```

## Layout

```
fifa17srv/redirector.py   fake redirector (HTTPS)
fifa17srv/blaze.py        main Blaze protocol handler -- almost all protocol logic lives here
fifa17srv/probe.py        capture probe for the main Blaze port
fifa17srv/server.py       threaded server, capture logs, TLS-or-plaintext negotiation
fifa17srv/tls_hello.py    ClientHello parser (explains handshake failures)
fifa17srv/tdf.py          TDF codec
fifa17srv/analyze.py      capture inspection helper
fifa17srv/certs.py        throwaway local CA + server cert
fifa17srv/config.py       Config dataclass, all tunables with inline comments
tools/*.ps1               hosts/CA install and removal (Windows, run as admin)
update_and_run.ps1        one-command pull + run for repeat testing
```

## Security notes

* `-InstallCA` makes Windows trust a CA whose private key lives in `certs/`. Use it only if
  needed, keep `certs/` private, and run `remove_redirector.ps1` afterwards.
* The server is meant for localhost or a trusted friend. Do not expose it to the open internet.
* Do not download "FIFA private server" builds from random sites; build from source.

## Roadmap

1. ~~Capture redirector + first Blaze packets.~~ Done.
2. ~~Confirm frame format; implement PreAuth / Ping / Authentication responses.~~ Done.
3. ~~Get the client to a logged-in main menu with a local fake profile.~~ Done.
4. **Current:** get past the Online menu into an actual match (Cup Match freeze / Season blank
   screen — see "Current blocker" above).
5. Online friendlies: lobby, invite, matchmaking, session hand-off (P2P vs relayed TBD).
6. Docs of the protocol (clean-room notes, no EA code).

## Related work

Other people are reviving old FIFA online modes (mostly Ultimate Team); this project focuses on
friendlies. Contributions and shared captures are welcome. License: MIT.
