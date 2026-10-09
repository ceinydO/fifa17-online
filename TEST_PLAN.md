# Plan testu (nastepna sesja)

1. Oba komputery: `git pull`, uruchom serwer jak dotad. `config.json` ma zawierac tylko
   `{"idle_timeout":600,"bind_address":"0.0.0.0","blaze_advertise_host":"<twoj adres Radmin>"}`.
2. Zrob zaproszenie jak zwykle (host zaprasza kolege, "Online Friendlies").
3. Wyslij: log RPCS3 hosta i kolegi + log serwera (`logs/captures`).

## Jesli host nadal wisi na "Sending match invite..."
Zmieniaj po jednej rzeczy w `config.json` (sprawdz po kazdej zmianie):
- `"gm_faithful_flow": false` -- stary przebieg (obaj gracze od razu w NotifyGameSetup).
- `"gm_deferred_pregame": false` -- stary wariant (PRE_GAME od razu).
- `"gm_initial_player_state": 4` -- gracze od razu "polaczeni".
- `"gm_send_player_joining": false` -- bez NotifyPlayerJoining.
- `"gm_followups": false` -- bez zadnych dodatkowych powiadomien.

## Diagnostyka sieci (jesli nadal nic)
Wireshark na adapterze Radmin, filtr `udp.port == 3659 || udp.port == 9999`:
czy host/kolega w ogole wysyla pakiety do siebie po NotifyGameSetup?

## Baner "EAS FC servers are unavailable" (test 2026-10-09)
1. `git pull` + `.\update_and_run.ps1`. W bannerze startowym powinna byc linia `web (POW/FUT): ...:8094`.
   Zezwol Windows Firewall na port 8094 (i 8080, 6776 jesli kolega sie laczy).
2. Wejdz do menu glownego. W logu RPCS3 szukaj `DnsHook: DNS query for ut` -- po tej zmianie ma zniknac
   (zamiast tego `Attempting to connect on <adres Radmin>:8094`). Zapytanie z pusta nazwa moze zostac.
3. Sprawdz, czy baner sie zmienil. Przeslij: log serwera i pliki `logs/captures/pow_*.txt` (co FUT zadal).
4. Opcjonalnie (tylko kosmetyka): patch `tools/rpcs3_patch_easfc_banner.yml` -- instrukcja w pliku.
   Wylaczenie nowych kluczy w serwerze: `"serve_fut_config": false`.

## Play Season (test po zmianie `serve_seasonal_stats`)
1. `git pull` + `.\update_and_run.ps1`, wejdz w Play Season i odczekaj ~20 s.
2. Wyslij log serwera od "H2HSeasonalPlay": w logu ma byc `StatGroupResponse ... [70 deskryptorow statystyk sezonu]`
   i potem NOWE zadania (kolejna grupa statystyk albo `fetchClientConfig CFID='FIFA_H2H_SEASONALPLAY'`) -- to znaczy, ze ruszylo.
3. Jesli nadal cisza: `logs/captures/blaze_*.txt` + log RPCS3 (od momentu klikniecia).

## Test GameManager po przebudowie (2026-10-09)
Oba komputery: `git pull`, uruchom serwer, zrob zaproszenie Online Friendlies jak zwykle. Przeslij logi serwera
i RPCS3 obu stron. W logu serwera szukaj: `finalizeGameCreation`, `updateMeshConnection ... TCG=`, `NotifyGameSetup`.
W RPCS3 hosta: czy pojawia sie `sceNpBasicSendMessageGui` (zaproszenie) i czy UDP 3659/9999 idzie miedzy PC.
Przelaczniki (po jednym): `gm_fifa17_union_tags`, `gm_indirect_join`, `gm_host_initial_state` (4),
`gm_faithful_flow`, `gm_deferred_pregame`, `serve_entitlements`, `serve_messaging`.
