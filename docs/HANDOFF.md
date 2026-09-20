# HANDOFF: projekt „FIFA 17 – mecze towarzyskie online” (przeniesienie na PS3 / RPCS3)

> Ten dokument jest przeznaczony dla nowego czatu z Claude'em. Wklej go jako pierwszą wiadomość
> (albo wgraj jako plik) i **dołącz `fifa17-friendlies.zip`**. Poprzedni czat nie jest dostępny,
> więc wszystko, co ustaliliśmy, jest tutaj. Data w chwili pisania: 20 września 2026.

## 0. Jak masz pracować z tym użytkownikiem (instrukcje dla Claude'a)

- Pisz **po polsku**, luźno i przyjaźnie (użytkownik pisze potocznie, np. „mordko”), krótko, konkretnie.
- Użytkownik pracuje na **Windows 10/11, PowerShell (jako administrator)**, Python **3.14**
  (`C:\Python314`), najnowszy pakiet `cryptography`. Dawaj gotowe komendy do skopiowania.
- Użytkownik programuje („umiem w wielu” językach), ale nie jest specjalistą od sieci/TLS.
- **Nie zakładaj niczego, co nie było sprawdzone.** W poprzednim czacie kilka moich założeń okazało się
  błędnych (np. opcja `--sha1` działała u mnie, a u użytkownika nie, bo nowsza `cryptography` odmawia
  podpisów SHA-1). Przed dostarczeniem kodu **przetestuj go w piaskownicy** i uczciwie oddziel
  „przetestowane” od „niezweryfikowane”.
- Szukaj w sieci, zanim coś stwierdzisz o RPCS3, protokole Blaze lub cudzych projektach.
- **Granice, których się trzymamy:** nie pomagamy w obchodzeniu DRM/Denuvo ani weryfikacji posiadania
  gry, nie pomagamy w zdobywaniu pirackich kopii gier ani firmware, nie dystrybuujemy plików EA ani
  gry w repozytorium. Zakładamy, że użytkownik ma **własną, legalną kopię** gry. Projekt jest
  open source (MIT), cel: zachowanie (preservation) wyłączonej funkcji online.

## 1. Cel

Użytkownik chce zagrać z kolegą **mecz towarzyski 1 na 1 przez internet w FIFA 17**, mimo że oficjalne
serwery EA nie działają (wyłączono je 14 lutego 2023). Plan: stworzyć **otwartoźródłowy emulator
serwera** (redirector + serwer Blaze) i uruchomić grę tak, żeby łączyła się z naszym serwerem.

## 2. Co ustaliliśmy (chronologicznie, skrót)

1. Serii FIFA już nie ma: obecnie **EA Sports FC** (FC 27 na PC od 25 września 2026, z Denuvo).
   Użytkownikowi FC nie odpowiada.
2. **Oficjalne serwery starszych FIFA są wyłączone:** FIFA 16/17 (14.02.2023), FIFA 18–21 na PC
   (6.11.2023), FIFA 22 (listopad 2024), FIFA 23 (30.10.2025).
3. **Stare części z trybem LAN/Direct IP** (przez Hamachi/GameRanger): FIFA 08/09/10 (Hamachi, Direct
   IP), FIFA 11 (tylko LAN; GameRanger, nie Hamachi). Nie sprawdzono w praktyce.
4. **Alternatywy dla samej gry z kolegą:** eFootball (darmowy), Rocket League, oraz zdalne granie
   lokalne przez **Parsec**/Steam Remote Play Together (FIFA 17 ma tryb 2 graczy na jednym PC; gra
   potrzebna tylko jednej osobie). To jest plan awaryjny i użytkownik o nim wie.
5. **Istniejące projekty społeczności** (patrz sekcja 6): impulsum (FIFA 13/14/17, skupiony na
   Ultimate Team, oparty na RPCS3), rplm10/FIFA17-Private-Server (bardzo wczesny, Python), Arcadia
   (emulator EA Plasma dla gier PS3).
6. Napisaliśmy **zestaw narzędzi discovery** (`fifa17-friendlies.zip`, sekcja 4) i uruchomiliśmy go z
   **wersją PC** FIFA 17. Wynik w sekcji 3.
7. Wniosek: **wersja PC jest zablokowana**, a impulsum robi to na **wersji PS3 w emulatorze RPCS3**.
   Decyzja użytkownika: **przenosimy projekt na FIFA 17 na PS3 uruchomioną w RPCS3.**

## 3. Wyniki eksperymentu z wersją PC (dane rzeczywiste)

Przekierowanie działało: wpis w pliku hosts `127.0.0.1 winter15.gosredirector.ea.com` sprawił, że gra
połączyła się z naszym serwerem na porcie **42230** (TLS). Zapis do hosts skryptem PowerShell
(`Set-Content`) wywalał błąd na komputerze użytkownika; pomogło `Add-Content` z wiersza poleceń.

**ClientHello wysłany przez grę PC (redirector):**
- pole wersji w nagłówku rekordu: 0x0300 (SSLv3), **realna wersja klienta: TLS 1.2**
- 8 zestawów szyfrów, **wyłącznie RSA key exchange**: `0x009D` (TLS_RSA_WITH_AES_256_GCM_SHA384),
  RSA_AES_128_GCM_SHA256, RSA_AES_256_CBC_SHA256, RSA_AES_128_CBC_SHA256, RSA_AES_256_CBC_SHA,
  RSA_AES_128_CBC_SHA, RSA_RC4_128_SHA, RSA_RC4_128_MD5
- rozszerzenia: 0 (SNI = `winter15.gosredirector.ea.com`) i 13 (signature_algorithms)
- To typowy silnik **ProtoSSL** EA.

**Reakcja gry:** serwer wysłał `ServerHello + Certificate + ServerHelloDone` (1719 B), a klient
**natychmiast zerwał połączenie (WinError 10054), bez alertu i bez ClientKeyExchange**.
Powtórzone: (a) certyfikaty SHA-256, (b) certyfikaty SHA-1 (potwierdzone `certutil`: `sha1RSA`),
(c) nasze CA zainstalowane w magazynie Root Windowsa. **Za każdym razem to samo.**

**Wniosek:** wersja PC waliduje certyfikat względem **listy CA wbudowanej w exe**. Obejście wymaga
zmiany pliku gry. Wersja PC FIFA 17 jest chroniona **Denuvo**, więc tego **nie robimy** (granica z
sekcji 0). Serwer negocjujący szyfry działa poprawnie: w piaskownicy handshake z klientem oferującym
ten sam zestaw (bez RC4, którego OpenSSL 3 nie ma) kończył się sukcesem (TLS 1.2, AES256-GCM-SHA384).

**Sprzątanie po testach (zapytaj użytkownika, czy zrobił):**
```powershell
certutil -delstore Root "FIFA17 Friendlies Local Dev CA"
(Get-Content C:\Windows\System32\drivers\etc\hosts) | Where-Object { $_ -notmatch "fifa17-friendlies" } | Set-Content C:\Windows\System32\drivers\etc\hosts
ipconfig /flushdns
```

## 4. Nasz kod (`fifa17-friendlies.zip`, MIT, Python 3.11+)

Uruchomienie: `python -m fifa17srv <certs|run|analyze|selftest>`; testy: `python -m fifa17srv selftest`
(**25/25 przechodzi**, sztuczni klienci, bez gry). Zależność: `cryptography`.

```
fifa17srv/config.py      konfiguracja (config.json nadpisuje pola): host redirectora, porty, secure...
fifa17srv/certs.py       lokalne CA + certyfikat serwera; podpis SHA-1 składany ręcznie (DER + RSA)
fifa17srv/server.py      Capture (logi .txt + surowe .bin), TracedTLS (handshake ręcznie przez
                         MemoryBIO, loguje każdy bajt i alerty), negotiate() (TLS albo plaintext),
                         Server (wątkowy TCP)
fifa17srv/redirector.py  fałszywy redirector: odpowiada XML `serverinstanceinfo` na getServerInstance
fifa17srv/probe.py       sonda głównego portu Blaze (10051): tylko przechwytuje, nic nie odpowiada
fifa17srv/tls_hello.py   parser ClientHello + podsumowanie rekordów TLS/alertów
fifa17srv/tdf.py         kodek TDF (Blaze) best-effort, NIEPOTWIERDZONY na prawdziwych danych
fifa17srv/analyze.py     analiza przechwyconego .bin (zgaduje długość nagłówka ramki)
tools/*.ps1              instalacja/usunięcie wpisu hosts (dla PC; przy RPCS3 niepotrzebne)
README.md, LICENSE, docs/HANDOFF.md
```

**Przetestowane w piaskownicy:** redirector przez TLS, sonda (plain/TLS/TLS1.0), rozpoznawanie alertów
i resetów, ClientHello, SHA-1, kodek TDF (round-trip), analiza offsetu nagłówka.
**Niezweryfikowane:** format XML redirectora dla FIFA 17 (oparty na innych grach Blaze), format
ramki (Fire/Fire2), poprawność kodowania tagów TDF na prawdziwych danych, wszystko o samej rozgrywce.

## 5. Nowy plan: FIFA 17 (PS3) w RPCS3

**Dlaczego to ma sens:** FIFA 17 wyszła też na PS3 i Xbox 360 (silnik „Impact”, nie Frostbite).
impulsum, według doniesień, wskrzesza FIFA 13/14/17 online **na RPCS3**; nie ma tam Denuvo,
a emulator pozwala przekierować hosty i dopasować zachowanie sieci. Arcadia (emulator EA Plasma)
pokazuje ten wzorzec: w RPCS3 włącza się sieć, ustawia pole **„IP/Hosts switches”** w formacie
`host1=ip&&host2=ip` (zamiast edycji pliku hosts), a problem z ProtoSSL w starszych grach
rozwiązuje się znaną luką (opis: `Aim4kill/Bug_OldProtoSSL`; **nie wiadomo**, czy dotyczy FIFA 17 PS3).

**Etapy (propozycja):**
0. **Wymagania użytkownika** (zapytaj!): czy ma/ może mieć **PS3-ową kopię FIFA 17** (płyta lub
   cyfrowa) i jak ją zgrać (RPCS3 quickstart opisuje zgrywanie własnych gier; zwykle wymaga PS3 lub
   kompatybilnego napędu); firmware PS3 pobiera się z oficjalnej strony Sony; specyfikacja PC
   (CPU/RAM/GPU) i czy kolega ma to samo. Sprawdź na liście kompatybilności RPCS3, jak chodzi FIFA 17.
1. Gra bootuje offline w RPCS3 (pomoc wg oficjalnej dokumentacji RPCS3).
2. Konfiguracja sieci w RPCS3 (network status, IP/Hosts switches). **Ustal prawdziwe nazwy hostów**,
   z którymi łączy się wersja PS3 (logi RPCS3 lub Wireshark); mogą różnić się od PC
   (`winter15.gosredirector.ea.com` było nazwą z wersji PC).
3. Uruchom nasz toolkit (`run`), zobacz w logach czy handshake TLS przechodzi. **TracedTLS pokaże
   dokładnie, co robi klient.** Jeśli klient PS3 odrzuca certyfikat, zbadać lukę ProtoSSL / ustawienia
   RPCS3 (bez ruszania ochron DRM; PS3 ich tu nie ma).
4. Zdekoduj protokół (PreAuth, Ping, Authentication...), zaimplementuj odpowiedzi do „zalogowanego
   menu głównego”, potem lobby i **mecz towarzyski 1v1**. Ustalić, czy sam mecz idzie P2P czy przez serwer.
5. Gra z kolegą: obaj w RPCS3, hosty wskazują na komputer gospodarza (publiczne IP z przekierowaniem
   portów albo VPN: Tailscale/ZeroTier/Hamachi); `bind_address` = `0.0.0.0`, `blaze_advertise_host` =
   adres osiągalny dla kolegi.
6. Dokumentacja protokołu (clean-room, bez kodu EA), publikacja na GitHubie.

**Rzeczy do sprawdzenia na początku nowego czatu (web search):** aktualna konfiguracja sieci w RPCS3
(IP/Hosts switches, RPCN), kompatybilność FIFA 17 z RPCS3, jak dokładnie robi to Arcadia, jakich
hostów używa FIFA 17 PS3, opis protokołu Blaze/Fire/Fire2 (repozytoria PocketRelay, Arcadia,
BFBC2_MasterServer), aktualny stan projektu impulsum.

## 6. Odnośniki (znalezione w poprzednim czacie)

- https://github.com/rplm10/FIFA17-Private-Server (wczesny projekt, Python, FUT, README opisuje
  redirector `winter15.gosredirector.ea.com`, port 42230, Blaze na 10051)
- Arcadia: github.com/valters-tomsons/arcadia (wiki; emulator EA Plasma, PS3/RPCS3, IP/Hosts switches)
- `Aim4kill/Bug_OldProtoSSL` (wspomniany w Arcadii; nie udało się go pobrać)
- https://soccergaming.com/old-fifa-games-like-fifa-13-could-be-brought-back-to-life/
- https://www.generationamiga.com/2026/07/19/fifa-13-fifa-14-and-fifa-17-could-get-working-servers-again/
- https://www.youtube.com/watch?v=eW5Hiyh_DVA (FIFA 13 UT Preservation Project on RPCS3; w opisie
  serwer Discord, **nie potwierdzono**, że to ta sama grupa co impulsum)
- impulsum: Discord (szukać po nazwie „impulsum”; sprawdzić, czy to oficjalny serwer), planują też
  zbieranie przechwyconych pakietów; skupiają się na FUT, nie wiadomo nic o meczach towarzyskich.

## 7. Pierwsza wiadomość, którą powinien wysłać nowy czat

1. Krótko potwierdź, że znasz kontekst (jednym zdaniem).
2. Zadaj **maks. 3 pytania:** (a) czy użytkownik ma wersję PS3 FIFA 17 i jak może ją zgrać,
   (b) specyfikacja PC (i czy kolega ma podobny), (c) czy posprzątał hosts i CA po testach z PC.
3. W międzyczasie sam zrób research z sekcji 5 i podaj plan działania z konkretnymi krokami.
