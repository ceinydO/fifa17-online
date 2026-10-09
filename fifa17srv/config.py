"""Configuration. Override any field by creating config.json in the project root."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, fields
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Config:
    # Hostname the game asks EA's redirector for (found in the FIFA 17 executable).
    redirector_host: str = "winter15.gosredirector.ea.com"
    redirector_port: int = 42230

    # Interface to listen on. Use "0.0.0.0" later if a friend should connect to you.
    bind_address: str = "127.0.0.1"

    # What we tell the game to connect to after the redirector step.
    blaze_advertise_host: str = "127.0.0.1"
    blaze_port: int = 10051
    # secure=False asks the client to speak plain TCP to the main server (much easier to
    # capture). If the game ignores it or refuses, switch to True.
    blaze_secure: bool = False

    # GameManager (patrz gamemgr.py). Wszystkie przelaczniki to eksperymenty -- zadnego nie zweryfikowano jeszcze
    # na zywym kliencie, kazdy mozna wylaczyc w config.json (zob. TEST_PLAN.md).
    gm_enabled: bool = True
    # Gra startuje w GSTA=INITIALIZING(1); PRE_GAME(130) idzie dopiero po finalizeGameCreation hosta.
    gm_deferred_pregame: bool = True
    # Tryb "faithful": host dostaje NotifyGameSetup tylko ze soba, zaproszony dopiero po finalizeGameCreation hosta
    # (jak przy dolaczaniu do istniejacej gry); False = obaj od razu w setupie.
    gm_faithful_flow: bool = True
    # Stan hosta w pierwszym NotifyGameSetup: 2 = ACTIVE_CONNECTING (klient sam zglasza updateMeshConnection i
    # dopiero wtedy dostaje ACTIVE_CONNECTED + NotifyPlayerJoinCompleted), 4 = ACTIVE_CONNECTED od razu.
    # Test na zywo 2026-10-09: z wartoscia 2 (i INITIALIZING) host po NotifyGameSetup zbindowal UDP 3659/9999,
    # ale NIE wyslal ani updateMeshConnection, ani finalizeGameCreation -- stary przebieg (PRE_GAME + host 4) wysylal.
    gm_host_initial_state: int = 4
    # Wariant pierwszego NotifyGameSetup dla hosta (patrz gamemgr.VARIANTS):
    #   0  = automatycznie: zaczyna od wariantu 1; jesli poprzednia proba hosta NIE doszla do finalizeGameCreation,
    #        kolejny createGame uzywa nastepnego wariantu (1 -> 2 -> 3 -> 1 ...); jesli doszla, wariant zostaje.
    #        Stan trzymany w state/gm_variant.json (przetrwa restart serwera).
    #   1..4 = wymuszony wariant, -1 = uzyj pojedynczych przelacznikow gm_deferred_pregame/gm_faithful_flow/
    #        gm_host_initial_state z tego pliku.
    gm_variant: int = 0
    # Stan dolaczajacego gracza po NotifyGameSetup: 2 = ACTIVE_CONNECTING (klient laczy sie z hostem P2P).
    gm_initial_player_state: int = 2
    # NotifyPlayerJoining dla hosta o dolaczajacym graczu.
    gm_send_player_joining: bool = True
    # Rozsylanie advanceGameState/setGameAttributes/setPlayerAttributes do wszystkich graczy gry.
    gm_followups: bool = True
    # Zaproszony gracz dostaje gre jako IndirectJoinGameSetupContext (IJGS) -- jedyna skladowa REAS, przy ktorej
    # SDK klienta bez wlasnego createGame/joinGame doprowadza dolaczenie do konca. False = DatalessSetupContext/JOIN.
    gm_indirect_join: bool = True
    # Tagi i numery skladowych unii REAS jak w FIFA 17 (DLSC/IJGS, numer = pozycja po tagu). False = ksztalt FIFA 14.
    gm_fifa17_union_tags: bool = True

    # Authentication::listEntitlements: jedna AKTYWNA pozycja na kazda zadana grupe (jak serwer FIFA 14), zamiast pustej
    # odpowiedzi; Messaging: skrzynka wiadomosci/zaproszen (messaging.py).
    serve_entitlements: bool = True
    serve_messaging: bool = True

    # Usluga POW / EASFC (patrz pow_stub.py): serwer podaje klientowi adresy w konfiguracji
    # FIFA_POW_URL / FIFA_POW_CONTENT_SERVER_URL i nasluchuje na tych portach (tylko nagrywa zadania).
    serve_pow_config: bool = True
    pow_port: int = 8094
    pow_content_port: int = 8080
    # Klucze FUT_RS4_BASE_URL / FUTDYNAMICMESSAGES_URL_BASE (EBOOT 0x4eab24, funkcja po zalogowaniu).
    # Gdy serwer ich nie poda, modul FUT buduje zle adresy ("ut/game/fifa17/..." -> DNS 'ut', "/messages"
    # -> DNS '') i te zapytania koncza sie bledem. Z tym przelacznikiem wskazuja na atrape pod pow_port.
    serve_fut_config: bool = True
    # Statystyki sezonowe (Play Season): grupy H2HSeasonalPlay / H2HPreviousSeasonalPlay / CoopSeasonalPlay_StatGroup
    # dostaja deskryptory statystyk i jeden wiersz wartosci dla gracza (EBOOT 0x507a84 sklada z nich dane sezonu;
    # z pustymi listami klient nie wysyla zdarzenia SeasonalPlayDownloadSuccess i ekran sezonu zostaje pusty).
    serve_seasonal_stats: bool = True

    # Util::postAuth / getTelemetryServer: adresy serwera ticker (gorny pasek) i telemetrii (patrz blaze.py).
    serve_post_auth: bool = True
    ticker_port: int = 6776
    ea_telemetry_port: int = 6767
    # Klucze OSDK_* (bufory peer, limity gier, timeouty) w fetchClientConfig, jak w dzialajacym serwerze FIFA 14.
    serve_osdk_core_defaults: bool = True

    cert_dir: str = "certs"
    log_dir: str = "logs/captures"
    # trwale ustawienia uzytkownikow (Util::userSettings*), np. FirstTimeFlag -- zeby rejestracja nie wracala
    state_dir: str = "state"
    persist_user_settings: bool = True
    cert_sig_hash: str = "sha256"  # "sha1" may be needed for very old TLS stacks
    cert_send_chain: bool = True  # False sends only the leaf cert, not leaf+CA
    idle_timeout: float = 60.0
    # Eksperyment diagnostyczny: podstawia w odpowiedziach unikalne nazwy hostow
    # (canary-*.test), zeby po logu RPCS3 ("DnsHook: DNS query for ...") zobaczyc,
    # ktore pola gra naprawde czyta. Domyslnie wylaczone.
    canary_hosts: bool = False
    # Test uporzadkowania mapy CONF: gdy True (i canary_hosts True), CONF w PreAuthResponse
    # zawiera TYLKO jeden klucz (nucleusConnect). Mapa z jednym elementem jest posortowana przy
    # kazdym komparatorze, wiec jesli klient wtedy znajdzie klucz, problemem byla kolejnosc.
    canary_single_conf: bool = False
    # Port lokalnej atrapy Nucleusa (HTTP). Adres bazowy dla gry ustawia patch pamieci (nucleusConnect).
    nucleus_port: int = 8081
    # Port atrapy telemetrii EA (rl.data.ea.com, pin-river.data.ea.com, ...), przekierowanych
    # przez IP/Hosts switches RPCS3 na 127.0.0.1. FEThread probuje sie tam laczyc po HTTPS co
    # ok. 60s; bez nasluchu na tym porcie polaczenie wisi ~1s w EINPROGRESS zanim dostanie
    # ENOTCONN, w kolko. Nasluch tutaj po prostu przyjmuje i natychmiast zamyka polaczenie
    # (RST przez SO_LINGER), zeby klient dostal szybka, czysta porazke.
    telemetry_port: int = 443
    # Bisekcja dekodowania PreAuthResponse po stronie klienta. Lista grup pol zlozonych, ktore maja byc wyslane,
    # rozdzielona przecinkami: cids (lista liczb, typ 7), cids4 (ta sama lista jako typ 4 LIST), conf, qoss.
    # Domyslnie cids4,conf,qoss: klient przyjmuje odpowiedz tylko wtedy, gdy CIDS jest lista typu 4 (cids4);
    # typ 7 (cids) powodowal odrzucenie calej PreAuthResponse. Pusty napis = tylko pola proste.
    preauth_groups: str = "cids4,conf,qoss"
    # Bisekcja odpowiedzi na Authentication::login: ktore czesci LoginResponse wysylac. sess = struktura SESS
    # (UserLoginInfo), pdtl = PersonaDetails wewnatrz SESS. Domyslnie wszystko (sess,pdtl); pusty napis = same flagi.
    login_groups: str = "sess,pdtl"
    # UserSessions::UserAuthenticated (0x7802/0x0008, ladunek UserSessionLoginInfo) po odpowiedzi na login.
    # Hipoteza: dopiero to powiadomienie tworzy lokalnego uzytkownika w menedzerze uzytkownikow SDK.
    send_user_authenticated: bool = True
    # Wartosci czasow w PreAuth CONF (klient je stosuje, format: liczba i przyrostek s). Do eksperymentow z limitem
    # czasu: gdy logout zmienia moment, wiadomo, ktory z nich go wywoluje.
    conf_request_timeout: str = "20s"
    conf_idle_timeout: str = "40s"
    # Eksperyment diagnostyczny (2026-09-26): drugi klient (RPCS3 #2, konto RPCN "playerB")
    # crashuje deterministycznie (PPU access violation, FEThread, offset 0x90 od null-wskaznika)
    # jakis czas po odpowiedzi na lookupUsersByPersonaNames -- ta odpowiedz idzie automatycznie
    # przy kazdym starcie (klient sam dopytuje o ostatnio widzianego gracza), wiec nie da sie tego
    # ominac z poziomu UI. Tresc odpowiedzi zmienialismy trzykrotnie (puste pola / kopia wlasnego
    # EXTB-EXID / usuniecie shotgun fallbacku) bez ZADNEGO wplywu na crash -- zawsze ten sam adres.
    # Ta flaga pozwala sprawdzic OSTATNIA rzecz w naszej kontroli: czy sama OBECNOSC jakiejkolwiek
    # odpowiedzi (zamiast calkowitego jej braku, jak inne nieobslugiwane komendy) jest wyzwalaczem.
    # True = odpowiadamy pusto (jak NIEOBSLUZONE), tak jakbysmy w ogole nie mieli handlera.
    lookup_users_empty_reply: bool = False
    # Przed odpowiedzia na lookupUsersByPersonaNames wyslij NotifyUserAdded dla kazdej obcej persony
    # z zapytania (te same ID co w odpowiedzi). Eksperyment 2026-10-08, patrz blaze.py.
    lookup_users_send_user_added: bool = True

    @property
    def cert_dir_path(self) -> Path:
        return ROOT / self.cert_dir

    @property
    def log_dir_path(self) -> Path:
        return ROOT / self.log_dir

    @property
    def user_settings_path(self) -> Path:
        return ROOT / self.state_dir / "user_settings.json"

    @property
    def gm_variant_path(self) -> Path:
        return ROOT / self.state_dir / "gm_variant.json"


def load_config() -> Config:
    cfg = Config()
    path = Path(os.environ.get("FIFA17SRV_CONFIG", ROOT / "config.json"))
    if path.is_file():
        data = json.loads(path.read_text(encoding="utf-8"))
        known = {f.name for f in fields(Config)}
        for key, value in data.items():
            if key in known:
                setattr(cfg, key, value)
    return cfg
