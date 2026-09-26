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

    cert_dir: str = "certs"
    log_dir: str = "logs/captures"
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
    # Eksperyment diagnostyczny (2026-09-26): drugi klient (RPCS3 #2, konto RPCN "reinoldo")
    # crashuje deterministycznie (PPU access violation, FEThread, offset 0x90 od null-wskaznika)
    # jakis czas po odpowiedzi na lookupUsersByPersonaNames -- ta odpowiedz idzie automatycznie
    # przy kazdym starcie (klient sam dopytuje o ostatnio widzianego gracza), wiec nie da sie tego
    # ominac z poziomu UI. Tresc odpowiedzi zmienialismy trzykrotnie (puste pola / kopia wlasnego
    # EXTB-EXID / usuniecie shotgun fallbacku) bez ZADNEGO wplywu na crash -- zawsze ten sam adres.
    # Ta flaga pozwala sprawdzic OSTATNIA rzecz w naszej kontroli: czy sama OBECNOSC jakiejkolwiek
    # odpowiedzi (zamiast calkowitego jej braku, jak inne nieobslugiwane komendy) jest wyzwalaczem.
    # True = odpowiadamy pusto (jak NIEOBSLUZONE), tak jakbysmy w ogole nie mieli handlera.
    lookup_users_empty_reply: bool = False

    @property
    def cert_dir_path(self) -> Path:
        return ROOT / self.cert_dir

    @property
    def log_dir_path(self) -> Path:
        return ROOT / self.log_dir


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
