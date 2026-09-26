"""Handler Blaze dla portu 10051 -- w miejsce probe.py, ktory tylko nagrywal.

FORMAT NAGLOWKA POTWIERDZONY (nie zgadywany): odtworzony ze zrodel projektu
grid-leak/blaze (serwer Blaze dla Mirror's Edge Catalyst, ten sam rok 2016 co
FIFA17, ten sam SDK Blaze 15.1.x -- ich SVER "Blaze 15.1.1.0.5" niemal
dokladnie odpowiada BSDK "15.1.1.0.0" ktore FIFA17 wysyla w swoim CINF).

Uklad 16-bajtowego naglowka (sprawdzony na WSZYSTKICH czterech realnych
przechwytach preAuth z FIFA17, zero rozbieznosci):

    offset  0-3  payload_size   u32 BE
    offset  4-5  metadata_size  u16 BE (u nas zawsze 0 -- brak sekcji metadata)
    offset  6-7  component      u16 BE
    offset  8-9  command        u16 BE
    offset 10-12 msg_num        3 bajty BE  (NIE 2 -- to bylo zrodlem wczesniejszych
                                             pomylek; rosnie z kazda proba polaczenia
                                             w tej samej sesji RPCS3: 0,0,1,2...)
    offset 13    msg_type << 5  (Message=0, Reply=1, Notification=2, ErrorReply=3,
                                 Ping=4, PingReply=5)
    offset 14    options        zawsze 0 w naszych przechwytach
    offset 15    reserved       zawsze 0 w naszych przechwytach

KLUCZOWE: odpowiedz (Reply) ma DOKLADNIE TE SAME component/command/msg_num co
zadanie, na ktore odpowiada -- zmienia sie TYLKO msg_type na Reply(1). To
odtwarza wzorzec `Fire2Frame::reply()` z grid-leak/blaze.
"""
from __future__ import annotations

import hashlib
import socket
import ssl
import threading
import time

from . import tdf
from .config import Config
from .qos import QOS_PORT
from .server import Capture, negotiate

_LOOPBACK_IP_U32 = int.from_bytes(socket.inet_aton("127.0.0.1"), "big")  # 2130706433

UTIL_COMPONENT = 0x0009
PRE_AUTH_COMMAND = 0x0007
PING_COMMAND = 0x0002
FETCH_CLIENT_CONFIG_COMMAND = 0x0001
AUTH_COMPONENT = 0x0001
GET_ACCOUNT_COMMAND = 0x001E   # Authentication::getAccount -- nazwa z tabeli komend w EBOOT (0x00C778CC)
LOGIN_COMMAND = 0x000A      # Authentication: LoginRequest {AUTH, EXTB, EXTI} (odczytane z EBOOT: typ 0x025490A0)

# Identyfikatory zwracane w LoginResponse (wartosci lokalne, wymyslone -- klient ma tylko dostac spojne liczby).
LOCAL_USER_ID = 1000000001
LOCAL_PERSONA_ID = 1000000002
LOCAL_SESSION_KEY = "fifa17-local-session-key-0001"
LOCAL_EMAIL = "player@fifa17.local"
PLATFORM_PS3 = 2            # ta sama wartosc co CPFT w PreAuth (ClientPlatformType dla PS3)
PERSONA_STATUS_ACTIVE = 1

USER_SESSIONS_COMPONENT = 0x7802   # UserSessions
NOTIFY_USER_SESSION_EXTENDED_DATA_UPDATE = 0x0001
NOTIFY_USER_ADDED = 0x0002
NOTIFY_USER_UPDATED = 0x0005
NOTIFY_USER_AUTHENTICATED = 0x0008   # nazwa 'UserAuthenticated' z tabeli powiadomien komponentu 0x7802 (0x00C837E4)
USER_FLAG_ONLINE = 0x1      # UserDataFlags::Online
UPDATE_NETWORK_INFO_COMMAND = 0x0014
# UserSessions::lookupUsersByPersonaNames -- nazwa komendy i typ zadania (Blaze::LookupUsersByPersonaNamesRequest)
# potwierdzone w EBOOT (0x0209F4D9 / referencja 0x00C81FC4). Pola zadania (NASP, PLST) zgadzaja sie z
# przechwyconym ruchem. Typ odpowiedzi zidentyfikowany jako Blaze::UserDataResponse (0x0209FED0, ref 0x00C830B0),
# ale nazwa jego pola-listy NIE zostala potwierdzona w kodzie (funkcja pod referencja tylko rejestruje typ w
# tabeli refleksji, nie buduje odpowiedzi) -- uzywamy tagu "USER" (lista UserIdentification) przez analogie do
# NotifyUserAdded, ktory uzywa tego samego ksztaltu struktury pod tym samym tagiem singularnym.
LOOKUP_USERS_BY_PERSONA_NAMES_COMMAND = 0x0032

# Blaze::Stats -- komponent 0x0007, potwierdzony na drucie (klient wysyla go zaraz po lookupUsersByPersonaNames,
# gdy wchodzi w Cup Match/Seasons). Namiary na dokladny uklad komend i typow pochodza z Impulsum14
# (github.com/Mk0M/Impulsum14, ten sam ekosystem SDK co nasz projekt), ktory ma pelna, dzialajaca implementacje
# tego komponentu -- numeracja komend (getStatGroup=4, getKeyScopesMap=15, getStatsByGroupAsync=16) zgadza sie
# z tym, co realnie przyszlo od klienta (0x04/0x0F/0x10), a pola GetStatsByGroupRequest (EID/NAME/PCTR/POFF/
# PTYP/TIME/VID) pasuja do przechwyconego zadania.
STATS_COMPONENT = 0x0007
GET_STAT_GROUP_COMMAND = 0x0004                    # StatsComponentCommand.getStatGroup = 4
GET_KEY_SCOPES_MAP_COMMAND = 0x000F                # StatsComponentCommand.getKeyScopesMap = 15
GET_STATS_BY_GROUP_ASYNC_COMMAND = 0x0010          # StatsComponentCommand.getStatsByGroupAsync = 16
GET_STATS_ASYNC_NOTIFICATION = 0x0032              # StatsComponentNotification.GetStatsAsyncNotification = 50

# Komponent 0x08C9 (2249) -- nazwa NIEPOTWIERDZONA, nie ma go w Impulsum14 (prawdopodobnie FIFA-specific).
# Klient wysyla 0x0001 i 0x0002 (oba zero-payloadowe) zaraz po getAccount, przed lookupUsersByPersonaNames,
# i po tym NIC wiecej nie wysyla poza pingami -- to najbardziej prawdopodobny winowajca zamrozenia na
# "Loading Seasons information...". Sesja 2026-09-25: sledzenie w Ghidrze funkcji FUN_009a3590 (tabela
# nazw komend "GetCurrentSeasonID"/"StartSeason"/...) doprowadzilo do tabeli handlerow pod 0x024cb1a4,
# ale okazala sie to byc lokalna tabela akcji skryptowych trybu kariery (Career Mode state machine), NIE
# siec Blaze -- wiazanie command=1 -> GetCurrentSeasonID jest wiec TYLKO HIPOTEZA oparta na kolejnosci w
# tabeli nazw, nie na potwierdzonym kodzie sieciowym. Ponizej: eksperyment empiryczny zamiast dalszej
# statycznej analizy -- wysylamy niepusta odpowiedz z kilkoma kandydatami na tag naraz (TDF ignoruje
# nieznane tagi) i sprawdzamy czy to cokolwiek zmienia w zachowaniu klienta.
SEASONS_COMPONENT = 0x08C9
GET_CURRENT_SEASON_ID_COMMAND = 0x0001
START_SEASON_COMMAND = 0x0002
_SEASON_ID_TAG_CANDIDATES = ("SEAS", "SNUM", "SIID", "CSID", "ID  ", "STAT")

# Blaze::GameManager -- komponent 0x0004, potwierdzony w Impulsum14 (Components/GameManagerBase.json,
# "Id": 4) I na drucie (realny przechwyt: klient po ekranie "Play Match" wysyla component=0x0004
# command=0x0001, ktore u nas wpadalo w ogolny fallback i dostawalo pusta odpowiedz -- stad zawieszenie
# na "Sending match invite and creating a game session"). createGame = method Id 1 (CreateGameRequest/
# CreateGameResponse), NotifyGameSetup = notification Id 20 (0x14) -- oba potwierdzone w tym samym pliku.
GAME_MANAGER_COMPONENT = 0x0004
CREATE_GAME_COMMAND = 0x0001
NOTIFY_GAME_SETUP = 0x0014

# Rejestr polaczonych graczy (nazwa persony -> stream/lock/adres), potrzebny zeby createGame wywolane
# w watku jednego gracza moglo wypchnac powiadomienie NotifyGameSetup do watku DRUGIEGO gracza --
# do tej pory kazde polaczenie bylo obslugiwane w calkowitej izolacji (zmienna `identity` byla lokalna
# dla handle()). send_lock chroni WSZYSTKIE zapisy na danym streamie (wlasne odpowiedzi tego polaczenia
# ORAZ asynchroniczne powiadomienia wpychane z watku innego gracza), zeby ramki nigdy sie nie przeplotly.
_PLAYERS_LOCK = threading.Lock()
_PLAYERS: dict = {}   # nazwa persony -> {"stream", "send_lock", "ip", "port"}
_GAMES_LOCK = threading.Lock()
_next_game_id = [1]


def _register_player(name: str, stream, send_lock: threading.Lock) -> None:
    with _PLAYERS_LOCK:
        _PLAYERS[name] = {"stream": stream, "send_lock": send_lock, "ip": 0, "port": 0}


def _unregister_player(name: str) -> None:
    with _PLAYERS_LOCK:
        _PLAYERS.pop(name, None)


def _update_player_network(name: str, ip: int, port: int) -> None:
    with _PLAYERS_LOCK:
        entry = _PLAYERS.get(name)
        if entry is not None:
            entry["ip"], entry["port"] = ip, port


def _send_frame(name: str, frame: bytes, cap: Capture, label: str) -> bool:
    """Wypycha ramke (powiadomienie) do INNEGO gracza, z dowolnego watku."""
    with _PLAYERS_LOCK:
        entry = _PLAYERS.get(name)
    if entry is None:
        return False
    try:
        with entry["send_lock"]:
            entry["stream"].sendall(frame)
        cap.data("S->C", frame)
        cap.note(f"-> wysylam {label} do {name!r}, {len(frame)-HDR_LEN}B payloadu")
        return True
    except OSError as exc:
        cap.note(f"-> blad wysylki {label} do {name!r}: {exc}")
        return False


PERSONA_NAMESPACE = "cem_ea_id"
DEFAULT_LOCALE = 1701724754        # 'enBR' -- taka wartosc klient wyslal w LANG w PreAuth
AUTH_COMPONENT = 0x0001

HDR_LEN = 16
# Adres serwera QoS podawany klientowi w PreAuth. Klient laczy sie tam przez TLS (SNI = ten adres), wiec uzywamy tej
# samej nazwy co przekierowanie: RPCS3 tlumaczy ja na 127.0.0.1 (IP swap list), a certyfikat serwera jest
# wystawiony wlasnie na te nazwe, czyli dokladnie ta sama sciezka, ktora dziala przy redirectorze.
QOS_HOST = "winter15.gosredirector.ea.com"

MSG_MESSAGE = 0     # request (klient -> serwer)
MSG_REPLY = 1       # odpowiedz (serwer -> klient) -- to jest to, czego uzywamy
MSG_NOTIFICATION = 2
MSG_ERROR_REPLY = 3
MSG_PING = 4
MSG_PING_REPLY = 5


def parse_header(hdr: bytes):
    """Zwraca (payload_size, metadata_size, component, command, msg_num, msg_type, options, reserved)."""
    payload_size = int.from_bytes(hdr[0:4], "big")
    metadata_size = int.from_bytes(hdr[4:6], "big")
    component = int.from_bytes(hdr[6:8], "big")
    command = int.from_bytes(hdr[8:10], "big")
    msg_num = int.from_bytes(hdr[10:13], "big")
    msg_type = hdr[13] >> 5
    options = hdr[14]
    reserved = hdr[15]
    return payload_size, metadata_size, component, command, msg_num, msg_type, options, reserved


def build_header(payload_size: int, component: int, command: int, msg_num: int,
                  msg_type: int = MSG_REPLY, metadata_size: int = 0,
                  options: int = 0, reserved: int = 0) -> bytes:
    if msg_num > 0xFFFFFF:
        raise ValueError("msg_num nie miesci sie w 3 bajtach")
    return (
        payload_size.to_bytes(4, "big")
        + metadata_size.to_bytes(2, "big")
        + component.to_bytes(2, "big")
        + command.to_bytes(2, "big")
        + msg_num.to_bytes(3, "big")
        + bytes([(msg_type & 0x7) << 5])
        + bytes([options])
        + bytes([reserved])
    )


def build_reply(component: int, command: int, msg_num: int, payload: bytes) -> bytes:
    """Odpowiedz mirroruje component/command/msg_num zadania, zmienia tylko typ na Reply."""
    hdr = build_header(len(payload), component, command, msg_num, msg_type=MSG_REPLY)
    return hdr + payload


def login_identity(request_fields):
    """Z zadania login: (nazwa persony z EXTB, EXTI, surowy EXTB)."""
    ext_id, name, blob = 0, "player", b""
    for tag, _t, v in request_fields:
        if tag == "EXTI" and isinstance(v, int):
            ext_id = v
        elif tag == "EXTB" and isinstance(v, (bytes, bytearray)):
            blob = bytes(v)
            txt = blob.split(b"\0", 1)[0].decode("utf-8", "replace")
            if txt:
                name = txt
    return name, ext_id, blob


def build_notification(component: int, command: int, payload: bytes) -> bytes:
    """Asynchroniczne powiadomienie serwer -> klient (msg_type=2, msg_num=0)."""
    return build_header(len(payload), component, command, 0, msg_type=MSG_NOTIFICATION) + payload


def _persona_user_id(name: str) -> int:
    """Stabilny falszywy UID dla persony INNEJ niz lokalnie zalogowana sesja (multi-gracz, np. dwie
    instancje RPCS3 polaczone przez RPCN) -- unika kolizji z LOCAL_USER_ID/LOCAL_PERSONA_ID, ktore sa
    zarezerwowane dla wlasnej tozsamosci polaczonej sesji. Bez tego kazdy gracz dostawal identyczny
    BlazeId, wiec np. lookupUsersByPersonaNames('odyniec') wykonane przez sesje 'reinoldo' zwracalo
    wpis z tym samym ID co sesja reinoldo -- klient wykrywal sprzecznosc (ten sam BlazeId, inna nazwa
    persony niz wlasna) i padal (rozlaczenie ~10-20s po odpowiedzi)."""
    h = int(hashlib.sha1(name.encode("utf-8")).hexdigest(), 16)
    return 2000000000 + (h % 1000000000)


def identity_for_persona(name: str, own_identity):
    """Zwraca (nazwa, ext_id, blob, uid, persona_id) dla podanej nazwy persony -- jesli to wlasna
    tozsamosc biezacej sesji, uzywa prawdziwych LOCAL_USER_ID/LOCAL_PERSONA_ID i EXTI/EXTB z loginu;
    w przeciwnym razie generuje spojny, unikalny falszywy identyfikator (patrz _persona_user_id).

    UWAGA (crash po poprawce kolizji BlazeId): pierwsza wersja zwracala tu ext_id=0, blob=b"" dla
    kazdej persony innej niz wlasna. To odblokowalo dawny problem (kolizja BlazeId -> rozlaczenie),
    ale ujawnilo NOWY: PPU access violation na FEThread (czytanie adresu 0x90 -- niski, stale
    przesuniecie typowe dla odczytu pola ze struktury spod pustego/null wskaznika). EXBB (EXTB z
    loginu) to najwyrazniej struktura o ustalonym ksztalcie (np. NpId), ktora klient parsuje zakladajac
    minimalny rozmiar; pusty blob (0 bajtow) daje wskaznik null/za krotki bufor, wiec odczyt pola w
    stalym przesunieciu (tu akurat 0x90) pada. Serwer nie zna PRAWDZIWEGO EXTB/EXTI drugiego gracza
    (kazde polaczenie jest obslugiwane osobno, bez wspoldzielonego stanu sesji), wiec jako
    najbezpieczniejszy placeholder o poprawnym ksztalcie/rozmiarze uzywamy blobu/ext_id WLASNEJ
    sesji (own_blob/own_ext_id) zamiast zera/pustego bajtow -- klient i tak juz poprawnie parsuje ten
    ksztalt (bo to dokladnie to, co sam wyslal w swoim loginie), wiec nie powinien juz czytac poza
    buforem, nawet jesli tresc semantycznie nie nalezy do szukanej persony."""
    own_name, own_ext_id, own_blob = own_identity
    if name == own_name:
        return name, own_ext_id, own_blob, LOCAL_USER_ID, LOCAL_PERSONA_ID
    uid = _persona_user_id(name)
    return name, own_ext_id, own_blob, uid, uid + 1


def build_user_identification(identity, uid: int = LOCAL_USER_ID, persona_id: int = LOCAL_PERSONA_ID):
    """Blaze::UserIdentification (9 pol, ksztalt potwierdzony w NotifyUserAdded z realnego ruchu)."""
    name, ext_id, blob = identity
    return [
        ("AID ", tdf.VARINT, uid),
        ("ALOC", tdf.VARINT, DEFAULT_LOCALE),
        ("EXBB", tdf.BLOB, blob),
        ("EXID", tdf.VARINT, ext_id),
        ("ID  ", tdf.VARINT, uid),
        ("NAME", tdf.STRING, name),
        ("NASP", tdf.STRING, PERSONA_NAMESPACE),
        ("ORIG", tdf.VARINT, 0),
        ("PIDI", tdf.VARINT, persona_id),
    ]


def build_user_added(identity) -> bytes:
    """NotifyUserAdded {DATA: UserSessionExtendedData, USER: UserIdentification} (0x7802/0x0002).
    Definicje pol odczytane z EBOOT. DATA zawiera tylko nieustawiona unie ADDR (jak w logach SDK innych gier)."""
    data = [("ADDR", tdf.UNION, (tdf.UNION_UNSET, None))]
    payload = tdf.encode([("DATA", tdf.STRUCT, data), ("USER", tdf.STRUCT, build_user_identification(identity))])
    return build_notification(USER_SESSIONS_COMPONENT, NOTIFY_USER_ADDED, payload)


def build_user_data(identity, uid: int = LOCAL_USER_ID):
    """Blaze::UserManager::UserData -- INNY typ niz UserIdentification. Znaleziony sesja 9 poprzez
    find_tdf_members.py przeszukujac tabele refleksji pod katem pol UserIdentification: zaraz PO tej
    tabeli w EBOOT (0x0254DD4C-0x0254DE04) siedzi OSOBNA tabela pol z dokladnie 6 tagami w tej kolejnosci:
    EXBB (externalBlob), EXID (externalId), ID (blazeId), NAME (name), NASP (personaNamespace),
    FLGS (statusFlags) -- FLGS potwierdzone liczbowo (enc('FLGS')<<8 == 0x9AC9F300, dokladnie ta wartosc
    w danych). To mniejszy ksztalt niz UserIdentification (brak AID/ALOC/ORIG/PIDI) i jest silnym
    kandydatem na prawdziwy typ elementu listy w odpowiedzi lookupUsersByPersonaNames -- w przeciwienstwie
    do UserIdentification (uzywany tylko w NotifyUserAdded), tej tabeli nigdy nie probowalismy wyslac."""
    name, ext_id, blob = identity
    return [
        ("EXBB", tdf.BLOB, blob),
        ("EXID", tdf.VARINT, ext_id),
        ("ID  ", tdf.VARINT, uid),
        ("NAME", tdf.STRING, name),
        ("NASP", tdf.STRING, PERSONA_NAMESPACE),
        ("FLGS", tdf.VARINT, USER_FLAG_ONLINE),
    ]


def build_lookup_users_response(component: int, command: int, msg_num: int, own_identity,
                                 persona_names) -> bytes:
    """Odpowiedz na UserSessions::lookupUsersByPersonaNames (typ zadania Blaze::LookupUsersByPersonaNamesRequest
    potwierdzony w EBOOT; typ odpowiedzi Blaze::UserDataResponse tez potwierdzony, ale nazwa i ksztalt
    pola-listy przez dlugi czas NIE -- funkcja pod jedynym innym odwolaniem do tablicy pol tylko
    rejestrowala typ w tabeli refleksji, nie budowala odpowiedzi.

    Sesja 9 cz.1: sprawdzono 4 kandydatow na tag jako tdf.LIST z UserIdentification (USER/VALU/DATA/LIST)
    oraz USER jako pojedynczy STRUCT -- zaden nie dal widocznego postepu.

    Sesja 9 cz.2: sledzenie miejsca wywolania RPC (find_requests.py -> disasm_range.py) doprowadzilo do
    nowo alokowanego obiektu-odpowiedzi, ktorego deskryptor klasy w danych ELF (find_tdf_members.py z
    tagami UserIdentification) ujawnil DRUGA, ODDZIELNA tabele pol zaraz obok: Blaze::UserManager::UserData
    (EXBB/EXID/ID/NAME/NASP/FLGS, patrz build_user_data) -- inny typ niz UserIdentification, nigdy dotad
    nie wyslany.

    Sesja 9 cz.3: reczny przeglad open-source projektu Impulsum14 (github.com/Mk0M/Impulsum14 --
    backend FIFA 14 PC, ten sam rodzaj SDK -- EATDF/ProtoFire/Blaze.Core, tylko starsza wersja
    Blaze 13 zamiast naszej 15.1.x) pokazal PELNA, dzialajaca definicje Blaze::UserDataResponse:
    pole-lista NIE nazywa sie USER (ani VALU/DATA/LIST) -- nazywa sie ULST ("UserDataList",
    tag 0xD6CCF400), co potwierdza rowniez policzony enc('ULST')<<8. To bylo do znalezienia w kodzie
    innej gry z tego samego ekosystemu, a nie do wygrzebania w disasemblerze -- ten tag ma NAJWYZSZY
    priorytet, bo pochodzi z dzialajacego, potwierdzonego kodu serwera Blaze innej gry EA z tej samej
    rodziny SDK, nie z domyslu.

    Wysylamy WYLACZNIE ULST jako LIST<UserData> (potwierdzona nazwa pola z Impulsum14 + potwierdzony
    w EBOOT ksztalt struktury).

    USUNIETO (2026-09-26) shotgun fallback pod tagami USER/VALU/DATA/LIST z UserIdentification --
    zalozenie "TDF ignoruje nieznane tagi, wiec to bezpieczne" okazalo sie falszywe w multi-gracz
    scenariuszu: RPCS3 log pokazal deterministyczny PPU access violation na FEThread, zawsze pod
    TYM SAMYM adresem (0x2ef598, instrukcja `lwz r3,0x90(r31)` -- odczyt pola pod stalym przesunieciem
    z obiektu, ktorego wskaznik (r31) jest null/zly), niezalezny od tresci EXBB/EXID ktore probowalismy
    naprawiac wczesniej. Skoro crash jest identyczny przy dwoch roznych tresciach danych, ale WYSTEPUJE
    dopiero odkad odpowiedz zawiera dane INNEGO gracza (nie tylko wlasna tozsamosc), najbardziej
    prawdopodobnym podejrzanym staja sie redundantne pola USER/VALU/DATA/LIST -- kod klienta
    (SDK Blaze/reflection) mogl brac jeden z tych tagow jako sygnal do zupelnie innej sciezki
    przetwarzania (np. rejestracja obiektu sesji/kontaktu) niz przy odpowiedzi zawierajacej tylko
    wlasna tozsamosc, i tworzyc/uzywac obiekt z nieprawidlowymi/pustymi polami. README juz potwierdzal
    ULST jako jedyne zweryfikowane, potrzebne pole -- shotgun byl zabezpieczeniem "na wszelki wypadek"
    z czasow zanim to potwierdzono, teraz jest tylko zbednym ryzykiem.

    KRYTYCZNA POPRAWKA (multi-gracz, dwie instancje RPCS3 polaczone przez RPCN): wczesniej ta funkcja
    ZAWSZE zwracala wlasna tozsamosc biezacej sesji (identity) z tym samym sztywnym LOCAL_USER_ID,
    ignorujac pole PLST z zadania (liste FAKTYCZNIE szukanych nazw person). Gdy gracz A szukal gracza B,
    dostawal z powrotem dane gracza A pod tym samym BlazeId co jego wlasna sesja -- SDK Blaze wykrywalo
    sprzecznosc (ten sam BlazeId, inna nazwa niz wlasna) i klient sie rozlaczal ~10-20s po odpowiedzi.
    Teraz budujemy wpis dla KAZDEJ nazwy z PLST osobno: dla wlasnej nazwy uzywamy prawdziwej tozsamosci
    (LOCAL_USER_ID), dla kazdej innej -- stabilnego, unikalnego falszywego ID (patrz identity_for_persona/
    _persona_user_id), zeby uniknac kolizji identyfikatorow miedzy graczami."""
    if not persona_names:
        persona_names = [own_identity[0]]
    user_data_structs = []
    for name in persona_names:
        p_name, p_ext_id, p_blob, uid, persona_id = identity_for_persona(name, own_identity)
        user_data_structs.append(build_user_data((p_name, p_ext_id, p_blob), uid))
    fields = [("ULST", tdf.LIST, (tdf.STRUCT, user_data_structs))]
    payload = tdf.encode(fields)
    return build_reply(component, command, msg_num, payload)


def build_user_authenticated(identity) -> bytes:
    """UserSessions::UserAuthenticated (0x7802/0x0008). Numer wynika z tabeli nazw powiadomien komponentu w EBOOT
    (id 8 -> 'UserAuthenticated'); ladunek zakladam jako UserSessionLoginInfo (16 pol, definicja z EBOOT) --
    to jest HIPOTEZA (nazwa 'UserAuthenticated' sasiaduje z typem, ale wiazania nie potwierdzono).
    Pole CGID (ObjectId) pomijam: brakujace pola dekodowane sa jako wartosci domyslne."""
    name, ext_id, _blob = identity
    now = int(time.time())
    fields = [
        ("1CON", tdf.VARINT, 0),
        ("ALOC", tdf.VARINT, DEFAULT_LOCALE),
        ("BUID", tdf.VARINT, LOCAL_USER_ID),
        ("DSNM", tdf.STRING, name),
        ("FRST", tdf.VARINT, 0),
        ("KEY ", tdf.STRING, LOCAL_SESSION_KEY),
        ("LAST", tdf.VARINT, now),
        ("LLOG", tdf.VARINT, now),
        ("MAIL", tdf.STRING, LOCAL_EMAIL),
        ("NASP", tdf.STRING, PERSONA_NAMESPACE),
        ("PID ", tdf.VARINT, LOCAL_PERSONA_ID),
        ("PLAT", tdf.VARINT, PLATFORM_PS3),
        ("UID ", tdf.VARINT, LOCAL_USER_ID),
        ("USTP", tdf.VARINT, 0),
        ("XREF", tdf.VARINT, ext_id),
    ]
    return build_notification(USER_SESSIONS_COMPONENT, NOTIFY_USER_AUTHENTICATED, tdf.encode(fields))


def build_user_updated() -> bytes:
    """UserSessions::UserUpdated (0x7802/0x0005), typ UserStatus {FLGS statusFlags, ID blazeId} -- definicja z EBOOT.
    W logu SDK od EA przychodzi tuz po UserAdded i niesie flagi stanu uzytkownika (online)."""
    payload = tdf.encode([("FLGS", tdf.VARINT, USER_FLAG_ONLINE), ("ID  ", tdf.VARINT, LOCAL_USER_ID)])
    return build_notification(USER_SESSIONS_COMPONENT, NOTIFY_USER_UPDATED, payload)


def build_ext_data_update(ip: int = 0, maci: int = 0, port: int = 0, best_ping_site: str = "",
                           dbps: int = 0, ubps: int = 0, natt: int = 0) -> bytes:
    """UserSessionExtendedDataUpdate {DATA, SUBS, USID} (0x7802/0x0001).

    HIPOTEZA (2026-09-24): wczesniej ADDR bylo UNSET -- klient sam prosi o swoj adres w
    updateNetworkInfo, ale nigdy nie dostawal odpowiedzi z prawdziwym adresem z powrotem.
    Teraz wysylamy ADDR jako IpPairAddress (disc=2, tag VALU, ksztalt EXIP/INIP potwierdzony
    na drucie w zadaniu klienta updateNetworkInfo) z EXIP=INIP=to co klient sam podal jako
    swoj adres lokalny (jestesmy wszyscy na loopback, wiec 'zewnetrzny' adres = ten sam).

    HIPOTEZA (sesja 4, 2026-09-24): klient w drugim updateNetworkInfo przysyla NLMP (sam
    zmierzone opoznienie do ping site'ow, np. 'ea-sjc') i NQOS (DBPS/NATT/UBPS, sam wyliczone).
    UserSessionExtendedData (potwierdzone w Impulsum14) ma pola BPS (BestPingSiteAlias) i QDAT
    (Util::NetworkQosData {DBPS,NATT,UBPS}), ktorych NIGDY nie wypelnialismy (tylko ADDR).
    Ekran "laczenie" w grach EA Sports typowo czeka na potwierdzenie od serwera, ktory ping
    site jest najlepszy (BPS) i jakie jest ostateczne QOS/NAT, zanim zniknie spinner -- wiec
    odsylamy z powrotem to, co klient sam zmierzyl/wyliczyl, zamiast milczec na te pola."""
    if ip == 0:
        ip = _LOOPBACK_IP_U32
    ip_addr = [("IP  ", tdf.VARINT, ip), ("MACI", tdf.VARINT, maci), ("PORT", tdf.VARINT, port)]
    ip_pair = [("EXIP", tdf.STRUCT, ip_addr), ("INIP", tdf.STRUCT, ip_addr), ("MACI", tdf.VARINT, maci)]
    data = [("ADDR", tdf.UNION, (2, ("VALU", tdf.STRUCT, ip_pair)))]
    if best_ping_site:
        data.append(("BPS ", tdf.STRING, best_ping_site))
    qos_data = [("DBPS", tdf.VARINT, dbps), ("NATT", tdf.VARINT, natt), ("UBPS", tdf.VARINT, ubps)]
    data.append(("QDAT", tdf.STRUCT, qos_data))
    payload = tdf.encode([("DATA", tdf.STRUCT, data), ("SUBS", tdf.VARINT, 0), ("USID", tdf.VARINT, LOCAL_USER_ID)])
    return build_notification(USER_SESSIONS_COMPONENT, NOTIFY_USER_SESSION_EXTENDED_DATA_UPDATE, payload)


def build_ip_address(ip: int, port: int):
    """Blaze::IpAddress {IP, PORT} -- ksztalt i tagi potwierdzone w Impulsum14 (Blaze/IpAddress.cs),
    hash tagow zweryfikowany lokalnie (encode_tag('IP  ')<<8 == 0xA7000000, encode_tag('PORT')<<8 ==
    0xC2FCB400 -- dokladnie te same wartosci co w TdfMemberInfo)."""
    return [("IP  ", tdf.VARINT, ip), ("PORT", tdf.VARINT, port)]


def build_network_address_union(ip: int, port: int):
    """Blaze::NetworkAddress -- union, disc=2 => IpPairAddress {EXIP, INIP} (oba Blaze::IpAddress),
    ksztalt potwierdzony w Impulsum14 (NetworkAddress.cs, IpPairAddress.cs). Uzywamy tego samego adresu
    dla EXIP/INIP jak w build_ext_data_update -- oba klienty siedza w tej samej podsieci Radmin VPN."""
    addr = build_ip_address(ip, port)
    ip_pair = [("EXIP", tdf.STRUCT, addr), ("INIP", tdf.STRUCT, addr)]
    return (2, ("VALU", tdf.STRUCT, ip_pair))


def build_replicated_game_player(name: str, identity, uid: int, persona_id: int, game_id: int,
                                  ip: int, port: int, slot_id: int = 0, team_index: int = 0):
    """Blaze::GameManager::ReplicatedGamePlayer -- pola/tagi potwierdzone w Impulsum14
    (GameManager/ReplicatedGamePlayer.cs). PID=PlayerId (BlazeId persony, jak PIDI w
    build_user_identification), UID=PlayerSessionId (jak AID/ID gdzie indziej) -- to samo
    rozroznienie uid/persona_id co reszta projektu (identity_for_persona)."""
    _, ext_id, _blob = identity
    return [
        ("EXID", tdf.VARINT, ext_id),
        ("GID ", tdf.VARINT, game_id),
        ("NAME", tdf.STRING, name),
        ("PID ", tdf.VARINT, persona_id),
        ("PNET", tdf.UNION, build_network_address_union(ip, port)),
        ("SID ", tdf.VARINT, slot_id),
        ("SLOT", tdf.VARINT, 0),          # SlotType.SLOT_PUBLIC (Impulsum14 SlotType.cs)
        ("STAT", tdf.VARINT, 4),          # PlayerState.ACTIVE_CONNECTED (Impulsum14 PlayerState.cs)
        ("TIDX", tdf.VARINT, team_index),
        ("UID ", tdf.VARINT, uid),
    ]


def build_replicated_game_data(game_id: int, game_name: str, host_ip: int, host_port: int,
                                max_players: int, proto_version: str, network_topology: int = 130):
    """Blaze::GameManager::ReplicatedGameData -- podzbior pol (reszta pomijana, klient dostaje
    wartosci domyslne dla nieobecnych tagow, jak wszedzie indziej w tym module). Tagi potwierdzone
    w Impulsum14 (GameManager/ReplicatedGameData.cs). GSTA=PRE_GAME(130) -- gra utworzona, czeka na
    graczy, zanim przejdzie w IN_GAME(131) (GameState.cs). NTOP domyslnie
    PEER_TO_PEER_FULL_MESH(130) (GameNetworkTopology.cs) -- echo wartosci klienta gdy podana."""
    return [
        ("GID ", tdf.VARINT, game_id),
        ("GNAM", tdf.STRING, game_name),
        ("GSET", tdf.VARINT, 0),
        ("GSTA", tdf.VARINT, 130),
        ("GTYP", tdf.STRING, "gameType0"),
        ("HNET", tdf.LIST, (tdf.UNION, [build_network_address_union(host_ip, host_port)])),
        ("MCAP", tdf.VARINT, max_players),
        ("NTOP", tdf.VARINT, network_topology),
        ("VSTR", tdf.STRING, proto_version),
    ]


def build_notify_game_setup(game_data_fields, roster_players, setup_reason_disc: int = 0) -> bytes:
    """NotifyGameSetup {GAME, PROS, QUEU, REAS} (0x0004/0x0014) -- ksztalt potwierdzony w Impulsum14
    (GameManager/NotifyGameSetup.cs). REAS to unia GameSetupReason (GameSetupReason.cs): disc=0
    DatalessSetupContext dla gracza ktory sam wywolal createGame, disc=2 IndirectJoinGameSetupContext
    dla gracza dolaczanego do gry bez wlasnego wywolania createGame/joinGame (patrz komentarz przy
    obsludze CREATE_GAME_COMMAND) -- oba warianty istnieja w unii, wybor miedzy nimi to decyzja
    projektowa serwera co do PRZYCZYNY dolaczenia, nie zgadywanie ksztaltu protokolu."""
    payload = tdf.encode([
        ("GAME", tdf.STRUCT, game_data_fields),
        ("PROS", tdf.LIST, (tdf.STRUCT, roster_players)),
        ("QUEU", tdf.LIST, (tdf.STRUCT, [])),
        ("REAS", tdf.UNION, (setup_reason_disc, ("VALU", tdf.STRUCT, []))),
    ])
    return build_notification(GAME_MANAGER_COMPONENT, NOTIFY_GAME_SETUP, payload)


def build_create_game_response(component: int, command: int, msg_num: int, game_id: int) -> bytes:
    """CreateGameResponse {GID} -- JEDYNE pole, potwierdzone w Impulsum14 (GameManager/
    CreateGameResponse.cs: dokladnie jeden czlonek, mGameId/GID, UInt32)."""
    payload = tdf.encode([("GID ", tdf.VARINT, game_id)])
    return build_reply(component, command, msg_num, payload)


def _find_field(fields, tag):
    for t, _typ, v in fields:
        if t == tag:
            return v
    return None


def _stats_async_fields(group_name: str, view_id: int):
    stat_values = [("AGGR", tdf.LIST, (tdf.STRUCT, [])), ("STAT", tdf.LIST, (tdf.STRUCT, []))]
    return [
        ("GRNM", tdf.STRING, group_name),
        ("KEY ", tdf.STRING, ""),
        ("LAST", tdf.VARINT, 1),
        ("STS ", tdf.STRUCT, stat_values),
        ("VID ", tdf.VARINT, view_id),
    ]


def build_stats_async_notification(group_name: str, view_id: int) -> bytes:
    """Blaze::Stats::KeyScopedStatValues -- ladunek powiadomienia GetStatsAsyncNotification (0x0007/0x0032),
    ksztalt potwierdzony w Impulsum14 (Blaze3SDK/Blaze/Stats/KeyScopedStatValues.cs + StatValues.cs).
    Klient wysyla getStatsByGroupAsync (0x0007/0x0010) i dostaje na nie PUSTA odpowiedz Reply -- prawdziwe
    dane (tu: pusta lista statystyk, bo nie mamy zadnych realnych danych sezonu) przychodza AS YNC jako ta
    notyfikacja. LAST=1 sygnalizuje klientowi koniec strumienia (brak kolejnych paczek)."""
    payload = tdf.encode(_stats_async_fields(group_name, view_id))
    return build_notification(STATS_COMPONENT, GET_STATS_ASYNC_NOTIFICATION, payload)


def build_stats_by_group_async_reply(component: int, command: int, msg_num: int,
                                      group_name: str, view_id: int) -> bytes:
    """EKSPERYMENT (2026-09-26): odpowiedz Reply na getStatsByGroupAsync (0x0007/0x0010) z tymi samymi
    danymi co GetStatsAsyncNotification, zamiast pustego Reply. Log pokazuje ze klient po dotychczasowej
    parze (pusty Reply + notification) po prostu milknie i zawiesza sie (baner RE-CONNECT po ~1s) -- test
    czy oczekuje danych synchronicznie w samym Reply, a nie tylko async w osobnej notyfikacji."""
    payload = tdf.encode(_stats_async_fields(group_name, view_id))
    return build_reply(component, command, msg_num, payload)


def build_stat_group_response(component: int, command: int, msg_num: int, group_name: str) -> bytes:
    """Blaze::Stats::StatGroupResponse -- odpowiedz na getStatGroup (0x0007/0x0004), ksztalt potwierdzony
    w Impulsum14 (Blaze3SDK/Blaze/Stats/StatGroupResponse.cs). Pusta lista StatDescs -- nie mamy zadnych
    prawdziwych definicji statystyk, wysylamy tylko szkielet z poprawna nazwa grupy, zeby klient mial co
    powiazac z pozniejsza notyfikacja GetStatsAsyncNotification."""
    fields = [
        ("CNAM", tdf.STRING, ""),
        ("DESC", tdf.STRING, ""),
        ("ETYP", tdf.OBJTYPE, (0, 0)),
        ("KSUM", tdf.MAP, (tdf.STRING, tdf.VARINT, [])),
        ("META", tdf.STRING, ""),
        ("NAME", tdf.STRING, group_name),
        ("STAT", tdf.LIST, (tdf.STRUCT, [])),
    ]
    payload = tdf.encode(fields)
    return build_reply(component, command, msg_num, payload)


def build_key_scopes_response(component: int, command: int, msg_num: int) -> bytes:
    """Blaze::Stats::KeyScopes -- odpowiedz na getKeyScopesMap (0x0007/0x000F), ksztalt potwierdzony
    w Impulsum14 (Blaze3SDK/Blaze/Stats/KeyScopes.cs): pojedyncze pole KSIT, map<string, KeyScopeItem>.
    Wczesniej ta komenda wpadala w ogolny fallback i dostawala calkiem pusta odpowiedz (bez nawet pola
    KSIT) -- to trzecia komenda w tej samej serii getStatGroup/getKeyScopesMap/getStatsByGroupAsync,
    ktora klient wysyla przy wejsciu w Cup Match/Seasons, wiec tez potrzebuje typowanej odpowiedzi."""
    fields = [("KSIT", tdf.MAP, (tdf.STRING, tdf.STRUCT, []))]
    payload = tdf.encode(fields)
    return build_reply(component, command, msg_num, payload)


def build_season_id_response(component: int, command: int, msg_num: int, season_id: int = 1) -> bytes:
    """EKSPERYMENT (2026-09-25): odpowiedz na 0x08C9/0x0001 (przypuszczalnie GetCurrentSeasonId -- patrz
    komentarz przy SEASONS_COMPONENT, wiazanie NIEPOTWIERDZONE). Wysylamy te sama wartosc pod kilkoma
    prawdopodobnymi tagami naraz (TDF ignoruje nieznane tagi) zamiast dotychczasowej pustej odpowiedzi,
    zeby sprawdzic empirycznie czy to odblokuje klienta po "Loading Seasons information...". Jesli nie
    zadziala, potrzebna dalsza analiza w Ghidrze (zob. README, sekcja o komponencie 0x08C9)."""
    fields = [(tag, tdf.VARINT, season_id) for tag in _SEASON_ID_TAG_CANDIDATES]
    payload = tdf.encode(fields)
    return build_reply(component, command, msg_num, payload)


def build_get_account_response(component: int, command: int, msg_num: int, identity) -> bytes:
    """Odpowiedz na Authentication::getAccount. Typ Blaze::Authentication::AccountInfo, 16 pol (definicja
    z EBOOT, funkcja 0x00C75874). Nie znaleziono kodu budujacego prawdziwa odpowiedz (funkcja pod jedynym
    innym odwolaniem do tablicy pol byla tylko inicjalizacja metadanych refleksji, nie enkoderem) --
    to jest HIPOTEZA co do ksztaltu odpowiedzi, oparta wylacznie na liscie pol i ich typach."""
    name, ext_id, _blob = identity
    now = int(time.time())
    fields = [
        ("AMU ", tdf.VARINT, 0),
        ("ASRC", tdf.STRING, "SP"),
        ("CO  ", tdf.STRING, "BR"),
        ("DOB ", tdf.STRING, ""),
        ("DTCR", tdf.STRING, ""),
        ("GOPT", tdf.VARINT, 0),
        ("LATH", tdf.STRING, ""),
        ("LN  ", tdf.STRING, "en"),
        ("MAIL", tdf.STRING, LOCAL_EMAIL),
        ("PML ", tdf.STRING, ""),
        ("RC  ", tdf.VARINT, 0),
        ("STAS", tdf.VARINT, 1),
        ("STAT", tdf.VARINT, 0),
        ("TPOT", tdf.VARINT, 0),
        ("UDU ", tdf.VARINT, 0),
        ("UID ", tdf.VARINT, LOCAL_USER_ID),
    ]
    return build_reply(component, command, msg_num, tdf.encode(fields))


def build_login_response(component: int, command: int, msg_num: int, request_fields,
                         groups: str = "sess,pdtl") -> bytes:
    """LoginResponse dla Authentication::login (typ i pola odczytane z definicji w EBOOT):
       LoginResponse {ANON, NTOS, SESS: UserLoginInfo, SPAM, UNDR},
       UserLoginInfo {1CON, BUID, FRST, KEY, LLOG, MAIL, PDTL: PersonaDetails, UID},
       PersonaDetails {DSNM, LAST, PID, PLAT, STAS, XREF}.
    Nazwa persony i XREF pochodza z zadania (EXTB = identyfikator PSN, EXTI = id zewnetrzne)."""
    name, ext_id, _blob = login_identity(request_fields)
    now = int(time.time())
    want = {g.strip() for g in groups.split(",") if g.strip()}
    persona = [
        ("DSNM", tdf.STRING, name),
        ("LAST", tdf.VARINT, now),
        ("PID ", tdf.VARINT, LOCAL_PERSONA_ID),
        ("PLAT", tdf.VARINT, PLATFORM_PS3),
        ("STAS", tdf.VARINT, PERSONA_STATUS_ACTIVE),
        ("XREF", tdf.VARINT, ext_id),
    ]
    sess = [
        ("1CON", tdf.VARINT, 0),
        ("BUID", tdf.VARINT, LOCAL_USER_ID),
        ("FRST", tdf.VARINT, 0),
        ("KEY ", tdf.STRING, LOCAL_SESSION_KEY),
        ("LLOG", tdf.VARINT, now),
        ("MAIL", tdf.STRING, LOCAL_EMAIL),
    ]
    if "pdtl" in want:
        sess.append(("PDTL", tdf.STRUCT, persona))
    sess.append(("UID ", tdf.VARINT, LOCAL_USER_ID))
    fields = [
        ("ANON", tdf.VARINT, 0),
        ("NTOS", tdf.VARINT, 0),
    ]
    if "sess" in want or "pdtl" in want:
        fields.append(("SESS", tdf.STRUCT, sess))
    fields += [
        ("SPAM", tdf.VARINT, 1),
        ("UNDR", tdf.VARINT, 0),
    ]
    return build_reply(component, command, msg_num, tdf.encode(fields))


def build_preauth_payload(canary: bool = False, single_conf: bool = False,
                          groups: str = "cids4,conf,qoss", request_timeout: str = "20s",
                          idle_timeout: str = "40s") -> bytes:
    """Tresc PreAuthResponse wzorowana na grid-leak/blaze (Mirror's Edge Catalyst,
    2016, Blaze SDK 15.1.x -- ta sama rodzina wersji co FIFA17's BSDK 15.1.1.0.0),
    zaadaptowana pod PS3/FIFA17 (PLAT="ps3", SVER dopasowany do zgloszonego BSDK).

    Wciaz HIPOTEZA co do dokladnych wartosci (CIDS, adresy QOSS itd.), ale oparta
    na najblizszej czasowo i wersyjnie znanej, dzialajacej implementacji tego
    samego protokolu -- nie zgadywanie od zera."""
    def h(default: str, canary_value: str) -> str:
        return canary_value if canary else default

    conf_map = [
        ("associationListSkipInitialSet", "1"),
        ("autoReconnectEnabled", "0"),
        ("bytevaultHostname", h("bytevault.gameservices.ea.com", "canary-bytevault.test")),
        ("bytevaultPort", "42210"),
        ("bytevaultSecure", "true"),
        ("connIdleTimeout", idle_timeout),
        ("defaultRequestTimeout", request_timeout),
        ("nucleusConnect", h("https://accounts.ea.com", "https://canary-nucleus.test")),
        ("nucleusConnectTrusted", h("https://accounts2s.ea.com", "https://canary-nucleus-trusted.test")),
        ("nucleusPortal", h("https://signin.ea.com", "https://canary-portal.test")),
        ("nucleusProxy", h("https://gateway.ea.com", "https://canary-proxy.test")),
        ("pingPeriod", "20s"),
        ("userManagerMaxCachedUsers", "0"),
        ("voipHeadsetUpdateRate", "1000"),
        ("xlspConnectionIdleTimeout", "300"),
    ]
    # QoS: adres lokalnego serwera z qos.py (zamiast pustych pol, ktore dawaly
    # w RPCS3 "DnsHook: DNS query for (null)" -- klient probowal rozwiazac pusta nazwe).
    def site(host: str):
        return [
            ("PSA", tdf.STRING, host),
            ("PSP", tdf.VARINT, QOS_PORT),
            ("SNA", tdf.STRING, "prod-sjc"),
        ]

    if canary and single_conf:
        conf_map = [("nucleusConnect", "https://canary-single-nucleus.test")]

    qos_site = site(h(QOS_HOST, "canary-qos-bwps.test"))
    qos_site_ltps = site(h(QOS_HOST, "canary-qos-ltps.test"))
    qoss = [
        ("BWPS", tdf.STRUCT, qos_site),
        ("LNP ", tdf.VARINT, 1),
        ("LTPS", tdf.MAP, (tdf.STRING, tdf.STRUCT, [("ea-sjc", qos_site_ltps)])),
        ("SVID", tdf.VARINT, 1161889797),
        ("TIME", tdf.VARINT, 5_000_000),
    ]
    want = {g.strip() for g in groups.split(",") if g.strip()}
    cids = [0x1, 0x19, 0x4, 0x1c, 0x7, 0x9, 0xf802, 0x7800, 0xf,
            0x7801, 0x7802, 0x7803, 0x7805, 0x7806, 0x7d0]
    fields = [("ASRC", tdf.STRING, "303107")]
    if "cids" in want:
        fields.append(("CIDS", tdf.INTLIST, cids))
    elif "cids4" in want:
        fields.append(("CIDS", tdf.LIST, (tdf.VARINT, cids)))
    fields.append(("CLID", tdf.STRING, "FIFA17-SERVER-PS3"))
    if "conf" in want:
        fields.append(("CONF", tdf.STRUCT, [
            ("CONF", tdf.MAP, (tdf.STRING, tdf.STRING, conf_map)),
        ]))
    fields += [
        ("ESRC", tdf.STRING, "303107"),
        ("INST", tdf.STRING, "fifa-2017-ps3"),
        ("MAID", tdf.VARINT, 1129238128),
        ("MINR", tdf.VARINT, 0),
        ("NASP", tdf.STRING, "cem_ea_id"),
        ("PILD", tdf.STRING, ""),
        ("PLAT", tdf.STRING, "ps3"),
    ]
    if "qoss" in want:
        fields.append(("QOSS", tdf.STRUCT, qoss))
    fields += [
        ("RSRC", tdf.STRING, "303107"),
        ("SVER", tdf.STRING, "Blaze 15.1.1.0.0"),
    ]
    return tdf.encode(fields)


def build_preauth_response(component: int, command: int, msg_num: int,
                           canary: bool = False, single_conf: bool = False,
                           groups: str = "cids4,conf,qoss", request_timeout: str = "20s",
                           idle_timeout: str = "40s") -> bytes:
    return build_reply(component, command, msg_num,
                       build_preauth_payload(canary, single_conf, groups, request_timeout, idle_timeout))


def build_ping_response(component: int, command: int, msg_num: int) -> bytes:
    """PingResponse: czas serwera (unix, sekundy) w polu TIME (jak grid-leak/blaze)."""
    payload = tdf.encode([("TIME", tdf.VARINT, int(time.time()))])
    return build_reply(component, command, msg_num, payload)


def build_keepalive_reply(request_header: bytes) -> bytes:
    """Ping ramkowy klienta (msg_type=4, component 0, command 0) -> ta sama ramka
    z msg_type=PingReply(5), bez tresci (jak routes::keep_alive w grid-leak/blaze)."""
    (payload_size, meta_size, component, command, msg_num, _t, options, reserved) = \
        parse_header(request_header)
    return build_header(0, component, command, msg_num, msg_type=MSG_PING_REPLY)


def build_client_config_reply(component: int, command: int, msg_num: int, cfid: str,
                              canary: bool = False) -> bytes:
    """fetchClientConfig: top-level pole CONF = mapa string->string.
    Dla nieznanych identyfikatorow (OSDK_*) mapa jest pusta, tak jak w grid-leak/blaze.

    HIPOTEZA (sesja 5, 2026-09-24): dyzasembler EBOOT pokazal, ze klient przed uruchomieniem
    watku "FIFA FE Second Initial Thread" (ten sam watek, ktory zapetla sie co ~10s i nigdy
    nie pozwala przejsc dalej ekranu "PRESS START TO RE-CONNECT") sprawdza flage configu o
    nazwie "NEW_THREAD_FOR_FE_INIT_STAGE3" (funkcja 0x005C2C1C -> 0x0143D0A0, ktora czyta
    wartosc po nazwie z domyslna=1/wlaczone, gdy klucza nie ma w configu). Jesli flaga
    wlaczona -> wchodzi w ta zawieszajaca sie sciezke; jesli wylaczona -> pomija ja calkowicie
    i idzie inna, starsza sciezka inicjalizacji. Nie wiemy, z ktorego dokladnie CFID klient
    czyta ten klucz, wiec dodajemy go do WSZYSTKICH odpowiedzi configu (dodatkowy nieznany
    klucz w mapie string->string jest bezpieczny -- reszta kluczy po prostu jest ignorowana)."""
    disable_fe_stage3_thread = [("NEW_THREAD_FOR_FE_INIT_STAGE3", "0")]
    if cfid == "IdentityParams":
        redirect = "http://canary-redirect.test/success" if canary else "http://127.0.0.1/success"
        items = [("display", "console2/welcome"), ("redirect_uri", redirect)]
        if canary:
            # Diagnostyka: w EBOOT klucz "nucleusConnect" stoi tuz przy szablonie
            # "%s/connect/auth?response_type=code" i napisie "IdentityParams" --
            # sprawdzamy, czy adres Nucleus jest czytany wlasnie z tego configu.
            items += [(k, f"https://canary-identity-{k.lower()}.test")
                      for k in ("nucleusConnect", "nucleusConnectTrusted", "nucleusPortal", "nucleusProxy")]
    elif canary and cfid.startswith("OSDK_"):
        # Diagnostyka: te same klucze co w PreAuth CONF, ale kazdy config dostaje
        # wlasna nazwe hosta (canary-<config>-<klucz>.test), zeby po logu DnsHook
        # bylo widac, z ktorego configu gra czyta adres.
        tag = cfid[5:].lower()
        items = [(k, f"https://canary-{tag}-{k.lower()}.test")
                 for k in ("nucleusConnect", "nucleusConnectTrusted", "nucleusPortal", "nucleusProxy")]
    else:
        items = []
    items = items + disable_fe_stage3_thread
    payload = tdf.encode([("CONF", tdf.MAP, (tdf.STRING, tdf.STRING, items))])
    return build_reply(component, command, msg_num, payload)


def handle(conn: socket.socket, addr, cfg: Config, ctx: ssl.SSLContext) -> None:
    cap = Capture(cfg, "blaze", addr)
    stream = None
    identity = None                # ustawiane tu tez, zeby finally mial dostep nawet jesli negotiate() rzuci wyjatek
    try:
        stream = negotiate(conn, ctx, cap)
        if stream is None:
            return
        stream.settimeout(cfg.idle_timeout)
        buf = b""
        identity = None            # (nazwa, EXTI, EXTB) z ostatniego login -- do powiadomien o uzytkowniku
        last_stat_group = ""       # NAME z ostatniego Stats::getStatGroup -- getStatsByGroupAsync przychodzi
                                    # z pustym NAME, ale odpowiedz-powiadomienie musi miec prawdziwa nazwe grupy
        send_lock = threading.Lock()   # chroni WSZYSTKIE zapisy na tym streamie, patrz komentarz przy _PLAYERS
        while True:
            try:
                chunk = stream.recv(65536)
            except socket.timeout:
                cap.note(f"idle for {cfg.idle_timeout}s, closing")
                break
            if not chunk:
                cap.note("client closed the connection")
                break
            cap.data("C->S", chunk)
            buf += chunk

            while len(buf) >= HDR_LEN:
                payload_size, meta_size, component, command, msg_num, msg_type, options, reserved = \
                    parse_header(buf[:HDR_LEN])
                total = HDR_LEN + meta_size + payload_size
                if len(buf) < total:
                    break  # ramka niekompletna, czekamy na wiecej bajtow
                req_header = buf[:HDR_LEN]
                metadata = buf[HDR_LEN:HDR_LEN + meta_size]
                payload = buf[HDR_LEN + meta_size:total]
                buf = buf[total:]

                cap.note(
                    f"ramka: component=0x{component:04X} command=0x{command:04X} "
                    f"msg_num={msg_num} msg_type={msg_type} meta={meta_size}B payload={payload_size}B"
                )
                fields = []
                try:
                    fields, reached, err = tdf.decode_partial(payload)
                    cap.note("TDF:\n" + tdf.pretty(fields))
                    if err:
                        cap.note(f"UWAGA: TDF decode niekompletny ({reached}/{payload_size}): {err}")
                except Exception as exc:
                    cap.note(f"TDF decode wyjatek: {exc}")

                resp = None
                extras = []        # dodatkowe ramki (powiadomienia) wysylane zaraz po odpowiedzi
                if msg_type == MSG_PING:
                    resp = build_keepalive_reply(req_header)
                    cap.note(f"-> PingReply na ping ramkowy (msg_num={msg_num})")
                elif msg_type != MSG_MESSAGE:
                    cap.note(f"-> ramka typu {msg_type} (nie zadanie), nie odpowiadam")
                elif component == UTIL_COMPONENT and command == PRE_AUTH_COMMAND:
                    resp = build_preauth_response(component, command, msg_num, cfg.canary_hosts,
                                  cfg.canary_single_conf, cfg.preauth_groups,
                                  cfg.conf_request_timeout, cfg.conf_idle_timeout)
                    cap.note(f"-> wysylam PreAuthResponse [{cfg.preauth_groups or 'tylko pola proste'}] (Reply, msg_num={msg_num}), "
                             f"{len(resp)-HDR_LEN}B payloadu")
                elif component == UTIL_COMPONENT and command == PING_COMMAND:
                    resp = build_ping_response(component, command, msg_num)
                    cap.note(f"-> wysylam PingResponse (Reply, msg_num={msg_num})")
                elif component == UTIL_COMPONENT and command == FETCH_CLIENT_CONFIG_COMMAND:
                    cfid = ""
                    for tag, t, v in fields:
                        if tag == "CFID":
                            cfid = v
                    resp = build_client_config_reply(component, command, msg_num, cfid, cfg.canary_hosts)
                    cap.note(f"-> wysylam fetchClientConfig CFID={cfid!r} (Reply, msg_num={msg_num})")
                elif component == AUTH_COMPONENT and command == LOGIN_COMMAND:
                    resp = build_login_response(component, command, msg_num, fields, cfg.login_groups)
                    cap.note(f"-> wysylam LoginResponse [{cfg.login_groups or 'same flagi'}] (Reply, msg_num={msg_num}), "
                             f"{len(resp)-HDR_LEN}B payloadu")
                    identity = login_identity(fields)
                    _register_player(identity[0], stream, send_lock)
                    if cfg.send_user_authenticated:
                        extras.append(("UserAuthenticated [0x7802::0x0008]", build_user_authenticated(identity)))
                    extras.append(("NotifyUserAdded [0x7802::0x0002]", build_user_added(identity)))
                    extras.append(("UserUpdated [0x7802::0x0005]", build_user_updated()))
                elif component == AUTH_COMPONENT and command == GET_ACCOUNT_COMMAND and identity is not None:
                    resp = build_get_account_response(component, command, msg_num, identity)
                    cap.note(f"-> wysylam GetAccountResponse (Reply, msg_num={msg_num}), {len(resp)-HDR_LEN}B payloadu")
                elif component == SEASONS_COMPONENT and command == GET_CURRENT_SEASON_ID_COMMAND:
                    resp = build_season_id_response(component, command, msg_num)
                    cap.note(f"-> EKSPERYMENT: wysylam niepusta odpowiedz na 0x08C9/0x0001 "
                             f"(kilka kandydatow na tag naraz, Reply, msg_num={msg_num}), "
                             f"{len(resp)-HDR_LEN}B payloadu")
                elif component == SEASONS_COMPONENT and command == START_SEASON_COMMAND:
                    resp = build_reply(component, command, msg_num, b"")
                    cap.note(f"-> odpowiadam pusto na 0x08C9/0x0002 (msg_num={msg_num}), "
                             f"prawdopodobnie akcja bez danych zwrotnych")
                elif component == USER_SESSIONS_COMPONENT and command == UPDATE_NETWORK_INFO_COMMAND:
                    resp = build_reply(component, command, msg_num, b"")
                    cap.note(f"-> odpowiadam pusto na UserSessions::updateNetworkInfo (msg_num={msg_num})")
                    info_v = _find_field(fields, "INFO") or []
                    addr_v = _find_field(info_v, "ADDR")
                    maci = port = ip = 0
                    if addr_v and addr_v[1] is not None:
                        _, _, valu_v = addr_v[1]
                        inip_v = _find_field(valu_v, "INIP") or []
                        ip = _find_field(inip_v, "IP") or 0
                        port = _find_field(inip_v, "PORT") or 0
                        maci = _find_field(valu_v, "MACI") or 0
                    if identity is not None:
                        _update_player_network(identity[0], ip, port)
                    best_ping_site = ""
                    nlmp_v = _find_field(info_v, "NLMP")
                    if nlmp_v is not None:
                        _, _, items = nlmp_v
                        if items:
                            best_ping_site = min(items, key=lambda kv: kv[1])[0]
                    nqos_v = _find_field(info_v, "NQOS") or []
                    dbps = _find_field(nqos_v, "DBPS") or 0
                    ubps = _find_field(nqos_v, "UBPS") or 0
                    natt = _find_field(nqos_v, "NATT") or 0
                    extras.append(("UserSessionExtendedDataUpdate [0x7802::0x0001]",
                                    build_ext_data_update(maci=maci, port=port, best_ping_site=best_ping_site,
                                                           dbps=dbps, ubps=ubps, natt=natt)))
                elif (component == USER_SESSIONS_COMPONENT and command == LOOKUP_USERS_BY_PERSONA_NAMES_COMMAND
                      and identity is not None and cfg.lookup_users_empty_reply):
                    resp = build_reply(component, command, msg_num, b"")
                    cap.note(f"-> EKSPERYMENT: odpowiadam pusto na lookupUsersByPersonaNames (jak "
                             f"NIEOBSLUZONE) zeby sprawdzic czy sama obecnosc jakiejkolwiek odpowiedzi "
                             f"powoduje crash FEThread na drugim kliencie (msg_num={msg_num})")
                elif (component == USER_SESSIONS_COMPONENT and command == LOOKUP_USERS_BY_PERSONA_NAMES_COMMAND
                      and identity is not None):
                    plst_v = _find_field(fields, "PLST")
                    persona_names = list(plst_v[1]) if plst_v else []
                    resp = build_lookup_users_response(component, command, msg_num, identity, persona_names)
                    cap.note(f"-> wysylam odpowiedz na lookupUsersByPersonaNames dla {persona_names!r} "
                             f"[ULST=LIST<UserData> (tag z Impulsum14, ksztalt EXBB/EXID/ID/NAME/NASP/FLGS "
                             f"z EBOOT), bez shotgun fallback USER/VALU/DATA/LIST -- patrz komentarz przy "
                             f"build_lookup_users_response] (Reply, msg_num={msg_num}), "
                             f"{len(resp)-HDR_LEN}B payloadu")
                elif component == STATS_COMPONENT and command == GET_STAT_GROUP_COMMAND:
                    group_name = ""
                    for tag, t, v in fields:
                        if tag == "NAME":
                            group_name = v
                    last_stat_group = group_name
                    resp = build_stat_group_response(component, command, msg_num, group_name)
                    cap.note(f"-> wysylam Stats::StatGroupResponse dla grupy={group_name!r} "
                             f"(Reply, msg_num={msg_num}), {len(resp)-HDR_LEN}B payloadu")
                elif component == STATS_COMPONENT and command == GET_KEY_SCOPES_MAP_COMMAND:
                    resp = build_key_scopes_response(component, command, msg_num)
                    cap.note(f"-> wysylam Stats::KeyScopes (pusta mapa KSIT, Reply, msg_num={msg_num}), "
                             f"{len(resp)-HDR_LEN}B payloadu")
                elif component == STATS_COMPONENT and command == GET_STATS_BY_GROUP_ASYNC_COMMAND:
                    group_name, view_id = last_stat_group, 0
                    for tag, t, v in fields:
                        if tag == "NAME" and v:
                            group_name = v
                        elif tag == "VID":
                            view_id = v
                    resp = build_stats_by_group_async_reply(component, command, msg_num, group_name, view_id)
                    cap.note(f"-> EKSPERYMENT: odpowiadam na Stats::getStatsByGroupAsync danymi w Reply "
                             f"(nie pusto, msg_num={msg_num}), grupa={group_name!r} "
                             f"(z ostatniego getStatGroup), {len(resp)-HDR_LEN}B payloadu")
                    extras.append(("GetStatsAsyncNotification [0x0007::0x0032]",
                                    build_stats_async_notification(group_name, view_id)))
                elif (component == GAME_MANAGER_COMPONENT and command == CREATE_GAME_COMMAND
                      and identity is not None):
                    # GameManager::createGame -- KLIENT WYSYLA TO PO KLIKNIECIU "Play Match", SERWER
                    # DOTAD ODPOWIADAL PUSTO (fallback ponizej), stad zawieszenie na "Sending match
                    # invite and creating a game session". Realny ksztalt zadania FIFA17 (potwierdzony
                    # na drucie, sesja 2026-09-26) rozni sie od CreateGameRequest.cs z Impulsum14:
                    # klient opakowuje dane w CMGD {GGTY,GVER,OSID,PNET,XNET} i GMCD {ATTR,CRIT,GNAM,
                    # GSET,NTOP,PMAX,PMIN,PRES,QCAP,...} zamiast pol plaskich na najwyzszym poziomie --
                    # GNAM/PMAX/NTOP sa WEWNATRZ GMCD, GVER (nie VSTR) jest wewnatrz CMGD. PLJD.PLDL
                    # zawiera TYLKO wlasny wpis gracza-tworcy (USID.NAME='odyniec' w przechwycie), NIE
                    # tozsamosc zapraszanego -- ten kto ma zostac zaproszony nie jest w tym zadaniu wcale,
                    # wiec budujemy to z WLASNEGO stanu serwera: w tym projekcie zawsze dokladnie dwoch
                    # graczy (host + znajomy przez RPCN), wiec zapraszamy KAZDEGO innego aktualnie
                    # zalogowanego gracza -- to decyzja logiki serwera, nie zalozenie co do protokolu.
                    host_name = identity[0]
                    gmcd_v = _find_field(fields, "GMCD") or []
                    cmgd_v = _find_field(fields, "CMGD") or []
                    game_name = _find_field(gmcd_v, "GNAM") or f"{host_name}'s game"
                    proto_version = _find_field(cmgd_v, "GVER") or ""
                    max_players = _find_field(gmcd_v, "PMAX") or 2

                    with _GAMES_LOCK:
                        game_id = _next_game_id[0]
                        _next_game_id[0] += 1

                    with _PLAYERS_LOCK:
                        host_info = _PLAYERS.get(host_name, {})
                        other_names = [n for n in _PLAYERS if n != host_name]
                    host_ip, host_port = host_info.get("ip", 0), host_info.get("port", 0)

                    resp = build_create_game_response(component, command, msg_num, game_id)
                    cap.note(f"-> wysylam CreateGameResponse GID={game_id} dla {host_name!r} "
                             f"(Reply, msg_num={msg_num})")

                    roster = [build_replicated_game_player(host_name, identity, LOCAL_USER_ID,
                                                            LOCAL_PERSONA_ID, game_id, host_ip, host_port,
                                                            slot_id=0, team_index=0)]
                    invited = []
                    for other_name in other_names:
                        other_p_name, other_ext_id, other_blob, other_uid, other_persona_id = \
                            identity_for_persona(other_name, identity)
                        with _PLAYERS_LOCK:
                            other_info = _PLAYERS.get(other_name, {})
                        other_ip, other_port = other_info.get("ip", 0), other_info.get("port", 0)
                        roster.append(build_replicated_game_player(
                            other_p_name, (other_p_name, other_ext_id, other_blob), other_uid,
                            other_persona_id, game_id, other_ip, other_port,
                            slot_id=len(roster), team_index=1))
                        invited.append(other_name)

                    network_topology = _find_field(gmcd_v, "NTOP") or 130
                    game_data = build_replicated_game_data(game_id, game_name, host_ip, host_port,
                                                            max_players, proto_version, network_topology)
                    extras.append(("NotifyGameSetup [0x0004::0x0014] (host, DatalessSetupContext)",
                                    build_notify_game_setup(game_data, roster, setup_reason_disc=0)))
                    if invited:
                        for other_name in invited:
                            frame = build_notify_game_setup(game_data, roster, setup_reason_disc=2)
                            if not _send_frame(other_name, frame, cap,
                                               "NotifyGameSetup [0x0004::0x0014] "
                                               "(zaproszony, IndirectJoinGameSetupContext)"):
                                cap.note(f"-> nie udalo sie wyslac NotifyGameSetup do {other_name!r} "
                                         f"(rozlaczony?)")
                    else:
                        cap.note(f"-> UWAGA: brak innych zalogowanych graczy do zaproszenia do gry {game_id}")
                else:
                    resp = build_reply(component, command, msg_num, b"")
                    cap.note(f"-> NIEOBSLUZONE zadanie component=0x{component:04X} command=0x{command:04X}: "
                             f"wysylam pusta odpowiedz Reply (msg_num={msg_num})")

                with send_lock:
                    if resp is not None:
                        cap.data("S->C", resp)
                        stream.sendall(resp)
                    for label, frame in extras:
                        cap.note(f"-> wysylam powiadomienie {label}, {len(frame)-HDR_LEN}B payloadu")
                        cap.data("S->C", frame)
                        stream.sendall(frame)

    except (ssl.SSLError, OSError) as exc:
        cap.note(f"connection error: {exc}")
    finally:
        try:
            if identity is not None:
                _unregister_player(identity[0])
        finally:
            try:
                if stream is not None:
                    stream.close()
            finally:
                cap.close()
