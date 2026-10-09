"""Identyfikatory graczy -- jedno zrodlo prawdy dla calego serwera.

Dawniej kazdy klient mial ten sam sztywny BlazeId (LOCAL_USER_ID) i widzial INNYCH graczy pod haszowanymi
numerami, wiec ten sam gracz mial u dwoch klientow dwa rozne identyfikatory. Przy laczeniu P2P (siatka
pelna) peer przedstawia sie swoim wlasnym identyfikatorem/grupa polaczen, a druga strona oczekuje tego,
co dostala z serwera -- czyli identyfikatory MUSZA byc wspolne. Teraz kazda persona ma jeden, stabilny,
unikalny zestaw liczb (z nazwy persony), uzywany WSZEDZIE: w loginie, powiadomieniach o uzytkownikach,
rosterach gier i grupie polaczen (CGID/CONG).
"""
from __future__ import annotations

import hashlib

# typ obiektu "grupa polaczen" (komponent UserSessions 0x7802, typ encji 2) -- klient sam wysyla taki typ
# w TCG zadania GameManager::updateMeshConnection, a CGID w UserSessionLoginInfo to ObjectId tego typu
CONNECTION_GROUP_TYPE = (30722, 2)


def uid_for(name: str) -> int:
    """BlazeId (== UserIdentification.ID == UID == numer sesji uzytkownika) persony o danej nazwie."""
    h = int(hashlib.sha1(name.encode("utf-8")).hexdigest(), 16)
    return 2000000000 + (h % 1000000000)


def persona_id_for(name: str) -> int:
    return uid_for(name) + 1


def connection_group_id_for(name: str) -> int:
    """Id grupy polaczen gracza (ReplicatedGamePlayer.CONG, HostInfo.CONG, czesc id w CGID/TCG)."""
    return uid_for(name)


def connection_group_objid_for(name: str):
    """CGID w UserSessionLoginInfo: ObjectId (komponent, typ encji, id)."""
    return CONNECTION_GROUP_TYPE + (connection_group_id_for(name),)
