"""Trwale ustawienia uzytkownika dla Util::userSettingsLoad/Save/LoadAll (0x0009 / 0x000A, 0x000B, 0x000C).

Dowod z przechwytu (sesja 2026-10-08): po loginie klient pyta o klucz 'FirstTimeFlag'; gdy odpowiedz jest
pusta, pokazuje "rejestracje" (welcome / opt-in), a na koncu zapisuje FirstTimeFlag='0' (0x000B). Dotad
serwer ignorowal zapis, wiec rejestracja wracala przy kazdym uruchomieniu. Tu zapisujemy wartosci do
pliku JSON (klucz = nazwa persony), zeby kolejne uruchomienia zwracaly to, co klient zapisal.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

_LOCK = threading.Lock()
_CACHE: dict | None = None
_PATH: Path | None = None


def _load(path: Path) -> dict:
    global _CACHE, _PATH
    if _CACHE is None or _PATH != path:
        _PATH = path
        try:
            _CACHE = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(_CACHE, dict):
                _CACHE = {}
        except (OSError, ValueError):
            _CACHE = {}
    return _CACHE


def get(path: Path, user: str, key: str):
    with _LOCK:
        return _load(path).get(user, {}).get(key)


def get_all(path: Path, user: str) -> dict:
    with _LOCK:
        return dict(_load(path).get(user, {}))


def put(path: Path, user: str, key: str, value: str) -> None:
    with _LOCK:
        data = _load(path)
        data.setdefault(user, {})[key] = value
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
