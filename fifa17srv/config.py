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
    idle_timeout: float = 60.0

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
