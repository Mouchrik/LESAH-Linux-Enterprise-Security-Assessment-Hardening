"""Data models + JSON persistence for the LESAH Security Toolkit GUI."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional

CONFIG_DIR = Path.home() / ".lesah_toolkit"
INVENTORY_FILE = CONFIG_DIR / "inventory.json"
SETTINGS_FILE = CONFIG_DIR / "settings.json"
REPORTS_DB_FILE = CONFIG_DIR / "reports_db.json"
LOCAL_REPORTS_DIR = CONFIG_DIR / "reports"


def ensure_dirs() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    LOCAL_REPORTS_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class Host:
    name: str
    host: str
    port: int = 22
    user: str = "root"
    key_path: str = ""       # empty = use default SSH agent / ~/.ssh keys
    group: str = "default"
    last_score: Optional[int] = None
    last_run: str = ""       # ISO timestamp string

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Host":
        return Host(
            name=d.get("name", ""),
            host=d.get("host", ""),
            port=int(d.get("port", 22)),
            user=d.get("user", "root"),
            key_path=d.get("key_path", ""),
            group=d.get("group", "default"),
            last_score=d.get("last_score"),
            last_run=d.get("last_run", ""),
        )


@dataclass
class Settings:
    local_script_path: str = ""
    remote_dir: str = "/root/LESAH/"
    max_concurrency: int = 5
    connect_timeout: int = 15

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Settings":
        s = Settings()
        s.local_script_path = d.get("local_script_path", s.local_script_path)
        s.remote_dir = d.get("remote_dir", s.remote_dir)
        s.max_concurrency = int(d.get("max_concurrency", s.max_concurrency))
        s.connect_timeout = int(d.get("connect_timeout", s.connect_timeout))
        return s


def load_inventory() -> List[Host]:
    ensure_dirs()
    if not INVENTORY_FILE.exists():
        return []
    try:
        data = json.loads(INVENTORY_FILE.read_text())
        return [Host.from_dict(d) for d in data]
    except Exception:
        return []


def save_inventory(hosts: List[Host]) -> None:
    ensure_dirs()
    INVENTORY_FILE.write_text(json.dumps([h.to_dict() for h in hosts], indent=2))


def load_settings() -> Settings:
    ensure_dirs()
    default_script = str(Path(__file__).resolve().parent.parent / "scripts" / "security_audit_rhel.sh")
    if not SETTINGS_FILE.exists():
        s = Settings(local_script_path=default_script)
        save_settings(s)
        return s
    try:
        data = json.loads(SETTINGS_FILE.read_text())
        s = Settings.from_dict(data)
        if not s.local_script_path:
            s.local_script_path = default_script
        return s
    except Exception:
        return Settings(local_script_path=default_script)


def save_settings(settings: Settings) -> None:
    ensure_dirs()
    SETTINGS_FILE.write_text(json.dumps(settings.to_dict(), indent=2))


def load_reports_db() -> List[dict]:
    ensure_dirs()
    if not REPORTS_DB_FILE.exists():
        return []
    try:
        return json.loads(REPORTS_DB_FILE.read_text())
    except Exception:
        return []


def save_reports_db(entries: List[dict]) -> None:
    ensure_dirs()
    REPORTS_DB_FILE.write_text(json.dumps(entries, indent=2))


def import_legacy_inventory(txt_path: str, default_user: str = "root") -> List[Host]:
    """Parse the old lunch_check.sh style server.txt (one IP/host per line, # = comment)."""
    hosts = []
    with open(txt_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            hosts.append(Host(name=line, host=line, user=default_user))
    return hosts
