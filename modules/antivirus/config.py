"""Configuracoes do modulo AntiVirus BenguelaShield."""

from __future__ import annotations

import json
import os
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path


_CONFIG_ENV_PREFIX = "BENGUELA_"


def _get_data_dir() -> Path:
    """Devolve o directorio de dados gravaveis.
    
    frozen: PROGRAMDATA/BenguelaShield
    dev: pasta raiz do projecto
    """
    if getattr(sys, 'frozen', False):
        return Path(os.environ.get('PROGRAMDATA', r'C:\ProgramData')) / 'BenguelaShield'
    return Path(__file__).resolve().parent.parent.parent


def _get_app_dir() -> Path:
    """Devolve o directorio da aplicacao (solo leitura em instalacao).
    
    frozen: directorio do .exe
    dev: pasta raiz do projecto
    """
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent.parent


@dataclass
class AntiVirusConfig:
    """Configuracoes centralizadas do modulo anti-virus.

    Program Files: executaveis, engine, certs, regras YARA (solo leitura)
    %PROGRAMDATA%: logs, quarantine, db, config, chave AES (gravavel)
    """

    clamd_host: str = "127.0.0.1"
    clamd_port: int = 3310
    scan_timeout: int = 300

    base_dir: Path = field(default_factory=_get_app_dir)
    engine_dir: Path = field(default=None)
    quarantine_dir: Path = field(default=None)
    db_path: Path = field(default=None)

    quarantine_key: bytes = field(default=None)

    freshclam_config: Path = field(default=None)
    freshclam_binary: Path = field(default=None)
    clamscan_binary: Path = field(default=None)

    quick_scan_paths: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        app = self.base_dir
        data = _get_data_dir()
        frozen = getattr(sys, 'frozen', False)

        # Engine: sempre em Program Files (so leitura)
        if self.engine_dir is None:
            self.engine_dir = app / "engine" if frozen else app / "engine" / "clamav" / "x64"

        # Dados gravaveis: sempre em %PROGRAMDATA%
        if self.quarantine_dir is None:
            self.quarantine_dir = data / "quarantine"
        if self.db_path is None:
            self.db_path = data / "config" / "benguelashield.db"

        # Configs de leitura: em Program Files
        if self.freshclam_config is None:
            self.freshclam_config = app / "config" / "freshclam.conf"
        if self.freshclam_binary is None:
            self.freshclam_binary = self.engine_dir / "freshclam.exe"
        if self.clamscan_binary is None:
            self.clamscan_binary = self.engine_dir / "clamscan.exe"

        if not self.quick_scan_paths:
            userprofile = os.environ.get("USERPROFILE", "")
            temp_dir = os.environ.get("TEMP", "")
            appdata = os.environ.get("APPDATA", "")
            startup = (
                Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
                if appdata
                else Path("C:\\")
            )
            self.quick_scan_paths = [
                str(Path(temp_dir)) if temp_dir else "",
                str(Path(userprofile) / "Downloads") if userprofile else "",
                str(startup),
            ]
            self.quick_scan_paths = [p for p in self.quick_scan_paths if p]

        # So criar pastas gravaveis (em data, nunca em app)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        (data / "logs").mkdir(parents=True, exist_ok=True)
        (data / "config").mkdir(parents=True, exist_ok=True)

        if self.quarantine_key is None:
            self.quarantine_key = self._load_or_create_quarantine_key(data)

        self._apply_env_overrides()

    def _load_or_create_quarantine_key(self, data_dir: Path) -> bytes:
        """Carrega ou gera a chave AES de quarentena, persistida em disco."""
        key_dir = data_dir / "config"
        key_dir.mkdir(parents=True, exist_ok=True)
        key_file = key_dir / "quarantine.key"
        if key_file.exists():
            try:
                return key_file.read_bytes()
            except Exception:
                pass
        key = secrets.token_bytes(32)
        try:
            key_file.write_bytes(key)
        except Exception:
            pass
        return key

    def _apply_env_overrides(self) -> None:
        """Aplica variaveis de ambiente com prefixo BENGUELA_."""
        env_map: dict[str, str] = {
            f"{_CONFIG_ENV_PREFIX}CLAMD_HOST": "clamd_host",
            f"{_CONFIG_ENV_PREFIX}CLAMD_PORT": "clamd_port",
            f"{_CONFIG_ENV_PREFIX}SCAN_TIMEOUT": "scan_timeout",
            f"{_CONFIG_ENV_PREFIX}DB_PATH": "db_path",
            f"{_CONFIG_ENV_PREFIX}QUARANTINE_DIR": "quarantine_dir",
            f"{_CONFIG_ENV_PREFIX}ENGINE_DIR": "engine_dir",
        }
        for env_key, attr_name in env_map.items():
            val = os.environ.get(env_key)
            if val is None:
                continue
            if attr_name in ("clamd_port", "scan_timeout"):
                setattr(self, attr_name, int(val))
            elif attr_name in ("db_path", "quarantine_dir", "engine_dir"):
                setattr(self, attr_name, Path(val))
            else:
                setattr(self, attr_name, val)

    @classmethod
    def from_file(cls, path: str | Path) -> AntiVirusConfig:
        """Carrega configuracao a partir de um ficheiro JSON."""
        path = Path(path)
        if not path.exists():
            return cls()

        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        kwargs: dict = {}
        if "clamd_host" in data:
            kwargs["clamd_host"] = data["clamd_host"]
        if "clamd_port" in data:
            kwargs["clamd_port"] = int(data["clamd_port"])
        if "scan_timeout" in data:
            kwargs["scan_timeout"] = int(data["scan_timeout"])
        if "engine_dir" in data:
            kwargs["engine_dir"] = Path(data["engine_dir"])
        if "quarantine_dir" in data:
            kwargs["quarantine_dir"] = Path(data["quarantine_dir"])
        if "db_path" in data:
            kwargs["db_path"] = Path(data["db_path"])
        if "quarantine_key_hex" in data:
            kwargs["quarantine_key"] = bytes.fromhex(data["quarantine_key_hex"])
        if "quick_scan_paths" in data:
            kwargs["quick_scan_paths"] = data["quick_scan_paths"]

        return cls(**kwargs)

    def save_to_file(self, path: str | Path | None = None) -> bool:
        """Persiste a configuracao actual num ficheiro JSON."""
        if path is None:
            path = _get_data_dir() / "config" / "benguelashield.json"
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "clamd_host": self.clamd_host,
            "clamd_port": self.clamd_port,
            "scan_timeout": self.scan_timeout,
            "quick_scan_paths": self.quick_scan_paths,
        }
        try:
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            return True
        except Exception:
            return False
