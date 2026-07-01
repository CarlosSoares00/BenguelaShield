"""Configuracao do modulo Anti-Ransomware."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path


def _data_dir() -> Path:
    if getattr(sys, 'frozen', False):
        return Path(os.environ.get('PROGRAMDATA', r'C:\ProgramData')) / 'BenguelaShield'
    return Path(__file__).resolve().parent.parent.parent


@dataclass
class AntiRansomConfig:
    """Configuracoes do modulo anti-ransomware."""

    data_dir: Path = field(default_factory=_data_dir)
    base_dir: Path = field(default=None)

    backup_dir: Path = field(default=None)
    backup_max_size_mb: int = 500
    backup_max_versions: int = 3

    encryption_rate_threshold: int = 30
    encryption_time_window: float = 10.0

    honeypot_enabled: bool = True
    honeypot_prefix: str = "Z__DECOY__"

    protected_dirs: list[str] = field(default_factory=list)

    whitelist: list[str] = field(default_factory=lambda: [
        "winword.exe", "excel.exe", "powerpnt.exe", "msaccess.exe",
        "notepad.exe", "notepad++.exe", "code.exe", "sublime_text.exe",
        "photoshop.exe", "gimp.exe", "paint.exe", "mspaint.exe",
        "explorer.exe", "cmd.exe", "powershell.exe",
        "python.exe", "python3.exe", "node.exe",
        "chrome.exe", "firefox.exe", "msedge.exe",
        "clamscan.exe", "clamd.exe", "freshclam.exe",
        "7z.exe", "winrar.exe",
        "pdf24.exe", "acrord32.exe", "sumatrapdf.exe",
    ])

    def __post_init__(self) -> None:
        if self.backup_dir is None:
            self.backup_dir = _data_dir() / "antiransom" / "backup"

        if not self.protected_dirs:
            userprofile = os.environ.get("USERPROFILE", "")
            if userprofile:
                for sub in ["Documents", "Desktop", "Pictures", "Videos", "Music"]:
                    p = os.path.join(userprofile, sub)
                    if os.path.isdir(p):
                        self.protected_dirs.append(p)

        self.backup_dir.mkdir(parents=True, exist_ok=True)
