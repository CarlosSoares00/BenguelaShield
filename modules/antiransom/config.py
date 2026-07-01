"""Configuração do módulo Anti-Ransomware."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AntiRansomConfig:
    """Configurações do módulo anti-ransomware."""

    base_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent.parent)

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
        "7z.exe", "winrar.exe", "explorer.exe",
        "pdf24.exe", "acrord32.exe", "sumatrapdf.exe",
    ])

    def __post_init__(self) -> None:
        base = self.base_dir

        if self.backup_dir is None:
            self.backup_dir = base / "backup"

        if not self.protected_dirs:
            userprofile = os.environ.get("USERPROFILE", "")
            if userprofile:
                for sub in ["Documents", "Desktop", "Pictures", "Videos", "Music"]:
                    p = os.path.join(userprofile, sub)
                    if os.path.isdir(p):
                        self.protected_dirs.append(p)

        self.backup_dir.mkdir(parents=True, exist_ok=True)
