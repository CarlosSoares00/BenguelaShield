"""Configuração do módulo de scan agendado."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

LOG_FILE = Path(__file__).parent.parent.parent / "logs" / "scheduler.log"


@dataclass
class SchedulerConfig:
    """Configurações de scan agendado."""

    quick_scan_hour: int = 2
    quick_scan_minute: int = 0
    quick_scan_days: list[int] = field(default_factory=lambda: [0, 1, 2, 3, 4, 5, 6])

    full_scan_hour: int = 3
    full_scan_minute: int = 0
    full_scan_days: list[int] = field(default_factory=lambda: [6])

    quick_scan_paths: list[str] = field(default_factory=list)
    full_scan_path: str = "C:\\"
    scan_timeout: int = 3600
    auto_quarantine: bool = True
    notify_on_complete: bool = True

    def __post_init__(self) -> None:
        if not self.quick_scan_paths:
            userprofile = os.environ.get("USERPROFILE", "")
            if userprofile:
                for sub in ["Downloads", "Desktop"]:
                    p = os.path.join(userprofile, sub)
                    if os.path.isdir(p):
                        self.quick_scan_paths.append(p)


DAYS_PT = {
    0: "Segunda",
    1: "Terca",
    2: "Quarta",
    3: "Quinta",
    4: "Sexta",
    5: "Sabado",
    6: "Domingo",
}
