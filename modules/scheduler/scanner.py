"""Executa scans agendados usando clamscan."""

from __future__ import annotations

import logging
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from modules.scheduler.config import SchedulerConfig

logger = logging.getLogger("BenguelaShield.Scheduler")


@dataclass
class ScheduledScanResult:
    """Resultado de um scan agendado."""
    scan_type: str
    paths_scanned: list[str]
    files_scanned: int
    threats_found: int
    duration_seconds: float
    quarantined: int
    errors: list[str]


class ScheduledScanner:
    """Executa scans agendados usando clamscan."""

    def __init__(self, config: SchedulerConfig) -> None:
        self.config = config

    def run_quick_scan(self) -> ScheduledScanResult:
        """Executa scan rápido nas pastas configuradas."""
        return self._run_scan("quick", self.config.quick_scan_paths)

    def run_full_scan(self) -> ScheduledScanResult:
        """Executa scan completo do disco."""
        return self._run_scan("full", [self.config.full_scan_path])

    def run_custom_scan(self, paths: list[str]) -> ScheduledScanResult:
        """Executa scan em pastas específicas."""
        return self._run_scan("custom", paths)

    def _run_scan(self, scan_type: str, paths: list[str]) -> ScheduledScanResult:
        """Executa clamscan nos caminhos especificados."""
        clamscan = Path(self.config.quick_scan_paths[0]).parent.parent / "engine" / "clamav" / "x64" / "clamscan.exe"

        if not clamscan.exists():
            from modules.antivirus.config import AntiVirusConfig
            av_config = AntiVirusConfig()
            clamscan = av_config.clamscan_binary

        if not clamscan.exists():
            return ScheduledScanResult(
                scan_type=scan_type, paths_scanned=paths,
                files_scanned=0, threats_found=0,
                duration_seconds=0, quarantined=0,
                errors=["clamscan.exe não encontrado"],
            )

        total_files = 0
        total_threats = 0
        errors: list[str] = []
        all_threats: list[str] = []

        start = time.monotonic()

        for path in paths:
            if not os.path.exists(path):
                errors.append(f"Pasta não encontrada: {path}")
                continue

            cmd = [
                str(clamscan),
                "-r", "--force-to-disk", "--no-summary",
                path,
            ]

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.config.scan_timeout,
                    encoding="utf-8",
                    errors="replace",
                )

                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if ": FOUND" in line:
                        total_threats += 1
                        all_threats.append(line)
                        logger.warning("AMEAÇA: %s", line)
                    elif ": OK" in line:
                        total_files += 1

                if proc.returncode not in (0, 1):
                    errors.append(f"clamscan retornou código {proc.returncode}")

            except subprocess.TimeoutExpired:
                errors.append(f"Timeout scan em {path}")
            except Exception as e:
                errors.append(f"Erro scan {path}: {e}")

        elapsed = time.monotonic() - start

        logger.info(
            "Scan %s concluído: %d ficheiros, %d ameaças, %.1fs",
            scan_type, total_files, total_threats, elapsed,
        )

        return ScheduledScanResult(
            scan_type=scan_type,
            paths_scanned=paths,
            files_scanned=total_files,
            threats_found=total_threats,
            duration_seconds=elapsed,
            quarantined=0,
            errors=errors,
        )

    def get_next_quick_scan(self) -> str:
        """Devolve a data/hora do próximo scan rápido."""
        from datetime import datetime, timedelta
        now = datetime.now()
        target = now.replace(
            hour=self.config.quick_scan_hour,
            minute=self.config.quick_scan_minute,
            second=0, microsecond=0,
        )
        if target <= now:
            target += timedelta(days=1)
        while target.weekday() not in self.config.quick_scan_days:
            target += timedelta(days=1)
        return target.strftime("%d/%m/%Y %H:%M")

    def get_next_full_scan(self) -> str:
        """Devolve a data/hora do próximo scan completo."""
        from datetime import datetime, timedelta
        now = datetime.now()
        target = now.replace(
            hour=self.config.full_scan_hour,
            minute=self.config.full_scan_minute,
            second=0, microsecond=0,
        )
        if target <= now:
            target += timedelta(days=1)
        while target.weekday() not in self.config.full_scan_days:
            target += timedelta(days=1)
        return target.strftime("%d/%m/%Y %H:%M")
