"""Protecção USB — detecta dispositivos removíveis e executa scan automático."""

from __future__ import annotations

import logging
import os
import string
import threading
import time
from pathlib import Path

import win32api

from modules.antivirus.config import AntiVirusConfig
from modules.antivirus.database import DatabaseManager
from modules.antivirus.quarantine import QuarantineManager, QuarantineError

logger = logging.getLogger(__name__)

_EXTENSOES_PERIGOSAS = frozenset({
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".com", ".scr", ".pif",
    ".js", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".msi",
    ".docm", ".xlsm", ".pptm",
})


class USBGuard:
    """Detecta novos dispositivos USB e executa scan automático."""

    DRIVE_REMOVABLE = 2

    def __init__(
        self,
        config: AntiVirusConfig,
        db: DatabaseManager,
        on_threat: callable | None = None,
    ) -> None:
        self.config = config
        self.db = db
        self.on_threat = on_threat
        self._parar = False
        self._thread: threading.Thread | None = None
        self._drives_conhecidos: set[str] = set()
        self._scan_em_curso: set[str] = set()

    def iniciar(self) -> None:
        """Inicia a monitorização de dispositivos USB."""
        self._drives_conhecidos = self._obter_drives_removiveis()
        self._parar = False
        self._thread = threading.Thread(target=self._ciclo, daemon=True)
        self._thread.start()
        logger.info("USB Guard iniciado. Drives conhecidos: %s", self._drives_conhecidos)

    def parar(self) -> None:
        """Para a monitorização."""
        self._parar = True
        if self._thread:
            self._thread.join(timeout=5)

    def _ciclo(self) -> None:
        while not self._parar:
            time.sleep(3)
            drives_atuais = self._obter_drives_removiveis()

            novos = drives_atuais - self._drives_conhecidos
            for drive in novos:
                if drive not in self._scan_em_curso:
                    threading.Thread(
                        target=self._scan_usb,
                        args=(drive,),
                        daemon=True,
                    ).start()

            self._drives_conhecidos = drives_atuais

    def _obter_drives_removiveis(self) -> set[str]:
        drives = set()
        try:
            bitmask = win32api.GetLogicalDrives()
            for letra in string.ascii_uppercase:
                if bitmask & 1:
                    drive_path = f"{letra}:\\"
                    try:
                        tipo = win32api.GetDriveType(drive_path)
                        if tipo == self.DRIVE_REMOVABLE:
                            if os.path.exists(os.path.join(drive_path, ".")):
                                drives.add(letra)
                    except Exception:
                        pass
                bitmask >>= 1
        except Exception as e:
            logger.warning("Erro ao obter drives: %s", e)
        return drives

    def _scan_usb(self, drive: str) -> None:
        drive_path = f"{drive}:\\"
        self._scan_em_curso.add(drive)
        logger.info("A scanear dispositivo USB: %s", drive_path)

        try:
            cmd = [
                str(self.config.clamscan_binary),
                "-r", "--force-to-disk", "--no-summary",
                drive_path,
            ]
            import subprocess
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600,
                encoding="utf-8", errors="replace",
            )

            ameacas = 0
            for line in proc.stdout.splitlines():
                if ": FOUND" in line:
                    ameacas += 1
                    parts = line.split(": FOUND")
                    filepath = parts[0].strip()
                    threat = parts[1].strip() if len(parts) > 1 else "UNKNOWN"

                    try:
                        qm = QuarantineManager(self.config, self.db)
                        qid = qm.quarantine_file(filepath, threat)
                        self.db.log_threat(filepath, threat, "quarantined", "FOUND", source="usb")
                        if self.on_threat:
                            self.on_threat(filepath, threat, qid)
                    except QuarantineError:
                        self.db.log_threat(filepath, threat, "failed", "FOUND", source="usb")
                    except Exception as e:
                        logger.warning("Erro ao quarantinar %s: %s", filepath, e)

            self.db.log_scan("usb", 0, ameacas, 0)
            logger.info("Scan USB %s concluído: %d ameaças", drive, ameacas)

        except Exception as e:
            logger.warning("Erro no scan USB %s: %s", drive, e)
        finally:
            self._scan_em_curso.discard(drive)
