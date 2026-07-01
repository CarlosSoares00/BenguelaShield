"""Protecção de downloads — monitoriza a pasta Downloads e verifica novos ficheiros."""

from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler, FileCreatedEvent
from watchdog.observers import Observer

from modules.antivirus.config import AntiVirusConfig
from modules.antivirus.database import DatabaseManager
from modules.antivirus.quarantine import QuarantineManager, QuarantineError

logger = logging.getLogger(__name__)

_EXTENSOES_PERIGOSAS = frozenset({
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".com", ".scr", ".pif",
    ".js", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".msi", ".msp",
    ".hta", ".cpl", ".docm", ".xlsm", ".pptm",
})

_EXTENSIONS_SKIPPABLE = frozenset({
    ".tmp", ".crdownload", ".partial", ".part", ".download",
})


class DownloadScanHandler(FileSystemEventHandler):
    """Handler que verifica ficheiros descarregados."""

    def __init__(
        self,
        config: AntiVirusConfig,
        db: DatabaseManager,
        on_threat: callable | None = None,
    ) -> None:
        super().__init__()
        self.config = config
        self.db = db
        self.on_threat = on_threat
        self._fila: list[str] = []
        self._lock = threading.Lock()
        self._parar = False
        self._worker = threading.Thread(target=self._processar, daemon=True)
        self._worker.start()

    def on_created(self, event: FileCreatedEvent) -> None:
        if event.is_directory:
            return
        filepath = event.src_path
        ext = Path(filepath).suffix.lower()
        if ext in _EXTENSIONS_SKIPPABLE:
            return
        with self._lock:
            self._fila.append(filepath)

    def _processar(self) -> None:
        while not self._parar:
            item = None
            with self._lock:
                if self._fila:
                    item = self._fila.pop(0)

            if item is None:
                time.sleep(1)
                continue

            self._esperar_estavel(item)
            self._verificar(item)

    def _esperar_estavel(self, filepath: str, timeout: float = 10.0) -> None:
        """Espera até o ficheiro estabilizar em tamanho."""
        deadline = time.monotonic() + timeout
        ultimo_tamanho = -1

        while time.monotonic() < deadline:
            try:
                tamanho = os.path.getsize(filepath)
            except OSError:
                time.sleep(0.5)
                continue

            if tamanho == ultimo_tamanho and tamanho > 0:
                return
            ultimo_tamanho = tamanho
            time.sleep(0.5)

    def _verificar(self, filepath: str) -> None:
        if not os.path.isfile(filepath):
            return

        ext = Path(filepath).suffix.lower()
        if ext not in _EXTENSOES_PERIGOSAS:
            return

        try:
            size = os.path.getsize(filepath)
            if size == 0 or size > 200 * 1024 * 1024:
                return
        except OSError:
            return

        try:
            cmd = [
                str(self.config.clamscan_binary),
                "--force-to-disk",
                "--no-summary",
                filepath,
            ]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60,
                encoding="utf-8", errors="replace",
            )

            if ": FOUND" in proc.stdout:
                parts = proc.stdout.split(": FOUND")
                threat = parts[1].strip() if len(parts) > 1 else "UNKNOWN"

                try:
                    qm = QuarantineManager(self.config, self.db)
                    qid = qm.quarantine_file(filepath, threat)
                    self.db.log_threat(filepath, threat, "quarantined", "FOUND", source="download")
                    if self.on_threat:
                        self.on_threat(filepath, threat, qid)
                except QuarantineError:
                    self.db.log_threat(filepath, threat, "failed", "FOUND", source="download")
                except Exception as e:
                    logger.warning("Erro ao quarantinar download %s: %s", filepath, e)
            else:
                logger.debug("Download limpo: %s", Path(filepath).name)

        except subprocess.TimeoutExpired:
            logger.warning("Timeout ao verificar download: %s", filepath)
        except Exception as e:
            logger.warning("Erro ao verificar download %s: %s", filepath, e)

    def parar(self) -> None:
        self._parar = True


class DownloadGuard:
    """Monitoriza a pasta Downloads do utilizador."""

    def __init__(
        self,
        config: AntiVirusConfig,
        db: DatabaseManager,
        on_threat: callable | None = None,
    ) -> None:
        self.config = config
        self.db = db
        self.on_threat = on_threat
        self._observer: Observer | None = None
        self._handler: DownloadScanHandler | None = None

    def iniciar(self) -> None:
        downloads = os.path.join(os.environ.get("USERPROFILE", ""), "Downloads")
        if not downloads or not os.path.isdir(downloads):
            logger.warning("Pasta Downloads não encontrada")
            return

        self._handler = DownloadScanHandler(self.config, self.db, self.on_threat)
        self._observer = Observer()
        self._observer.schedule(self._handler, downloads, recursive=False)
        self._observer.start()
        logger.info("Download Guard iniciado em: %s", downloads)

    def parar(self) -> None:
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
        if self._handler:
            self._handler.parar()
