"""Protecção de pastas críticas — bloqueia processos não autorizados."""

from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent
from watchdog.observers import Observer

from .config import AntiRansomConfig
from .backup import BackupManager
from .encryption_detect import EncryptionDetector, EncryptionAlert
from .honeypot import HoneypotManager, HoneypotAlert

logger = logging.getLogger(__name__)


class ProtectedFileHandler(FileSystemEventHandler):
    """Handler que processa eventos de ficheiros em pastas protegidas."""

    def __init__(
        self,
        config: AntiRansomConfig,
        backup: BackupManager,
        detector: EncryptionDetector,
    ) -> None:
        super().__init__()
        self.config = config
        self.backup = backup
        self.detector = detector
        self._lock = threading.Lock()
        self._eventos_recentes: list[float] = []
        self._ficheiros_ignorar: set[str] = set()

    def on_modified(self, event: FileModifiedEvent) -> None:
        if event.is_directory:
            return
        self._processar(event.src_path, "modified")

    def on_created(self, event: FileCreatedEvent) -> None:
        if event.is_directory:
            return
        self._processar(event.src_path, "created")

    def _processar(self, filepath: str, evento: str) -> None:
        filepath = str(Path(filepath).resolve())

        if filepath in self._ficheiros_ignorar:
            return

        if not os.path.isfile(filepath):
            return

        ext = Path(filepath).suffix.lower()
        if ext in {".tmp", ".bak", ".swp", ".lock", ".log", ".db-shm", ".db-wal"}:
            return

        try:
            size = os.path.getsize(filepath)
            if size > 50 * 1024 * 1024:
                return
        except OSError:
            return

        if self._ja_processado_recente(filepath):
            return

        if evento == "modified":
            self.backup.antes_de_modificar(filepath)
            self.detector.registar_modificacao(filepath, 0, size)

    def _ja_processado_recente(self, filepath: str) -> bool:
        now = time.time()
        with self._lock:
            self._eventos_recentes.append(now)
            self._eventos_recentes = [t for t in self._eventos_recentes if (now - t) < 1.0]
            return len(self._eventos_recentes) > 100

    def marcar_para_ignorar(self, filepath: str) -> None:
        """Marca um ficheiro para ser ignorado (ex: após restauração)."""
        self._ficheiros_ignorar.add(filepath)
        threading.Timer(5.0, lambda: self._ficheiros_ignorar.discard(filepath)).start()


class FolderShield:
    """Protecção principal de pastas críticas.

    Combina:
    - Backup automático de ficheiros modificados
    - Detecção de encriptação massiva
    - Honeypots (ficheiros isco)
    """

    def __init__(self, config: AntiRansomConfig) -> None:
        self.config = config
        self.backup = BackupManager(config)
        self.detector = EncryptionDetector(config)
        self.honeypot = HoneypotManager(config)
        self._handler: ProtectedFileHandler | None = None
        self._observers: list[Observer] = []
        self._on_threat: callable | None = None
        self._activo = False

    def set_threat_callback(self, callback: callable) -> None:
        """Define callback chamado quando ameaça é detetada."""
        self._on_threat = callback

    def iniciar(self) -> int:
        """Inicia toda a protecção anti-ransomware.

        Returns:
            Número de honeypots criados.
        """
        if self._activo:
            return 0

        self._handler = ProtectedFileHandler(self.config, self.backup, self.detector)

        self.detector.set_alert_callback(self._on_encryption_alert)
        self.honeypot.set_alert_callback(self._on_honeypot_alert)

        for pasta in self.config.protected_dirs:
            if os.path.isdir(pasta):
                observer = Observer()
                observer.schedule(self._handler, pasta, recursive=True)
                observer.start()
                self._observers.append(observer)
                logger.info("Protecção activa em: %s", pasta)

        honeypots = self.honeypot.criar_honeypots()
        self.honeypot.iniciar_monitorizacao()

        self._activo = True
        return honeypots

    def parar(self) -> None:
        """Para toda a protecção."""
        for obs in self._observers:
            obs.stop()
            obs.join(timeout=5)
        self._observers.clear()

        self.honeypot.parar_monitorizacao()
        self._activo = False

    def esta_activo(self) -> bool:
        return self._activo

    def _on_encryption_alert(self, alert: EncryptionAlert) -> None:
        """Handler para alertas de encriptação massiva."""
        msg = (
            f"ALERTA RANSOMWARE: {alert.files_modified} ficheiros "
            f"modificados em {alert.time_window}s — severidade: {alert.severity}"
        )
        logger.warning(msg)

        if self._on_threat:
            self._on_threat({
                "type": "encryption_detected",
                "severity": alert.severity,
                "files_modified": alert.files_modified,
                "affected_files": alert.affected_files,
                "renames": alert.suspicious_renames,
            })

    def _on_honeypot_alert(self, alert: HoneypotAlert) -> None:
        """Handler para alertas de honeypot."""
        msg = f"ALERTA HONEYPOT: Processo modificou ficheiro isco: {alert.filepath}"
        logger.warning(msg)

        if self._on_threat:
            self._on_threat({
                "type": "honeypot_triggered",
                "filepath": alert.filepath,
                "event_type": alert.event_type,
            })

    def status(self) -> dict:
        """Devolve estado actual da protecção."""
        return {
            "activo": self._activo,
            "pastas_protegidas": len(self.config.protected_dirs),
            "honeypots_activos": self.honeypot.honeypots_activos(),
            "total_backups": self.backup.total_backups(),
            "tamanho_backups_mb": round(self.backup.tamanho_total() / (1024 * 1024), 2),
        }
