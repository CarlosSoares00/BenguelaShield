"""Monitor de ficheiros em tempo real usando watchdog.

Monitoriza pastas críticas e envia ficheiros novos/modificados
para o clamd via socket TCP para verificação imediata.
"""

from __future__ import annotations

import hashlib
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
from watchdog.observers import Observer

from modules.antivirus.config import AntiVirusConfig
from modules.antivirus.database import DatabaseManager
from modules.antivirus.quarantine import QuarantineManager, QuarantineError

logger = logging.getLogger(__name__)

_EXTENSOES_PERIGOSAS = frozenset({
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".com", ".scr", ".pif",
    ".js", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1", ".msi", ".msp",
    ".hta", ".cpl", ".lnk", ".inf", ".reg", ".rgs", ".sct", ".shb",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm",
})


@dataclass
class FileCache:
    """Cache de ficheiros já verificados, com TTL."""

    _cache: dict[str, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    ttl: float = 300.0

    def ja_verificado(self, filepath: str) -> bool:
        """Verifica se o ficheiro já foi verificado recentemente."""
        ahora = time.monotonic()
        with self._lock:
            ultimo = self._cache.get(filepath)
            if ultimo is not None and (ahora - ultimo) < self.ttl:
                return True
            self._cache[filepath] = ahora
            return False

    def limpar(self) -> None:
        """Remove entradas expiradas da cache."""
        ahora = time.monotonic()
        with self._lock:
            expirados = [k for k, v in self._cache.items() if (ahora - v) >= self.ttl]
            for k in expirados:
                del self._cache[k]


class ClamAVScanHandler(FileSystemEventHandler):
    """Handler que processa eventos de criação/modificação de ficheiros."""

    def __init__(
        self,
        config: AntiVirusConfig,
        db: DatabaseManager,
        cache: FileCache,
        on_threat: callable | None = None,
    ) -> None:
        super().__init__()
        self.config = config
        self.db = db
        self.cache = cache
        self.on_threat = on_threat
        self._executor = threading.Thread(target=self._processar_fila, daemon=True)
        self._fila: list[tuple[str, str]] = []
        self._lock = threading.Lock()
        self._parar = False
        self._executor.start()

    def on_created(self, event: FileCreatedEvent) -> None:
        if not event.is_directory:
            self._agendar(event.src_path, "created")

    def on_modified(self, event: FileModifiedEvent) -> None:
        if not event.is_directory:
            self._agendar(event.src_path, "modified")

    def _agendar(self, filepath: str, evento: str) -> None:
        ext = Path(filepath).suffix.lower()
        if ext not in _EXTENSOES_PERIGOSAS:
            return

        if self.cache.ja_verificado(filepath):
            return

        with self._lock:
            self._fila.append((filepath, evento))

    def _processar_fila(self) -> None:
        while not self._parar:
            item = None
            with self._lock:
                if self._fila:
                    item = self._fila.pop(0)

            if item is None:
                time.sleep(0.5)
                continue

            filepath, evento = item
            self._verificar_ficheiro(filepath, evento)

    def _verificar_ficheiro(self, filepath: str, evento: str) -> None:
        if not os.path.isfile(filepath):
            return

        try:
            size = os.path.getsize(filepath)
            if size == 0 or size > 100 * 1024 * 1024:
                return
        except OSError:
            return

        try:
            resultado = self._clamd_scan(filepath)
        except Exception as e:
            logger.warning("Erro ao verificar %s: %s", filepath, e)
            return

        if resultado is None:
            return

        if resultado["clean"]:
            # --- MOTOR YARA ---
            try:
                from modules.yara_engine.yara_scanner import YaraScanner
                if not hasattr(self, "_yara"):
                    self._yara = YaraScanner()
                if self._yara.is_ready:
                    yara_matches = self._yara.scan_file(filepath)
                    if yara_matches:
                        yara_rule = yara_matches[0]["rule"]
                        threat = "YARA:" + yara_rule
                        try:
                            qm = QuarantineManager(self.config, self.db)
                            qid = qm.quarantine_file(filepath, threat)
                            self.db.log_threat(filepath, threat, "quarantined", "FOUND", source="realtime")
                            if self.on_threat:
                                self.on_threat(filepath, threat, qid)
                        except Exception:
                            self.db.log_threat(filepath, threat, "failed", "FOUND", source="realtime")
                        return
            except Exception as e:
                logger.warning("Erro YARA: %s", e)

            # --- MOTOR 3: IA ---
            ext = Path(filepath).suffix.lower()
            if ext in [".exe", ".dll", ".scr"]:
                try:
                    if not hasattr(self, "_ai_classifier"):
                        from modules.ai.file_classifier import FileClassifier
                        self._ai_classifier = FileClassifier()

                    if self._ai_classifier.is_ready:
                        score = self._ai_classifier.classify(filepath)
                        if score is not None:
                            verdict = self._ai_classifier.get_verdict(score)
                            if verdict == "MALWARE":
                                threat = f"AI:Malware(score={score:.3f})"
                                try:
                                    qm = QuarantineManager(self.config, self.db)
                                    qid = qm.quarantine_file(filepath, threat)
                                    self.db.log_threat(filepath, threat, "quarantined", "FOUND", source="ai")
                                    if self.on_threat:
                                        self.on_threat(filepath, threat, qid)
                                except Exception:
                                    self.db.log_threat(filepath, threat, "failed", "FOUND", source="ai")
                                return
                            elif verdict == "SUSPEITO":
                                threat = f"AI:Suspeito(score={score:.3f})"
                                try:
                                    qm = QuarantineManager(self.config, self.db)
                                    qid = qm.quarantine_file(filepath, threat)
                                    self.db.log_threat(filepath, threat, "quarantined", "FOUND", source="ai")
                                    if self.on_threat:
                                        self.on_threat(filepath, threat, qid)
                                except Exception:
                                    self.db.log_threat(filepath, threat, "failed", "FOUND", source="ai")
                                return
                except Exception as e:
                    logger.error("Erro Motor IA: %s", e)

            self.db.log_threat(filepath, None, "none", "OK")
        else:
            threat = resultado["threat"]
            try:
                qm = QuarantineManager(self.config, self.db)
                qid = qm.quarantine_file(filepath, threat)
                self.db.log_threat(filepath, threat, "quarantined", "FOUND", source="realtime")
                if self.on_threat:
                    self.on_threat(filepath, threat, qid)
            except QuarantineError:
                self.db.log_threat(filepath, threat, "failed", "FOUND", source="realtime")
                if self.on_threat:
                    self.on_threat(filepath, threat, None)

    def _clamd_scan(self, filepath: str) -> dict | None:
        """Analisa ficheiro usando clamd INSCAN (rapido) com fallback para clamscan.exe."""
        try:
            from modules.antivirus.scanner import ClamAVScanner
            scanner = ClamAVScanner(self.config)
            result = scanner.scan_file(filepath)
            if result.status == "FOUND":
                return {"clean": False, "threat": result.threat_name or "UNKNOWN"}
            elif result.status == "OK":
                return {"clean": True, "threat": None}
        except Exception:
            pass

        import subprocess
        clamscan = self.config.clamscan_binary
        if not clamscan.exists():
            return None

        try:
            proc = subprocess.run(
                [str(clamscan), "--force-to-disk", "--no-summary", filepath],
                capture_output=True, text=True, timeout=60,
                encoding="utf-8", errors="replace",
            )
            stdout = proc.stdout.strip()
            for line in stdout.splitlines():
                line = line.strip()
                if line.endswith(" FOUND"):
                    parts = line.rsplit(": ", 1)
                    threat = parts[1].replace(" FOUND", "").strip() if len(parts) == 2 else "UNKNOWN"
                    return {"clean": False, "threat": threat}
                elif line.endswith(": OK"):
                    return {"clean": True, "threat": None}
            return None
        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return None

    def parar(self) -> None:
        self._parar = True


class RealtimeMonitor:
    """Monitor principal que gerencia os observers de pastas."""

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
        self._handler: ClamAVScanHandler | None = None
        self._cache = FileCache(ttl=300.0)
        self._limpeza_timer: threading.Timer | None = None

    def iniciar(self, pastas: list[str] | None = None) -> None:
        """Inicia a monitorização das pastas especificadas.

        Args:
            pastas: Lista de caminhos a monitorizar. Se None, usa pastas padrão.
        """
        if pastas is None:
            pastas = self._pastas_padrao()

        self._handler = ClamAVScanHandler(
            self.config, self.db, self._cache, self.on_threat
        )
        self._observer = Observer()

        for pasta in pastas:
            if os.path.isdir(pasta):
                self._observer.schedule(self._handler, pasta, recursive=True)
                logger.info("A monitorizar: %s", pasta)

        self._observer.start()
        self._limpeza_timer = threading.Timer(3600, self._limpar_cache)
        self._limpeza_timer.daemon = True
        self._limpeza_timer.start()

    def parar(self) -> None:
        """Para a monitorização."""
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
        if self._handler:
            self._handler.parar()
        if self._limpeza_timer:
            self._limpeza_timer.cancel()

    def _limpar_cache(self) -> None:
        self._cache.limpar()
        if not self._handler or not self._handler._parar:
            self._limpeza_timer = threading.Timer(3600, self._limpar_cache)
            self._limpeza_timer.daemon = True
            self._limpeza_timer.start()

    @staticmethod
    def _pastas_padrao() -> list[str]:
        userprofile = os.environ.get("USERPROFILE", "")
        pastas = []
        if userprofile:
            for sub in ["Documents", "Desktop", "Downloads", "Pictures"]:
                p = os.path.join(userprofile, sub)
                if os.path.isdir(p):
                    pastas.append(p)
        return pastas
