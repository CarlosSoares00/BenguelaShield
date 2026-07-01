"""Detecção de encriptação massiva — monitoriza a taxa de modificação de ficheiros."""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import AntiRansomConfig


@dataclass
class ModificationEvent:
    """Evento de modificação de ficheiro."""
    filepath: str
    timestamp: float
    old_size: int
    new_size: int


class EncryptionDetector:
    """Detecta padrões de encriptação massiva (ransomware).

    Monitoriza a taxa de modificações dentro de uma janela temporal.
    Se exceder o limiar, gera um alerta.

    Métricas:
    - Número de ficheiros modificados na janela temporal
    - Mudança de extensão (rename suspeito)
    - Aumento abrupto de entropia (ficheiros normais → encriptados)
    """

    def __init__(self, config: AntiRansomConfig) -> None:
        self.config = config
        self._events: list[ModificationEvent] = []
        self._lock = threading.Lock()
        self._processos_suspeitos: dict[str, int] = {}
        self._on_alert: callable | None = None

    def set_alert_callback(self, callback: callable) -> None:
        """Define a função chamada quando é detetada encriptação."""
        self._on_alert = callback

    def registar_modificacao(self, filepath: str, old_size: int = 0, new_size: int = 0) -> None:
        """Regista uma modificação de ficheiro para análise."""
        now = time.time()
        event = ModificationEvent(
            filepath=filepath,
            timestamp=now,
            old_size=old_size,
            new_size=new_size,
        )

        with self._lock:
            self._events.append(event)
            self._limpar_eventos_antigos(now)

    def verificar(self) -> EncryptionAlert | None:
        """Verifica se há padrão de encriptação massiva.

        Returns:
            ``EncryptionAlert`` se detetado, ``None`` caso contrário.
        """
        now = time.time()
        with self._lock:
            self._limpar_eventos_antigos(now)
            eventos_recentes = [
                e for e in self._events
                if (now - e.timestamp) <= self.config.encryption_time_window
            ]

        if len(eventos_recentes) < self.config.encryption_rate_threshold:
            return None

        ficheiros = set(e.filepath for e in eventos_recentes)

        renames = self._detectar_renames(eventos_recentes)
        entropy_spike = self._detectar_entropy_spike(eventos_recentes)

        severity = "medium"
        if len(ficheiros) > self.config.encryption_rate_threshold * 2:
            severity = "critical"
        elif len(ficheiros) > self.config.encryption_rate_threshold * 1.5:
            severity = "high"

        if renames:
            severity = "critical"
        if entropy_spike:
            severity = "high" if severity == "medium" else severity

        alert = EncryptionAlert(
            timestamp=now,
            files_modified=len(ficheiros),
            time_window=self.config.encryption_time_window,
            severity=severity,
            suspicious_renames=renames,
            entropy_spike_detected=entropy_spike,
            affected_files=list(ficheiros)[:20],
        )

        if self._on_alert:
            self._on_alert(alert)

        return alert

    def _detectar_renames(self, events: list[ModificationEvent]) -> list[str]:
        """Detecta renames para extensões conhecidas de ransomware."""
        SUSPECT_EXTENSIONS = {
            ".locked", ".enc", ".crypto", ".crypt", ".crypted",
            ".locky", ".zepto", ".cerber", ".wncry", ".wannacry",
            ".ryuk", ".maze", ".conti", ".darkside", ".revil",
            ".encrypted", ".wnry", ".wcry", ".aesir", ".zzzzz",
            ".abc", ".aaa", ".vvv", ".xxx", ".ttt", ".micro",
            ".mp3", ".xtbl", ".ytbl", ".ezz", ".ezz1",
        }
        renames = []
        for event in events:
            ext = Path(event.filepath).suffix.lower()
            if ext in SUSPECT_EXTENSIONS:
                renames.append(event.filepath)
        return renames

    def _detectar_entropy_spike(self, events: list[ModificationEvent]) -> bool:
        """Detecta aumento abrupto de tamanho (padrão de encriptação)."""
        for event in events:
            if event.old_size > 100 and event.new_size > 0:
                ratio = event.new_size / event.old_size
                if ratio > 1.5 and event.new_size > 1024:
                    return True
        return False

    def _limpar_eventos_antigos(self, now: float) -> None:
        cutoff = now - (self.config.encryption_time_window * 3)
        self._events = [e for e in self._events if e.timestamp > cutoff]


@dataclass
class EncryptionAlert:
    """Alerta de encriptação massiva."""
    timestamp: float
    files_modified: int
    time_window: float
    severity: str
    suspicious_renames: list[str]
    entropy_spike_detected: bool
    affected_files: list[str]
