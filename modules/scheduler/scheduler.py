"""Agendador de scans do BenguelaShield.

Monitoriza o relógio e executa scans nas horas programadas.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime

from modules.scheduler.config import SchedulerConfig, DAYS_PT
from modules.scheduler.scanner import ScheduledScanner, ScheduledScanResult

logger = logging.getLogger("BenguelaShield.Scheduler")


class ScanScheduler:
    """Agendador que executa scans nas horas programadas."""

    def __init__(self, config: SchedulerConfig) -> None:
        self.config = config
        self.scanner = ScheduledScanner(config)
        self._parar = False
        self._thread: threading.Thread | None = None
        self._on_complete: callable | None = None
        self._last_quick_scan: str | None = None
        self._last_full_scan: str | None = None
        self._quick_scan_done_today = False
        self._full_scan_done_today = False
        self._history: list[dict] = []

    def set_callback(self, callback: callable) -> None:
        """Define callback chamado ao concluir scan."""
        self._on_complete = callback

    def iniciar(self) -> None:
        """Inicia o agendador em thread separada."""
        self._parar = False
        self._thread = threading.Thread(target=self._ciclo, daemon=True)
        self._thread.start()
        logger.info("Scheduler iniciado — próximo rápido: %s, completo: %s",
                     self.scanner.get_next_quick_scan(),
                     self.scanner.get_next_full_scan())

    def parar(self) -> None:
        """Para o agendador."""
        self._parar = True
        if self._thread:
            self._thread.join(timeout=5)

    def _ciclo(self) -> None:
        """Ciclo principal que verifica o relógio a cada minuto."""
        while not self._parar:
            try:
                agora = datetime.now()

                # Reset diário
                if agora.hour == 0 and agora.minute == 0:
                    self._quick_scan_done_today = False
                    self._full_scan_done_today = False

                # Verificar scan rápido
                if (
                    not self._quick_scan_done_today
                    and agora.weekday() in self.config.quick_scan_days
                    and agora.hour == self.config.quick_scan_hour
                    and agora.minute == self.config.quick_scan_minute
                ):
                    self._executar_scan("quick")

                # Verificar scan completo
                if (
                    not self._full_scan_done_today
                    and agora.weekday() in self.config.full_scan_days
                    and agora.hour == self.config.full_scan_hour
                    and agora.minute == self.config.full_scan_minute
                ):
                    self._executar_scan("full")

            except Exception as e:
                logger.error("Erro no scheduler: %s", e)

            time.sleep(30)

    def _executar_scan(self, scan_type: str) -> None:
        """Executa um scan e regista o resultado."""
        logger.info("A executar scan %s...", scan_type)

        if scan_type == "quick":
            resultado = self.scanner.run_quick_scan()
            self._quick_scan_done_today = True
            self._last_quick_scan = datetime.now().strftime("%d/%m/%Y %H:%M")
        else:
            resultado = self.scanner.run_full_scan()
            self._full_scan_done_today = True
            self._last_full_scan = datetime.now().strftime("%d/%m/%Y %H:%M")

        registo = {
            "timestamp": datetime.now().isoformat(),
            "scan_type": scan_type,
            "files_scanned": resultado.files_scanned,
            "threats_found": resultado.threats_found,
            "duration_seconds": resultado.duration_seconds,
            "errors": resultado.errors,
        }
        self._history.append(registo)

        if self._on_complete:
            self._on_complete(resultado)

        logger.info("Scan %s: %d ficheiros, %d ameaças, %.1fs",
                     scan_type, resultado.files_scanned,
                     resultado.threats_found, resultado.duration_seconds)

    def executar_agora(self, scan_type: str = "quick") -> ScheduledScanResult:
        """Executa um scan imediatamente (para testes ou trigger manual)."""
        if scan_type == "quick":
            resultado = self.scanner.run_quick_scan()
            self._last_quick_scan = datetime.now().strftime("%d/%m/%Y %H:%M")
        else:
            resultado = self.scanner.run_full_scan()
            self._last_full_scan = datetime.now().strftime("%d/%m/%Y %H:%M")

        registo = {
            "timestamp": datetime.now().isoformat(),
            "scan_type": scan_type,
            "files_scanned": resultado.files_scanned,
            "threats_found": resultado.threats_found,
            "duration_seconds": resultado.duration_seconds,
        }
        self._history.append(registo)

        if self._on_complete:
            self._on_complete(resultado)

        return resultado

    def get_status(self) -> dict:
        """Devolve estado actual do agendador."""
        return {
            "activo": not self._parar and self._thread is not None and self._thread.is_alive(),
            "proximo_rapido": self.scanner.get_next_quick_scan(),
            "proximo_completo": self.scanner.get_next_full_scan(),
            "ultimo_rapido": self._last_quick_scan,
            "ultimo_completo": self._last_full_scan,
            "rapido_hoje": self._quick_scan_done_today,
            "completo_hoje": self._full_scan_done_today,
            "historial": len(self._history),
        }

    def get_history(self, limite: int = 20) -> list[dict]:
        """Devolve histórico de scans."""
        return list(reversed(self._history[-limite:]))
