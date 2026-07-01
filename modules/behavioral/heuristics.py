"""Análise heurística — detecta padrões de comportamento suspeito."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

from .config import BehavioralConfig
from .process_monitor import ProcessMonitor, ProcessEvent

logger = logging.getLogger(__name__)


@dataclass
class HeuristicAlert:
    """Alerta gerado pela análise heurística."""
    alert_type: str
    severity: str
    description: str
    timestamp: float
    process_name: str = ""
    details: dict = field(default_factory=dict)


class HeuristicAnalyzer:
    """Analisa padrões de comportamento para detetar ameaças."""

    def __init__(self, config: BehavioralConfig, monitor: ProcessMonitor) -> None:
        self.config = config
        self._monitor = monitor
        self._alertas: list[HeuristicAlert] = []
        self._on_alert: callable | None = None
        self._parar = False
        self._thread: threading.Thread | None = None
        self._historial_cmdlines: list[tuple[float, str]] = []

    def set_alert_callback(self, callback: callable) -> None:
        self._on_alert = callback

    def iniciar(self) -> None:
        self._parar = False
        self._thread = threading.Thread(target=self._ciclo, daemon=True)
        self._thread.start()
        logger.info("Heuristic Analyzer iniciado")

    def parar(self) -> None:
        self._parar = True
        if self._thread:
            self._thread.join(timeout=5)

    def _ciclo(self) -> None:
        while not self._parar:
            try:
                self._analisar()
            except Exception as e:
                logger.warning("Erro na análise heurística: %s", e)
            time.sleep(self.config.scan_interval * 2)

    def _analisar(self) -> None:
        processos = self._monitor.todos_processos()

        self._detectar_injecao_processos(processos)
        self._detectar_elevacao_privilegios(processos)
        self._detectar_exfiltracao(processos)
        self._detectar_encerramento_antivirus(processos)

    def _detectar_injecao_processos(self, processos: list) -> None:
        """Detecta processos que injecam código noutros processos."""
        for proc in processos:
            if proc.name.lower() in self.config.whitelisted_processes:
                continue

            if proc.exe and "temp" in proc.exe.lower():
                if proc.num_threads > 20:
                    self._gerar_alerta(
                        "process_injection",
                        "high",
                        f"Processo suspeito com muitas threads: {proc.name}",
                        proc.name,
                        {"pid": proc.pid, "threads": proc.num_threads, "exe": proc.exe},
                    )

    def _detectar_elevacao_privilegios(self, processos: list) -> None:
        """Detecta tentativas de elevação de privilégios."""
        elevacao_cmds = ["runas", "elevate", "psexec", "-accepteula", "/runas"]
        for proc in processos:
            cmdline = " ".join(proc.cmdline).lower()
            for cmd in elevacao_cmds:
                if cmd in cmdline:
                    self._gerar_alerta(
                        "privilege_escalation",
                        "critical",
                        f"Tentativa de elevação: {proc.name}",
                        proc.name,
                        {"pid": proc.pid, "cmdline": cmdline[:200]},
                    )
                    break

    def _detectar_exfiltracao(self, processos: list) -> None:
        """Detecta exfiltração de dados via rede."""
        for proc in processos:
            if proc.name.lower() in self.config.whitelisted_processes:
                continue

            if proc.memory_mb > 300 and proc.cpu_percent > 50:
                cmdline = " ".join(proc.cmdline).lower()
                if any(x in cmdline for x in ["curl", "wget", "powershell", "http"]):
                    self._gerar_alerta(
                        "data_exfiltration",
                        "high",
                        f"Possível exfiltração: {proc.name}",
                        proc.name,
                        {"pid": proc.pid, "memory_mb": proc.memory_mb, "cpu": proc.cpu_percent},
                    )

    def _detectar_encerramento_antivirus(self, processos: list) -> None:
        """Detecta processos que tentam terminar software de segurança."""
        av_processes = {"msmpeng.exe", "msseces.exe", "ccapp.exe", "avgnt.exe",
                        "avguard.exe", "bdagent.exe", "klblmg.exe", "clamscan.exe",
                        "clamd.exe", "benguelashield.exe"}

        for proc in processos:
            cmdline = " ".join(proc.cmdline).lower()
            for av in av_processes:
                if av in cmdline and ("taskkill" in cmdline or "stop" in cmdline):
                    self._gerar_alerta(
                        "av_termination",
                        "critical",
                        f"Tentativa de terminar AV: {proc.name} → {av}",
                        proc.name,
                        {"pid": proc.pid, "target": av},
                    )

    def _gerar_alerta(self, tipo: str, severidade: str, desc: str,
                       proc_name: str, details: dict) -> None:
        alerta = HeuristicAlert(
            alert_type=tipo,
            severity=severidade,
            description=desc,
            timestamp=time.time(),
            process_name=proc_name,
            details=details,
        )

        duplicado = any(
            a.alert_type == tipo and a.process_name == proc_name
            and (time.time() - a.timestamp) < 60
            for a in self._alertas
        )

        if not duplicado:
            self._alertas.append(alerta)
            logger.warning("HEURÍSTICA [%s]: %s", severidade, desc)
            if self._on_alert:
                self._on_alert(alerta)

    def alertas_recentes(self, limite: int = 20) -> list[HeuristicAlert]:
        """Devolve os alertas mais recentes."""
        return list(self._alertas[-limite:])
