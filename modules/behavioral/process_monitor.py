"""Monitor de processos — regras manuais + ML para detecção de anomalias."""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field

import psutil

from .config import BehavioralConfig
from .types import ProcessInfo, ProcessEvent
from .feature_collector import FeatureCollector
from .ml_detector import MLDetector
from .risk_score import RiskScorer

logger = logging.getLogger(__name__)


class ProcessMonitor:
    """Monitoriza processos com regras manuais + ML."""

    def __init__(self, config: BehavioralConfig) -> None:
        self.config = config
        self._processos_conhecidos: dict[int, ProcessInfo] = {}
        self._eventos: list[ProcessEvent] = []
        self._lock = threading.Lock()
        self._parar = False
        self._thread: threading.Thread | None = None
        self._on_event: callable | None = None
        self._stats: dict[str, int] = {
            "processos_monitorizados": 0,
            "processos_suspeitos": 0,
            "eventos_totais": 0,
        }

        self.feature_collector = FeatureCollector()
        self.risk_scorer = RiskScorer(config)
        self.ml_detector = MLDetector()

        if self.ml_detector.is_ready:
            logger.info("ML Comportamental (Isolation Forest) activo")
        else:
            logger.warning("ML Comportamental indisponivel — apenas regras manuais")

    def set_event_callback(self, callback: callable) -> None:
        self._on_event = callback

    def iniciar(self) -> None:
        self._parar = False
        self._thread = threading.Thread(target=self._ciclo, daemon=True)
        self._thread.start()
        logger.info("Process Monitor iniciado")

    def parar(self) -> None:
        self._parar = True
        if self._thread:
            self._thread.join(timeout=5)

    def _ciclo(self) -> None:
        while not self._parar:
            try:
                self._varredura()
            except Exception as e:
                logger.warning("Erro na varredura: %s", e)
            time.sleep(self.config.scan_interval)

    def _varredura(self) -> None:
        pids_atuais: set[int] = set()

        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline",
                                          "cpu_percent", "memory_info",
                                          "create_time", "num_threads"]):
            try:
                info = proc.info
                pid = info["pid"]
                pids_atuais.add(pid)

                nome = info["name"] or ""
                exe = info["exe"] or ""
                cmdline = info["cmdline"] or []
                cpu = info["cpu_percent"] or 0.0
                mem = (info["memory_info"].rss / (1024 * 1024)) if info["memory_info"] else 0.0
                create_time = info["create_time"] or 0.0
                threads = info["num_threads"] or 0

                process_info = ProcessInfo(
                    pid=pid, name=nome, exe=exe, cmdline=cmdline,
                    cpu_percent=cpu, memory_mb=round(mem, 1),
                    create_time=create_time, num_threads=threads,
                )

                if pid not in self._processos_conhecidos:
                    self._registar_evento("created", pid, nome,
                                          f"Novo processo: {nome} (PID {pid})")

                self._processos_conhecidos[pid] = process_info
                self._stats["processos_monitorizados"] = len(self._processos_conhecidos)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        with self._lock:
            pids_anteriores = set(self._processos_conhecidos.keys())
            pids_terminados = pids_anteriores - pids_atuais
            for pid in pids_terminados:
                proc = self._processos_conhecidos.pop(pid, None)
                if proc:
                    self._registar_evento("terminated", pid, proc.name,
                                          f"Processo terminado: {proc.name} (PID {pid})")

    def _registar_evento(self, tipo: str, pid: int, nome: str, detalhes: str) -> None:
        evento = ProcessEvent(
            event_type=tipo, pid=pid, name=nome,
            timestamp=time.time(), details=detalhes,
        )
        with self._lock:
            self._eventos.append(evento)
            if len(self._eventos) > 1000:
                self._eventos = self._eventos[-500:]
            self._stats["eventos_totais"] = len(self._eventos)

        if self._on_event:
            self._on_event(evento)

    def avaliar_processo(self, pid: int) -> dict | None:
        """Avalia um processo com regras + ML."""
        proc = self._processos_conhecidos.get(pid)
        if proc is None:
            return None

        ml_score = None
        if self.ml_detector.is_ready:
            vector = self.feature_collector.collect_as_vector(pid)
            if vector is not None:
                ml_score = self.ml_detector.detect(vector)

        result = self.risk_scorer.avaliar(proc, ml_score=ml_score)

        proc.risk_score = result.score
        proc.risk_reasons = result.reasons
        proc.ml_score = ml_score

        return {
            "pid": pid,
            "process_name": proc.name,
            "rules_score": result.score,
            "ml_score": ml_score,
            "ml_verdict": result.ml_verdict,
            "final_score": result.score,
            "score_source": result.score_source,
            "verdict": result.level,
            "action": result.action,
            "explanation": " | ".join(result.reasons) if result.reasons else "Normal",
        }

    def processos_suspeitos(self) -> list[ProcessInfo]:
        suspeitos = [p for p in self._processos_conhecidos.values() if p.risk_score > 0]
        suspeitos.sort(key=lambda p: p.risk_score, reverse=True)
        return suspeitos

    def todos_processos(self) -> list[ProcessInfo]:
        return list(self._processos_conhecidos.values())

    def eventos_recentes(self, limite: int = 50) -> list[ProcessEvent]:
        with self._lock:
            return list(self._eventos[-limite:])

    def stats(self) -> dict[str, int]:
        return dict(self._stats)
