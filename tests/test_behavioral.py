"""Testes do módulo comportamental."""

from __future__ import annotations

import time

import pytest

from modules.behavioral.config import BehavioralConfig
from modules.behavioral.process_monitor import ProcessMonitor, ProcessInfo
from modules.behavioral.risk_score import RiskScorer, RiskResult
from modules.behavioral.heuristics import HeuristicAnalyzer, HeuristicAlert


@pytest.fixture
def config() -> BehavioralConfig:
    return BehavioralConfig(scan_interval=0.5)


@pytest.fixture
def monitor(config: BehavioralConfig) -> ProcessMonitor:
    m = ProcessMonitor(config)
    yield m
    m.parar()


@pytest.fixture
def scorer(config: BehavioralConfig) -> RiskScorer:
    return RiskScorer(config)


# ── RiskScorer ─────────────────────────────────────────────

class TestRiskScorer:
    def test_processo_normal(self, scorer: RiskScorer) -> None:
        proc = ProcessInfo(
            pid=1, name="explorer.exe", exe="C:\\Windows\\explorer.exe",
            cmdline=["explorer.exe"], cpu_percent=5.0, memory_mb=50.0,
            create_time=time.time(), num_threads=10,
        )
        result = scorer.avaliar(proc)
        assert result.score <= 20
        assert result.level == "low"

    def test_processo_suspeito_nome(self, scorer: RiskScorer) -> None:
        proc = ProcessInfo(
            pid=100, name="mimikatz.exe", exe="C:\\Temp\\mimikatz.exe",
            cmdline=["mimikatz.exe", "sekurlsa::logonpasswords"],
            cpu_percent=30.0, memory_mb=100.0,
            create_time=time.time(), num_threads=5,
        )
        result = scorer.avaliar(proc)
        assert result.score >= 30
        assert result.level in ("low", "medium", "high", "critical")
        assert any("nome" in r.lower() for r in result.reasons)

    def test_processo_temp(self, scorer: RiskScorer) -> None:
        proc = ProcessInfo(
            pid=200, name="payload.exe", exe="C:\\Users\\test\\AppData\\Local\\Temp\\payload.exe",
            cmdline=["payload.exe"], cpu_percent=10.0, memory_mb=30.0,
            create_time=time.time(), num_threads=3,
        )
        result = scorer.avaliar(proc)
        assert result.score >= 15
        assert any("temp" in r.lower() for r in result.reasons)

    def test_whitelist(self, scorer: RiskScorer) -> None:
        proc = ProcessInfo(
            pid=1, name="svchost.exe", exe="C:\\Windows\\System32\\svchost.exe",
            cmdline=["svchost.exe", "-k", "netsvcs"],
            cpu_percent=2.0, memory_mb=20.0,
            create_time=time.time(), num_threads=5,
        )
        result = scorer.avaliar(proc)
        assert result.score < 0
        assert any("whitelist" in r.lower() for r in result.reasons)

    def test_cmdline_suspeita(self, scorer: RiskScorer) -> None:
        proc = ProcessInfo(
            pid=300, name="cmd.exe", exe="C:\\Windows\\System32\\cmd.exe",
            cmdline=["cmd.exe", "/c", "powershell", "-enc", "SQBFAFgA"],
            cpu_percent=5.0, memory_mb=20.0,
            create_time=time.time(), num_threads=2,
        )
        result = scorer.avaliar(proc)
        assert result.score >= 30
        assert any("powershell" in r.lower() or "encriptado" in r.lower() for r in result.reasons)

    def test_cpu_alto(self, scorer: RiskScorer) -> None:
        proc = ProcessInfo(
            pid=400, name="miner.exe", exe="C:\\Temp\\miner.exe",
            cmdline=["miner.exe"], cpu_percent=95.0, memory_mb=500.0,
            create_time=time.time(), num_threads=64,
        )
        result = scorer.avaliar(proc)
        assert result.score >= 10
        assert any("cpu" in r.lower() or "memória" in r.lower() for r in result.reasons)


# ── ProcessMonitor ─────────────────────────────────────────

class TestProcessMonitor:
    def test_iniciar_parar(self, monitor: ProcessMonitor) -> None:
        monitor.iniciar()
        time.sleep(1)
        assert monitor._thread is not None
        assert monitor._thread.is_alive()
        monitor.parar()
        assert not monitor._thread.is_alive()

    def test_listar_processos(self, monitor: ProcessMonitor) -> None:
        monitor.iniciar()
        time.sleep(2)
        processos = monitor.todos_processos()
        assert len(processos) > 0
        monitor.parar()

    def test_stats(self, monitor: ProcessMonitor) -> None:
        monitor.iniciar()
        time.sleep(2)
        stats = monitor.stats()
        assert "processos_monitorizados" in stats
        assert stats["processos_monitorizados"] > 0
        monitor.parar()


# ── HeuristicAnalyzer ──────────────────────────────────────

class TestHeuristicAnalyzer:
    def test_iniciar_parar(self, config: BehavioralConfig) -> None:
        monitor = ProcessMonitor(config)
        monitor.iniciar()
        analyzer = HeuristicAnalyzer(config, monitor)
        analyzer.iniciar()
        time.sleep(1)
        assert analyzer._thread is not None
        analyzer.parar()
        monitor.parar()

    def test_alertas(self, config: BehavioralConfig) -> None:
        monitor = ProcessMonitor(config)
        analyzer = HeuristicAnalyzer(config, monitor)
        alertas = []
        analyzer.set_alert_callback(lambda a: alertas.append(a))
        assert isinstance(analyzer.alertas_recentes(), list)
