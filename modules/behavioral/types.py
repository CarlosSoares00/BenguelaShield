"""Tipos de dados partilhados entre módulos comportamentais."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProcessInfo:
    """Informação de um processo monitorizado."""
    pid: int
    name: str
    exe: str
    cmdline: list[str]
    cpu_percent: float
    memory_mb: float
    create_time: float
    num_threads: int
    risk_score: int = 0
    risk_reasons: list[str] = field(default_factory=list)
    ml_score: float | None = None


@dataclass
class ProcessEvent:
    """Evento de processo (criação/terminação)."""
    event_type: str
    pid: int
    name: str
    timestamp: float
    details: str = ""
