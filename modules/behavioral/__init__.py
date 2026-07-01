"""Módulo Comportamental do BenguelaShield."""

from .config import BehavioralConfig
from .process_monitor import ProcessMonitor
from .risk_score import RiskScorer
from .heuristics import HeuristicAnalyzer

__all__ = [
    "BehavioralConfig",
    "ProcessMonitor",
    "RiskScorer",
    "HeuristicAnalyzer",
]
