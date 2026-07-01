"""Sistema de pontuação de risco — regras manuais + ML."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from .config import BehavioralConfig, ML_ANOMALY_THRESHOLD, ML_WARNING_THRESHOLD
from .types import ProcessInfo


@dataclass
class RiskResult:
    """Resultado da avaliação de risco."""
    score: int
    reasons: list[str]
    level: str
    ml_score: float | None = None
    ml_verdict: str = ""
    score_source: str = "rules"
    action: str = "IGNORE"


class RiskScorer:
    """Avalia o risco de processos com regras manuais + ML."""

    def __init__(self, config: BehavioralConfig) -> None:
        self.config = config
        self._historial: dict[str, list[float]] = {}

    def avaliar(self, proc: ProcessInfo, ml_score: float | None = None) -> RiskResult:
        """Avalia o risco de um processo.

        Args:
            proc: Informação do processo.
            ml_score: Score do ML (0.0-1.0) ou None.

        Returns:
            RiskResult com score 0-100 e razões.
        """
        rules_score = 0
        reasons: list[str] = []

        s, r = self._avaliar_nome(proc)
        rules_score += s
        reasons.extend(r)

        s, r = self._avaliar_path(proc)
        rules_score += s
        reasons.extend(r)

        s, r = self._avaliar_recursos(proc)
        rules_score += s
        reasons.extend(r)

        s, r = self._avaliar_cmdline(proc)
        rules_score += s
        reasons.extend(r)

        rules_score = min(rules_score, 100)

        ml_score_scaled = None
        if ml_score is not None:
            ml_score_scaled = int(round(ml_score * 10))
            ml_score_scaled = max(0, min(10, ml_score_scaled))

        if ml_score_scaled is None:
            final_score = rules_score
            score_source = "rules"
        elif rules_score == 0:
            final_score = ml_score_scaled
            score_source = "ml"
        else:
            final_score = max(rules_score, ml_score_scaled)
            score_source = "combined"

        if final_score >= 70:
            level = "critical"
            action = "BLOCK"
        elif final_score >= 40:
            level = "high"
            action = "ALERT"
        else:
            level = "low"
            action = "IGNORE"

        ml_verdict = ""
        if ml_score is not None:
            if ml_score < 0.3:
                ml_verdict = "NORMAL"
            elif ml_score < 0.5:
                ml_verdict = "ATENCAO"
            elif ml_score < 0.7:
                ml_verdict = "SUSPEITO"
            else:
                ml_verdict = "ANOMALO"

        parts: list[str] = []
        if reasons:
            parts.append(f"Regras: {len(reasons)} activadas (score={rules_score})")
        if ml_score is not None:
            parts.append(f"ML: {ml_verdict} (score={ml_score:.3f})")
        explanation = " | ".join(parts) if parts else "Comportamento normal"

        return RiskResult(
            score=final_score,
            reasons=reasons,
            level=level,
            ml_score=ml_score,
            ml_verdict=ml_verdict,
            score_source=score_source,
            action=action,
        )

    def _avaliar_nome(self, proc: ProcessInfo) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []
        nome_lower = proc.name.lower()

        if nome_lower in self.config.whitelisted_processes:
            return -20, ["Processo do sistema (whitelist)"]

        for sus in self.config.suspicious_process_names:
            if sus.lower() in nome_lower:
                score += 40
                reasons.append(f"Nome suspeito: {proc.name}")
                break

        if nome_lower.endswith(".tmp") or nome_lower.startswith("~"):
            score += 15
            reasons.append("Nome temporario")

        if proc.name.count(".") > 1:
            score += 10
            reasons.append("Nome com multiplos pontos")

        return score, reasons

    def _avaliar_path(self, proc: ProcessInfo) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []

        if not proc.exe:
            score += 20
            reasons.append("Sem caminho de executavel")
            return score, reasons

        exe_lower = proc.exe.lower()

        for path_sus in self.config.suspicious_paths:
            if path_sus.lower() in exe_lower:
                score += 25
                reasons.append(f"Caminho suspeito: {proc.exe}")
                break

        if "\\AppData\\Local\\Temp\\" in exe_lower:
            score += 15
            reasons.append("Executado da pasta Temp")

        if "\\Downloads\\" in exe_lower:
            score += 10
            reasons.append("Executado da pasta Downloads")

        if "\\Recycle" in exe_lower or "\\Recycled" in exe_lower:
            score += 30
            reasons.append("Executado da Reciclagem")

        return score, reasons

    def _avaliar_recursos(self, proc: ProcessInfo) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []

        if proc.cpu_percent > 90:
            score += 15
            reasons.append(f"CPU muito alto: {proc.cpu_percent:.0f}%")
        elif proc.cpu_percent > 70:
            score += 5

        if proc.memory_mb > 500:
            score += 10
            reasons.append(f"Memoria alta: {proc.memory_mb:.0f}MB")

        if proc.num_threads > 100:
            score += 10
            reasons.append(f"Muitas threads: {proc.num_threads}")

        return score, reasons

    def _avaliar_cmdline(self, proc: ProcessInfo) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []

        if not proc.cmdline:
            return score, reasons

        cmdline_str = " ".join(proc.cmdline).lower()

        sus_patterns = [
            ("powershell -enc", "PowerShell encriptado"),
            ("powershell -nop", "PowerShell sem perfil"),
            ("cmd /c echo", "CMD com echo suspeito"),
            ("certutil -urlcache", "CertUtil download"),
            ("bitsadmin /transfer", "BITS transfer"),
            ("reg add", "Modificacao de registo"),
            ("net user", "Gestao de utilizadores"),
            ("net localgroup", "Gestao de grupos"),
            ("wmic process call create", "Criacao de processo remoto"),
            ("schtasks /create", "Criacao de tarefa agendada"),
            ("bcdedit", "Modificacao de boot"),
            ("vssadmin delete shadows", "Eliminacao de shadow copies"),
        ]

        for pattern, desc in sus_patterns:
            if pattern in cmdline_str:
                score += 30
                reasons.append(desc)
                break

        if "http://" in cmdline_str or "https://" in cmdline_str:
            score += 10
            reasons.append("Contem URL na linha de comandos")

        return score, reasons
