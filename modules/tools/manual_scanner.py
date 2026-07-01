"""Scanner manual — submissão de ficheiro suspeito para análise."""
from __future__ import annotations
import hashlib
import logging
import os
import subprocess
from pathlib import Path

from modules.antivirus.config import AntiVirusConfig

logger = logging.getLogger("BenguelaShield.Tools.ManualScanner")


class ManualScanner:
    """Análise completa de um ficheiro submetido pelo utilizador."""

    def __init__(self):
        self.config = AntiVirusConfig()

    def analyze_file(self, filepath: str) -> dict:
        result = {
            "filepath": filepath,
            "filename": Path(filepath).name if os.path.exists(filepath) else "N/A",
            "size": 0, "extension": "", "md5": "", "sha1": "", "sha256": "",
            "file_type": "Desconhecido",
            "clamav": {"clean": True, "threat": None},
            "yara": {"clean": True, "matches": []},
            "entropy": {"average": 0.0, "max": 0.0, "is_packed": False},
            "pe_details": None,
            "overall_verdict": "LIMPO",
            "overall_score": 0.0,
            "recommendation": "Permitido",
            "detailed_report": "",
        }

        if not os.path.exists(filepath):
            result["overall_verdict"] = "ERRO"
            result["recommendation"] = "Ficheiro não encontrado"
            return result

        result["size"] = os.path.getsize(filepath)
        result["extension"] = Path(filepath).suffix.lower()

        self._compute_hashes(filepath, result)
        self._scan_clamav(filepath, result)
        self._scan_entropy(filepath, result)
        self._scan_ai(filepath, result)
        self._compute_overall(result)
        result["detailed_report"] = self.generate_report(result)

        return result

    def _compute_hashes(self, filepath: str, result: dict) -> None:
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            result["md5"] = hashlib.md5(data).hexdigest()
            result["sha1"] = hashlib.sha1(data).hexdigest()
            result["sha256"] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            logger.warning("Erro hashes: %s", e)

    def _scan_clamav(self, filepath: str, result: dict) -> None:
        try:
            proc = subprocess.run(
                [str(self.config.clamscan_binary), filepath],
                capture_output=True, text=True, timeout=60,
                encoding="utf-8", errors="replace",
            )
            if "FOUND" in proc.stdout:
                for line in proc.stdout.splitlines():
                    if "FOUND" in line:
                        threat = line.split(":")[-1].replace("FOUND", "").strip()
                        result["clamav"]["clean"] = False
                        result["clamav"]["threat"] = threat
                        break
        except Exception as e:
            logger.warning("Erro ClamAV: %s", e)

    def _scan_entropy(self, filepath: str, result: dict) -> None:
        try:
            from modules.ai.entropy_analyzer import EntropyAnalyzer
            ea = EntropyAnalyzer()
            data = ea.analyze(filepath)
            if data:
                result["entropy"]["average"] = round(data["average_entropy"], 2)
                result["entropy"]["max"] = round(data["max_entropy"], 2)
                result["entropy"]["is_packed"] = data["average_entropy"] > 6.8
        except Exception:
            pass

    def _scan_ai(self, filepath: str, result: dict) -> None:
        try:
            from modules.ai.file_classifier import FileClassifier
            fc = FileClassifier()
            if fc.is_ready and result["extension"] in (".exe", ".dll", ".scr", ".sys"):
                score = fc.classify(filepath)
                if score is not None:
                    result["ai_score"] = score
        except Exception:
            pass

    def _compute_overall(self, result: dict) -> None:
        score = 0.0
        if not result["clamav"]["clean"]:
            score += 0.4
        if result["entropy"]["is_packed"]:
            score += 0.2
        if result.get("ai_score") and result["ai_score"] > 0.5:
            score += 0.3
        result["overall_score"] = min(1.0, score)

        if score >= 0.7:
            result["overall_verdict"] = "MALICIOSO"
            result["recommendation"] = "Quarentena / Eliminar"
        elif score >= 0.3:
            result["overall_verdict"] = "SUSPEITO"
            result["recommendation"] = "Quarentena"
        else:
            result["overall_verdict"] = "LIMPO"
            result["recommendation"] = "Permitido"

    def generate_report(self, analysis: dict) -> str:
        lines = [
            "=" * 50,
            "BENGUELA SHIELD — RELATÓRIO DE ANÁLISE",
            "=" * 50,
            f"Ficheiro: {analysis['filename']}",
            f"Tamanho: {analysis['size'] / 1024:.1f} KB" if analysis["size"] > 1024 else f"Tamanho: {analysis['size']} B",
            f"Extensão: {analysis['extension']}",
            "",
            "HASHES:",
            f"  MD5:    {analysis['md5']}",
            f"  SHA-1:  {analysis['sha1']}",
            f"  SHA-256: {analysis['sha256']}",
            "",
            "DETECÇÃO:",
            f"  ClamAV: {'✅ LIMPO' if analysis['clamav']['clean'] else '❌ ' + (analysis['clamav']['threat'] or 'AMEAÇA')}",
            f"  Entropia: {'⚠️ PACKED' if analysis['entropy']['is_packed'] else '✅ Normal'} ({analysis['entropy']['average']})",
        ]

        if "ai_score" in analysis:
            verdict = "SUSPEITO" if analysis["ai_score"] > 0.5 else "LIMPO"
            lines.append(f"  IA: {'⚠️ ' if analysis['ai_score'] > 0.5 else '✅ '}{verdict} (score: {analysis['ai_score']:.2f})")

        lines.extend([
            "",
            "=" * 50,
            f"VEREDICTO: {analysis['overall_verdict']}",
            f"Recomendação: {analysis['recommendation']}",
            "=" * 50,
        ])

        return "\n".join(lines)
