"""Gestor de processos avançado do BenguelaShield."""
from __future__ import annotations
import logging
import time
from typing import Optional

try:
    import psutil
except ImportError:
    psutil = None

from modules.tools.config import SUSPICIOUS_LOCATIONS, TRUSTED_LOCATIONS

logger = logging.getLogger("BenguelaShield.Tools.ProcessManager")


class BenguelaProcessManager:
    """Gestor de processos com informações de segurança."""

    def list_processes(self) -> list[dict]:
        if psutil is None:
            return []

        processes = []
        for proc in psutil.process_iter(["pid", "name", "exe", "cpu_percent", "memory_info", "num_threads", "status", "create_time"]):
            try:
                info = proc.info
                pid = info["pid"]
                name = info["name"] or ""
                exe = info["exe"] or ""
                cpu = info["cpu_percent"] or 0.0
                mem = (info["memory_info"].rss / (1024 * 1024)) if info["memory_info"] else 0.0
                threads = info["num_threads"] or 0
                status = info["status"] or "unknown"
                create_time = info["create_time"] or 0.0

                age_seconds = int(time.time() - create_time)
                hours = age_seconds // 3600
                minutes = (age_seconds % 3600) // 60
                age_str = f"{hours}h {minutes}m" if hours > 0 else f"{minutes}m"

                location = self._classify_location(exe)
                parent_name = ""
                parent_pid = 0
                try:
                    p = psutil.Process(pid)
                    parent = p.parent()
                    if parent:
                        parent_name = parent.name()
                        parent_pid = parent.pid
                except Exception:
                    pass

                num_conns = 0
                try:
                    p = psutil.Process(pid)
                    num_conns = len(p.net_connections(kind="inet"))
                except Exception:
                    pass

                risk_factors = []
                if location == "suspicious":
                    risk_factors.append("Localização suspeita")
                if cpu > 90:
                    risk_factors.append("CPU muito alto")
                if mem > 500:
                    risk_factors.append("Memória alta")

                verdict = "DESCONHECIDO"
                if location == "trusted" and not risk_factors:
                    verdict = "SEGURO"
                elif location == "suspicious" or len(risk_factors) >= 2:
                    verdict = "SUSPEITO"

                processes.append({
                    "pid": pid, "name": name, "exe": exe,
                    "cpu_percent": round(cpu, 1), "memory_mb": round(mem, 1),
                    "num_threads": threads, "status": status,
                    "create_time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(create_time)),
                    "age": age_str, "parent_name": parent_name, "parent_pid": parent_pid,
                    "num_connections": num_conns, "location": location,
                    "location_path": exe, "security_verdict": verdict,
                    "risk_factors": risk_factors,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        processes.sort(key=lambda p: p["cpu_percent"], reverse=True)
        return processes

    def get_suspicious_processes(self) -> list[dict]:
        return [p for p in self.list_processes() if p["security_verdict"] != "SEGURO"]

    def kill_process(self, pid: int, force: bool = False) -> bool:
        if psutil is None:
            return False
        try:
            p = psutil.Process(pid)
            if force:
                p.kill()
            else:
                p.terminate()
            return True
        except Exception as e:
            logger.error("Erro ao terminar processo %d: %s", pid, e)
            return False

    @staticmethod
    def _classify_location(exe_path: str) -> str:
        if not exe_path:
            return "unknown"
        exe_lower = exe_path.lower()
        for loc in TRUSTED_LOCATIONS:
            if exe_lower.startswith(loc.lower()):
                return "trusted"
        for loc in SUSPICIOUS_LOCATIONS:
            parts = loc.split("*")
            if len(parts) == 2:
                if parts[0].lower() in exe_lower and parts[1].lower() in exe_lower:
                    return "suspicious"
            else:
                if loc.lower() in exe_lower:
                    return "suspicious"
        return "unknown"
