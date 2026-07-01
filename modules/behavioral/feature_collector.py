"""Recolhedor de características de processos do BenguelaShield.

Para cada processo em execução, extrai um vector numérico de 15
características que o modelo ML (Isolation Forest) usa para determinar
se o comportamento é normal ou anómalo.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from typing import Optional

try:
    import psutil
except ImportError:
    psutil = None

from modules.behavioral.config import (
    SYSTEM_PROCESSES,
    SUSPICIOUS_PROCESS_NAMES,
    FEATURE_ORDER,
    LOG_FILE,
)

logger = logging.getLogger("BenguelaShield.Behavioral.Features")


class FeatureCollector:
    """Recolhe características numéricas de processos em execução."""

    def __init__(self) -> None:
        if psutil is None:
            logger.error("psutil não está instalado. pip install psutil")

    def collect(self, pid: int) -> Optional[dict]:
        """Recolhe características de um processo pelo seu PID.

        Args:
            pid: Process ID do processo a analisar.

        Returns:
            Dicionário com 15 features numéricas, ou None se erro.
        """
        if psutil is None:
            return None

        try:
            proc = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

        try:
            name = proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

        try:
            cpu_percent = proc.cpu_percent(interval=0.1)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            cpu_percent = 0.0

        try:
            mem = proc.memory_info().rss / (1024 * 1024)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            mem = 0.0

        try:
            num_threads = proc.num_threads()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            num_threads = 0

        try:
            create_time = proc.create_time()
            process_age = int(time.time() - create_time)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            process_age = 0

        num_connections = 0
        has_remote = 0
        remote_is_private = 0
        try:
            connections = proc.net_connections(kind="inet")
            num_connections = len(connections)
            for conn in connections:
                if conn.raddr and conn.raddr.ip:
                    has_remote = 1
                    if self._is_private_ip(conn.raddr.ip):
                        remote_is_private = 1
                        break
        except (psutil.AccessDenied, OSError):
            pass

        num_open_files = 0
        try:
            num_open_files = len(proc.open_files())
        except (psutil.AccessDenied, OSError):
            pass

        parent_is_system = 0
        parent_is_suspicious = 0
        try:
            parent = proc.parent()
            if parent:
                parent_name = parent.name().lower()
                parent_is_system = 1 if parent_name in SYSTEM_PROCESSES else 0
                parent_is_suspicious = 1 if parent_name in SUSPICIOUS_PROCESS_NAMES else 0
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        num_children = 0
        try:
            num_children = len(proc.children(recursive=False))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        has_suspicious_name = 1 if name.lower() in SUSPICIOUS_PROCESS_NAMES else 0

        return {
            "pid": pid,
            "name": name,
            "cpu_percent": cpu_percent,
            "memory_mb": round(mem, 1),
            "num_threads": num_threads,
            "num_connections": num_connections,
            "has_remote_connection": has_remote,
            "remote_ip_is_private": remote_is_private,
            "num_open_files": num_open_files,
            "process_age_seconds": process_age,
            "parent_is_system": parent_is_system,
            "parent_is_suspicious": parent_is_suspicious,
            "num_children": num_children,
            "has_suspicious_name": has_suspicious_name,
            "cpu_is_high": 1 if cpu_percent > 80 else 0,
            "memory_is_high": 1 if mem > 500 else 0,
            "has_many_connections": 1 if num_connections > 10 else 0,
        }

    def collect_batch(self) -> dict[int, dict]:
        """Recolhe características de TODOS os processos activos."""
        if psutil is None:
            return {}

        results: dict[int, dict] = {}

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                info = proc.info
                pid = info["pid"]
                name = (info["name"] or "").lower()

                if name in SYSTEM_PROCESSES:
                    continue
                if "benguelashield" in name:
                    continue

                features = self.collect(pid)
                if features is not None:
                    results[pid] = features
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return results

    def collect_as_vector(self, pid: int) -> Optional[list[float]]:
        """Recolhe features e devolve como lista ordenada de floats."""
        features = self.collect(pid)
        if features is None:
            return None
        return [float(features[name]) for name in FEATURE_ORDER]

    def collect_batch_as_vectors(self) -> tuple[list[int], list[list[float]]]:
        """Recolhe features de todos os processos como vectores."""
        batch = self.collect_batch()
        pids = sorted(batch.keys())
        vectors = [[float(batch[pid][name]) for name in FEATURE_ORDER] for pid in pids]
        return pids, vectors

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Verifica se um IP é de rede privada."""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    @property
    def feature_count(self) -> int:
        """Número de features extraídas por processo."""
        return len(FEATURE_ORDER)

    @property
    def feature_names(self) -> list[str]:
        """Nomes das features na ordem do vector."""
        return list(FEATURE_ORDER)
