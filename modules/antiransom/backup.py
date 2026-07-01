"""Gestão de backup automático — guarda versões anteriores de ficheiros modificados."""

from __future__ import annotations

import hashlib
import os
import shutil
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import AntiRansomConfig


@dataclass
class BackupEntry:
    """Registo de um backup."""
    filepath: str
    backup_path: str
    timestamp: float
    size: int
    hash_sha256: str


class BackupManager:
    """Guarda versões anteriores de ficheiros antes de serem modificados.

    Mantém no máximo ``backup_max_versions`` por ficheiro.
    Limite total de disco: ``backup_max_size_mb`` MB.
    """

    def __init__(self, config: AntiRansomConfig) -> None:
        self.config = config
        self._lock = threading.RLock()
        self._index: dict[str, list[BackupEntry]] = {}
        self._carregar_index()

    def _carregar_index(self) -> None:
        index_file = self.config.backup_dir / "_index.txt"
        if not index_file.exists():
            return
        try:
            for line in index_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if len(parts) >= 5:
                    entry = BackupEntry(
                        filepath=parts[0],
                        backup_path=parts[1],
                        timestamp=float(parts[2]),
                        size=int(parts[3]),
                        hash_sha256=parts[4] if len(parts) > 4 else "",
                    )
                    self._index.setdefault(entry.filepath, []).append(entry)
        except Exception:
            pass

    def _guardar_index(self) -> None:
        index_file = self.config.backup_dir / "_index.txt"
        lines = ["# filepath|backup_path|timestamp|size|hash"]
        for backups in self._index.values():
            for b in backups:
                lines.append(f"{b.filepath}|{b.backup_path}|{b.timestamp}|{b.size}|{b.hash_sha256}")
        index_file.write_text("\n".join(lines), encoding="utf-8")

    def antes_de_modificar(self, filepath: str) -> bool:
        """Cria backup do ficheiro ANTES de ser modificado.

        Chamado pelo folder_shield quando detecta modificação.

        Returns:
            ``True`` se o backup foi criado com sucesso.
        """
        filepath = str(Path(filepath).resolve())
        if not os.path.isfile(filepath):
            return False

        try:
            size = os.path.getsize(filepath)
            if size == 0 or size > 50 * 1024 * 1024:
                return False
        except OSError:
            return False

        file_hash = self._hash(filepath)
        timestamp = time.time()

        backup_name = f"{Path(filepath).stem}_{int(timestamp)}.bak"
        backup_subdir = self.config.backup_dir / Path(filepath).parent.name
        backup_subdir.mkdir(parents=True, exist_ok=True)
        backup_path = backup_subdir / backup_name

        try:
            shutil.copy2(filepath, backup_path)
        except Exception:
            return False

        entry = BackupEntry(
            filepath=filepath,
            backup_path=str(backup_path),
            timestamp=timestamp,
            size=size,
            hash_sha256=file_hash,
        )

        with self._lock:
            self._index.setdefault(filepath, []).append(entry)
            self._limpar_versoes_excedentes(filepath)
            self._limpar_espaco()
            self._guardar_index()

        return True

    def restaurar(self, filepath: str, version_index: int = -1) -> str | None:
        """Restaura uma versão anterior do ficheiro.

        Args:
            filepath: Caminho do ficheiro a restaurar.
            version_index: Índice da versão (-1 = mais recente).

        Returns:
            Caminho do ficheiro restaurado, ou ``None`` se falhou.
        """
        filepath = str(Path(filepath).resolve())

        with self._lock:
            backups = self._index.get(filepath, [])

        if not backups:
            return None

        backups.sort(key=lambda b: b.timestamp, reverse=True)
        if abs(version_index) > len(backups):
            return None

        backup = backups[version_index]
        if not os.path.isfile(backup.backup_path):
            return None

        try:
            shutil.copy2(backup.backup_path, filepath)
            return filepath
        except Exception:
            return None

    def listar_versoes(self, filepath: str) -> list[BackupEntry]:
        """Devolve as versões disponíveis para um ficheiro."""
        filepath = str(Path(filepath).resolve())
        with self._lock:
            backups = list(self._index.get(filepath, []))
        backups.sort(key=lambda b: b.timestamp, reverse=True)
        return backups

    def total_backups(self) -> int:
        """Número total de backups armazenados."""
        with self._lock:
            return sum(len(v) for v in self._index.values())

    def tamanho_total(self) -> int:
        """Tamanho total dos backups em bytes."""
        total = 0
        with self._lock:
            for backups in self._index.values():
                for b in backups:
                    total += b.size
        return total

    def _limpar_versoes_excedentes(self, filepath: str) -> None:
        backups = self._index.get(filepath, [])
        if len(backups) <= self.config.backup_max_versions:
            return
        backups.sort(key=lambda b: b.timestamp, reverse=True)
        excedentes = backups[self.config.backup_max_versions:]
        for b in excedentes:
            try:
                os.remove(b.backup_path)
            except OSError:
                pass
        self._index[filepath] = backups[:self.config.backup_max_versions]

    def _limpar_espaco(self) -> None:
        max_bytes = self.config.backup_max_size_mb * 1024 * 1024
        total = self.tamanho_total()
        if total <= max_bytes:
            return

        todos = []
        for backups in self._index.values():
            todos.extend(backups)
        todos.sort(key=lambda b: b.timestamp)

        while todos and total > max_bytes:
            oldest = todos.pop(0)
            total -= oldest.size
            try:
                os.remove(oldest.backup_path)
            except OSError:
                pass
            filepath_backups = self._index.get(oldest.filepath, [])
            if oldest in filepath_backups:
                filepath_backups.remove(oldest)

    @staticmethod
    def _hash(filepath: str) -> str:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
