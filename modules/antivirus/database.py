"""Gestão da base de dados SQLite do BenguelaShield."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    filepath TEXT NOT NULL,
    threat_name TEXT,
    action TEXT,
    status TEXT NOT NULL,
    file_hash TEXT,
    file_size INTEGER
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    files_scanned INTEGER,
    threats_found INTEGER,
    duration_seconds REAL
);

CREATE TABLE IF NOT EXISTS quarantine_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    quarantine_id TEXT NOT NULL UNIQUE,
    original_path TEXT NOT NULL,
    filename TEXT NOT NULL,
    threat_name TEXT NOT NULL,
    date_quarantined TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    file_size INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS realtime_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    filepath TEXT NOT NULL,
    threat_name TEXT,
    action_taken TEXT,
    source TEXT NOT NULL DEFAULT 'local'
);

CREATE TABLE IF NOT EXISTS behavioral_ml_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    pid INTEGER,
    process_name TEXT,
    process_path TEXT,
    rules_score INTEGER DEFAULT 0,
    ml_score REAL,
    ml_score_scaled INTEGER,
    final_score INTEGER,
    score_source TEXT,
    verdict TEXT,
    action_taken TEXT,
    rules_triggered TEXT,
    ml_verdict TEXT,
    explanation TEXT
);

CREATE TABLE IF NOT EXISTS scheduled_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    files_scanned INTEGER DEFAULT 0,
    threats_found INTEGER DEFAULT 0,
    duration_seconds REAL DEFAULT 0,
    quarantined INTEGER DEFAULT 0,
    errors TEXT DEFAULT ''
);
"""


@dataclass
class DatabaseManager:
    """Gestor da base de dados SQLite do BenguelaShield.

    Cria automaticamente as tabelas necessárias ao primeiro acesso.

    Args:
        db_path: Caminho para o ficheiro SQLite.
    """

    db_path: Path

    def __post_init__(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA_SQL)
        self._conn.commit()

    def close(self) -> None:
        """Fecha a ligação à base de dados."""
        self._conn.close()

    def log_threat(
        self,
        filepath: str,
        threat_name: str | None,
        action: str | None,
        status: str,
        file_hash: str | None = None,
        file_size: int | None = None,
        source: str = "local",
    ) -> int:
        """Regista uma ameaça detectada.

        Args:
            filepath: Caminho completo do ficheiro.
            threat_name: Nome da ameaça (ex: ``Clamav.Test.File-1``).
            action: Acção tomada (``quarantined``, ``deleted``, ``none``).
            status: Estado (``FOUND``, ``OK``, ``ERROR``).
            file_hash: Hash SHA-256 do ficheiro.
            file_size: Tamanho em bytes.
            source: Origem (``local``, ``usb``, ``download``, ``realtime``).

        Returns:
            ID do registo criado.
        """
        now = datetime.now(timezone.utc).isoformat()
        cursor = self._conn.execute(
            """
            INSERT INTO threats (timestamp, filepath, threat_name, action, status, file_hash, file_size)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (now, filepath, threat_name, action, status, file_hash, file_size),
        )
        if source != "local" and threat_name:
            self._conn.execute(
                """
                INSERT INTO realtime_events (timestamp, event_type, filepath, threat_name, action_taken, source)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (now, "threat", filepath, threat_name, action, source),
            )
        self._conn.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def log_scan(
        self,
        scan_type: str,
        files_scanned: int,
        threats_found: int,
        duration_seconds: float,
    ) -> int:
        """Regista o resultado de um scan.

        Args:
            scan_type: Tipo de scan (``quick``, ``full``, ``custom``, ``realtime``).
            files_scanned: Número de ficheiros analisados.
            threats_found: Número de ameaças encontradas.
            duration_seconds: Duração em segundos.

        Returns:
            ID do registo criado.
        """
        now = datetime.now(timezone.utc).isoformat()
        cursor = self._conn.execute(
            """
            INSERT INTO scans (timestamp, scan_type, files_scanned, threats_found, duration_seconds)
            VALUES (?, ?, ?, ?, ?)
            """,
            (now, scan_type, files_scanned, threats_found, duration_seconds),
        )
        self._conn.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def get_threats(self, limit: int = 100) -> list[dict[str, Any]]:
        """Devolve as ameaças mais recentes.

        Args:
            limit: Número máximo de registos.

        Returns:
            Lista de dicionários com os dados das ameaças.
        """
        rows = self._conn.execute(
            "SELECT * FROM threats ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]

    def get_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        """Devolve os scans mais recentes.

        Args:
            limit: Número máximo de registos.

        Returns:
            Lista de dicionários com os dados dos scans.
        """
        rows = self._conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]

    def get_stats(self) -> dict[str, Any]:
        """Devolve estatísticas agregadas.

        Returns:
            Dicionário com contagens totais de ameaças, scans e ficheiros analisados.
        """
        threats_row = self._conn.execute(
            "SELECT COUNT(*) as total, "
            "SUM(CASE WHEN action='quarantined' THEN 1 ELSE 0 END) as quarantined, "
            "SUM(CASE WHEN action='deleted' THEN 1 ELSE 0 END) as deleted "
            "FROM threats"
        ).fetchone()

        scans_row = self._conn.execute(
            "SELECT COUNT(*) as total_scans, "
            "COALESCE(SUM(files_scanned), 0) as total_files, "
            "COALESCE(SUM(threats_found), 0) as total_threats_found "
            "FROM scans"
        ).fetchone()

        return {
            "total_threats": threats_row["total"] if threats_row else 0,
            "quarantined": threats_row["quarantined"] if threats_row else 0,
            "deleted": threats_row["deleted"] if threats_row else 0,
            "total_scans": scans_row["total_scans"] if scans_row else 0,
            "total_files_scanned": scans_row["total_files"] if scans_row else 0,
            "total_threats_found": scans_row["total_threats_found"] if scans_row else 0,
        }

    def log_quarantine_entry(
        self,
        quarantine_id: str,
        original_path: str,
        filename: str,
        threat_name: str,
        file_hash: str,
        file_size: int,
    ) -> None:
        """Regista uma entrada de quarentena.

        Args:
            quarantine_id: UUID da quarentena.
            original_path: Caminho original do ficheiro.
            filename: Nome do ficheiro.
            threat_name: Nome da ameaça detectada.
            file_hash: Hash SHA-256.
            file_size: Tamanho em bytes.
        """
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """
            INSERT INTO quarantine_log
                (quarantine_id, original_path, filename, threat_name, date_quarantined, file_hash, file_size)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (quarantine_id, original_path, filename, threat_name, now, file_hash, file_size),
        )
        self._conn.commit()

    def get_quarantine_entries(self) -> list[dict[str, Any]]:
        """Devolve todas as entradas de quarentena.

        Returns:
            Lista de dicionários com os dados das entradas.
        """
        rows = self._conn.execute(
            "SELECT * FROM quarantine_log ORDER BY id DESC"
        ).fetchall()
        return [dict(row) for row in rows]

    def remove_quarantine_entry(self, quarantine_id: str) -> None:
        """Remove uma entrada de quarentena da base de dados.

        Args:
            quarantine_id: UUID da quarentena a remover.
        """
        self._conn.execute(
            "DELETE FROM quarantine_log WHERE quarantine_id = ?", (quarantine_id,)
        )
        self._conn.commit()
