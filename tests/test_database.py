"""Testes do módulo de base de dados BenguelaShield."""

from __future__ import annotations

from pathlib import Path

import pytest

from modules.antivirus.database import DatabaseManager


@pytest.fixture
def db(tmp_path: Path) -> DatabaseManager:
    """Cria uma base de dados temporária para testes."""
    return DatabaseManager(tmp_path / "test.db")


class TestDatabaseManager:
    def test_table_creation(self, db: DatabaseManager) -> None:
        """Verifica que as tabelas foram criadas."""
        cursor = db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = {row["name"] for row in cursor.fetchall()}
        assert "threats" in tables
        assert "scans" in tables
        assert "quarantine_log" in tables

    def test_log_threat(self, db: DatabaseManager) -> None:
        """Testa o registo de uma ameaça."""
        tid = db.log_threat(
            filepath="/test/malware.exe",
            threat_name="Test-Virus-1",
            action="quarantined",
            status="FOUND",
            file_hash="abc123def456",
            file_size=1024,
        )
        assert tid is not None
        assert tid > 0

        threats = db.get_threats()
        assert len(threats) == 1
        assert threats[0]["filepath"] == "/test/malware.exe"
        assert threats[0]["threat_name"] == "Test-Virus-1"
        assert threats[0]["action"] == "quarantined"

    def test_log_scan(self, db: DatabaseManager) -> None:
        """Testa o registo de um scan."""
        sid = db.log_scan(
            scan_type="quick",
            files_scanned=150,
            threats_found=2,
            duration_seconds=45.5,
        )
        assert sid is not None
        assert sid > 0

        scans = db.get_scans()
        assert len(scans) == 1
        assert scans[0]["scan_type"] == "quick"
        assert scans[0]["files_scanned"] == 150
        assert scans[0]["threats_found"] == 2

    def test_get_threats_limit(self, db: DatabaseManager) -> None:
        """Testa o limite de ameaças retornadas."""
        for i in range(10):
            db.log_threat(
                filepath=f"/test/file_{i}.exe",
                threat_name=f"Virus-{i}",
                action="quarantined",
                status="FOUND",
            )

        threats = db.get_threats(limit=5)
        assert len(threats) == 5

    def test_get_threats_empty(self, db: DatabaseManager) -> None:
        """Testa quando não há ameaças registadas."""
        threats = db.get_threats()
        assert threats == []

    def test_get_scans_empty(self, db: DatabaseManager) -> None:
        """Testa quando não há scans registados."""
        scans = db.get_scans()
        assert scans == []

    def test_get_stats(self, db: DatabaseManager) -> None:
        """Testa estatísticas agregadas."""
        db.log_threat(
            filepath="/a.exe",
            threat_name="V-A",
            action="quarantined",
            status="FOUND",
        )
        db.log_threat(
            filepath="/b.exe",
            threat_name="V-B",
            action="deleted",
            status="FOUND",
        )
        db.log_threat(
            filepath="/c.exe",
            threat_name=None,
            action=None,
            status="OK",
        )
        db.log_scan("quick", 100, 2, 10.0)
        db.log_scan("full", 5000, 0, 300.0)

        stats = db.get_stats()
        assert stats["total_threats"] == 3
        assert stats["quarantined"] == 1
        assert stats["deleted"] == 1
        assert stats["total_scans"] == 2
        assert stats["total_files_scanned"] == 5100

    def test_get_stats_empty(self, db: DatabaseManager) -> None:
        """Testa estatísticas quando a base de dados está vazia."""
        stats = db.get_stats()
        assert stats["total_threats"] == 0
        assert stats["total_scans"] == 0

    def test_quarantine_log_entry(self, db: DatabaseManager) -> None:
        """Testa o registo e leitura de entradas de quarentena."""
        db.log_quarantine_entry(
            quarantine_id="test-uuid-123",
            original_path="/original/path.txt",
            filename="path.txt",
            threat_name="Test-Virus",
            file_hash="sha256hash",
            file_size=2048,
        )

        entries = db.get_quarantine_entries()
        assert len(entries) == 1
        assert entries[0]["quarantine_id"] == "test-uuid-123"
        assert entries[0]["original_path"] == "/original/path.txt"

    def test_remove_quarantine_entry(self, db: DatabaseManager) -> None:
        """Testa a remoção de uma entrada de quarentena."""
        db.log_quarantine_entry(
            quarantine_id="to-remove",
            original_path="/test.txt",
            filename="test.txt",
            threat_name="Virus",
            file_hash="hash",
            file_size=100,
        )

        db.remove_quarantine_entry("to-remove")
        entries = db.get_quarantine_entries()
        assert len(entries) == 0

    def test_close_and_reopen(self, tmp_path: Path) -> None:
        """Testa que os dados persistem entre sessões."""
        db1 = DatabaseManager(tmp_path / "persist.db")
        db1.log_threat(
            filepath="/test.exe",
            threat_name="Persistent-Virus",
            action="quarantined",
            status="FOUND",
        )
        db1.close()

        db2 = DatabaseManager(tmp_path / "persist.db")
        threats = db2.get_threats()
        assert len(threats) == 1
        assert threats[0]["threat_name"] == "Persistent-Virus"
        db2.close()
