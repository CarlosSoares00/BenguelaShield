"""Testes do módulo de quarentena BenguelaShield."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from modules.antivirus.config import AntiVirusConfig
from modules.antivirus.database import DatabaseManager
from modules.antivirus.quarantine import (
    QuarantineEntry,
    QuarantineError,
    QuarantineManager,
)


@pytest.fixture
def config(tmp_path: Path) -> AntiVirusConfig:
    """Cria uma configuração para testes."""
    return AntiVirusConfig(
        base_dir=tmp_path,
        quarantine_dir=tmp_path / "quarantine",
        db_path=tmp_path / "config" / "test.db",
        quarantine_key=b"\x01" * 32,
    )


@pytest.fixture
def db(config: AntiVirusConfig) -> DatabaseManager:
    """Cria uma base de dados para testes."""
    return DatabaseManager(config.db_path)


@pytest.fixture
def qm(config: AntiVirusConfig, db: DatabaseManager) -> QuarantineManager:
    """Cria um gestor de quarentena para testes."""
    return QuarantineManager(config=config, db=db)


class TestQuarantineManager:
    def test_quarantine_and_restore(
        self, qm: QuarantineManager, tmp_path: Path
    ) -> None:
        """Testa o ciclo completo: quarantinar → restaurar."""
        test_file = tmp_path / "test_malware.txt"
        test_file.write_text("conteúdo infectado de teste")

        qid = qm.quarantine_file(str(test_file), "Test-Virus-1")
        assert qid is not None
        assert len(qid) == 36  # UUID format

        assert not test_file.exists()

        entries = qm.list_files()
        assert len(entries) == 1
        assert entries[0].filename == "test_malware.txt"
        assert entries[0].threat_name == "Test-Virus-1"
        assert entries[0].id == qid

        restored_path = qm.restore_file(qid)
        assert Path(restored_path).exists()
        assert Path(restored_path).read_text() == "conteúdo infectado de teste"

        entries_after = qm.list_files()
        assert len(entries_after) == 0

    def test_quarantine_nonexistent_file(self, qm: QuarantineManager) -> None:
        """Quarentena de ficheiro inexistente deve lançar QuarantineError."""
        with pytest.raises(QuarantineError, match="não encontrado"):
            qm.quarantine_file("/nonexistent/file.txt", "Test")

    def test_restore_nonexistent_entry(self, qm: QuarantineManager) -> None:
        """Restaurar entrada inexistente deve lançar QuarantineError."""
        with pytest.raises(QuarantineError, match="não encontrada"):
            qm.restore_file("nonexistent-uuid")

    def test_delete_file(self, qm: QuarantineManager, tmp_path: Path) -> None:
        """Testa a eliminação de um ficheiro da quarentena."""
        test_file = tmp_path / "to_delete.txt"
        test_file.write_text("apagar este")

        qid = qm.quarantine_file(str(test_file), "Delete-Me")
        assert not test_file.exists()

        qm.delete_file(qid)

        entries = qm.list_files()
        assert len(entries) == 0

        encrypted = qm.config.quarantine_dir / f"{qid}.quarantine"
        assert not encrypted.exists()

    def test_delete_nonexistent_entry(self, qm: QuarantineManager) -> None:
        """Eliminar entrada inexistente deve lançar QuarantineError."""
        with pytest.raises(QuarantineError, match="não encontrada"):
            qm.delete_file("nonexistent-uuid")

    def test_list_files_empty(self, qm: QuarantineManager) -> None:
        """Lista vazia quando não há ficheiros em quarentena."""
        assert qm.list_files() == []

    def test_list_files_multiple(
        self, qm: QuarantineManager, tmp_path: Path
    ) -> None:
        """Testa listagem com múltiplos ficheiros."""
        for i in range(3):
            f = tmp_path / f"malware_{i}.txt"
            f.write_text(f"conteúdo {i}")
            qm.quarantine_file(str(f), f"Virus-{i}")

        entries = qm.list_files()
        assert len(entries) == 3

    def test_cleanup_old_entries(
        self, qm: QuarantineManager, db: DatabaseManager, tmp_path: Path
    ) -> None:
        """Testa limpeza de entradas antigas."""
        test_file = tmp_path / "old_file.txt"
        test_file.write_text("antigo")
        qid = qm.quarantine_file(str(test_file), "Old-Virus")

        db._conn.execute(
            "UPDATE quarantine_log SET date_quarantined = ? WHERE quarantine_id = ?",
            ("2020-01-01T00:00:00+00:00", qid),
        )
        db._conn.commit()

        removed = qm.cleanup(max_age_days=30)
        assert removed == 1

        entries = qm.list_files()
        assert len(entries) == 0


class TestQuarantineEntry:
    def test_dataclass_fields(self) -> None:
        """Testa que QuarantineEntry tem todos os campos necessários."""
        entry = QuarantineEntry(
            id="test-uuid",
            original_path="/path/to/file.txt",
            filename="file.txt",
            threat_name="Test-Virus",
            date_quarantined=datetime.now(timezone.utc),
            file_hash="abc123",
            file_size=1024,
        )
        assert entry.id == "test-uuid"
        assert entry.threat_name == "Test-Virus"
        assert entry.file_size == 1024


class TestEncryption:
    def test_encrypt_decrypt_roundtrip(
        self, qm: QuarantineManager, tmp_path: Path
    ) -> None:
        """Testa que encriptar e desencriptar recupera o conteúdo original."""
        original = tmp_path / "original.bin"
        decrypted = tmp_path / "decrypted.bin"
        content = bytes(range(256)) * 100  # 25.6 KB de dados variados

        original.write_bytes(content)

        qm._encrypt_file(str(original), str(decrypted))
        assert decrypted.exists()
        assert decrypted.read_bytes() != content

        restored = tmp_path / "restored.bin"
        qm._decrypt_file(str(decrypted), str(restored))
        assert restored.read_bytes() == content

    def test_encrypt_decrypt_small_file(
        self, qm: QuarantineManager, tmp_path: Path
    ) -> None:
        """Testa encriptação com ficheiro muito pequeno."""
        original = tmp_path / "tiny.bin"
        decrypted = tmp_path / "tiny_dec.bin"

        original.write_bytes(b"A")
        qm._encrypt_file(str(original), str(decrypted))

        restored = tmp_path / "tiny_rest.bin"
        qm._decrypt_file(str(decrypted), str(restored))
        assert restored.read_bytes() == b"A"

    def test_compute_hash(self, tmp_path: Path) -> None:
        """Testa cálculo de hash SHA-256."""
        test_file = tmp_path / "hash_test.txt"
        test_file.write_text("conteúdo para hash")

        h = QuarantineManager._compute_hash(str(test_file))
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)
