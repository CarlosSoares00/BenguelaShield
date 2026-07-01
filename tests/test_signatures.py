"""Testes do módulo de assinaturas BenguelaShield."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules.antivirus.config import AntiVirusConfig
from modules.antivirus.signatures import (
    SignatureManager,
    SignatureUpdateError,
    UpdateResult,
)


@pytest.fixture
def config(tmp_path: Path) -> AntiVirusConfig:
    """Cria uma configuração para testes."""
    engine_dir = tmp_path / "engine" / "clamav" / "x64"
    engine_dir.mkdir(parents=True)
    return AntiVirusConfig(
        base_dir=tmp_path,
        engine_dir=engine_dir,
        quarantine_dir=tmp_path / "quarantine",
        db_path=tmp_path / "config" / "test.db",
    )


@pytest.fixture
def sig_manager(config: AntiVirusConfig) -> SignatureManager:
    """Cria um gestor de assinaturas para testes."""
    return SignatureManager(config=config)


class TestSignatureManager:
    def test_update_missing_binary(self, sig_manager: SignatureManager) -> None:
        """Update deve falhar quando freshclam não existe."""
        with pytest.raises(SignatureUpdateError, match="não encontrado"):
            sig_manager.update()

    def test_check_version_no_databases(
        self, sig_manager: SignatureManager
    ) -> None:
        """Versão deve ser None quando não há ficheiros de base de dados."""
        version = sig_manager.check_version()
        assert version is None

    def test_last_update_no_databases(
        self, sig_manager: SignatureManager
    ) -> None:
        """Last update deve ser None quando não há ficheiros .cvd/.cld."""
        result = sig_manager.last_update()
        assert result is None

    def test_parse_signatures_added(self) -> None:
        """Testa a extração do número de assinaturas da saída."""
        output = "Downloading fresh signatures\n2500 added\nDone"
        count = SignatureManager._parse_signatures_added(output)
        assert count == 2500

    def test_parse_signatures_added_none(self) -> None:
        """Testa quando não há informação de assinaturas."""
        output = "No updates available"
        count = SignatureManager._parse_signatures_added(output)
        assert count == 0

    def test_parse_new_version(self) -> None:
        """Testa a extração da nova versão."""
        output = "Database updated. New version: 27456"
        version = SignatureManager._parse_new_version(output)
        assert version is not None
        assert "27456" in version

    def test_parse_new_version_none(self) -> None:
        """Testa quando não há versão na saída."""
        output = "No updates available"
        version = SignatureManager._parse_new_version(output)
        assert version is None

    def test_read_cvd_version(self, tmp_path: Path) -> None:
        """Testa a leitura de versão de ficheiro CVD."""
        cvd_file = tmp_path / "test.cvd"
        header = b"ClamAV-VDB:27456:17:1234567890:1:20240101:1:1:abc123:0\n"
        padding = b"\x00" * (512 - len(header))
        cvd_file.write_bytes(header + padding)

        version = SignatureManager._read_cvd_version(cvd_file)
        assert version is not None
        assert "27456" in version

    def test_read_cvd_version_nonexistent(self, tmp_path: Path) -> None:
        """Testa leitura de ficheiro CVD inexistente."""
        version = SignatureManager._read_cvd_version(tmp_path / "nonexistent.cvd")
        assert version is None


class TestUpdateResult:
    def test_success(self) -> None:
        result = UpdateResult(success=True, message="OK", signatures_added=100)
        assert result.success is True
        assert result.signatures_added == 100

    def test_failure(self) -> None:
        result = UpdateResult(success=False, message="Falhou")
        assert result.success is False
        assert result.new_version is None
