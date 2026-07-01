"""Testes do módulo anti-ransomware."""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

import pytest

from modules.antiransom.config import AntiRansomConfig
from modules.antiransom.backup import BackupManager, BackupEntry
from modules.antiransom.encryption_detect import EncryptionDetector, EncryptionAlert
from modules.antiransom.honeypot import HoneypotManager
from modules.antiransom.folder_shield import FolderShield


@pytest.fixture
def config(tmp_path: Path) -> AntiRansomConfig:
    return AntiRansomConfig(
        base_dir=tmp_path,
        backup_dir=tmp_path / "backup",
        protected_dirs=[],
    )


@pytest.fixture
def test_dir(config: AntiRansomConfig, tmp_path: Path) -> Path:
    d = tmp_path / "protected"
    d.mkdir()
    config.protected_dirs.append(str(d))
    return d


# ── BackupManager ──────────────────────────────────────────

class TestBackupManager:
    def test_backup_e_restauracao(self, config: AntiRansomConfig, test_dir: Path) -> None:
        bm = BackupManager(config)
        f = test_dir / "doc.txt"
        f.write_text("versao original")

        ok = bm.antes_de_modificar(str(f))
        assert ok is True

        f.write_text("versao modificada")
        assert f.read_text() == "versao modificada"

        restored = bm.restaurar(str(f))
        assert restored is not None
        assert f.read_text() == "versao original"

    def test_limite_versoes(self, config: AntiRansomConfig, test_dir: Path) -> None:
        config.backup_max_versions = 2
        bm = BackupManager(config)
        f = test_dir / "doc.txt"

        for i in range(5):
            f.write_text(f"versao {i}")
            bm.antes_de_modificar(str(f))

        versoes = bm.listar_versoes(str(f))
        assert len(versoes) <= 2

    def test_listar_versoes(self, config: AntiRansomConfig, test_dir: Path) -> None:
        bm = BackupManager(config)
        f = test_dir / "doc.txt"
        f.write_text("v1")
        bm.antes_de_modificar(str(f))
        f.write_text("v2")
        bm.antes_de_modificar(str(f))

        versoes = bm.listar_versoes(str(f))
        assert len(versoes) == 2
        assert versoes[0].timestamp >= versoes[1].timestamp

    def test_ficheiro_inexistente(self, config: AntiRansomConfig) -> None:
        bm = BackupManager(config)
        assert bm.antes_de_modificar("/nonexistent.txt") is False

    def test_backup_grande(self, config: AntiRansomConfig, test_dir: Path) -> None:
        config.backup_max_size_mb = 1
        bm = BackupManager(config)
        f = test_dir / "grande.bin"
        f.write_bytes(b"\x00" * (2 * 1024 * 1024))
        bm.antes_de_modificar(str(f))
        assert bm.tamanho_total() <= config.backup_max_size_mb * 1024 * 1024


# ── EncryptionDetector ─────────────────────────────────────

class TestEncryptionDetector:
    def test_sem_ameaca(self, config: AntiRansomConfig) -> None:
        ed = EncryptionDetector(config)
        for i in range(5):
            ed.registar_modificacao(f"/test/file_{i}.txt", 100, 110)
        assert ed.verificar() is None

    def test_ameaca_detectada(self, config: AntiRansomConfig) -> None:
        config.encryption_rate_threshold = 5
        ed = EncryptionDetector(config)
        for i in range(10):
            ed.registar_modificacao(f"/test/file_{i}.txt", 100, 10000)
        alert = ed.verificar()
        assert alert is not None
        assert alert.files_modified == 10
        assert alert.severity in ("medium", "high", "critical")

    def test_renames_suspeitos(self, config: AntiRansomConfig) -> None:
        config.encryption_rate_threshold = 2
        ed = EncryptionDetector(config)
        ed.registar_modificacao("/test/file.locked", 100, 200)
        ed.registar_modificacao("/test/file2.crypto", 100, 200)
        ed.registar_modificacao("/test/file3.txt", 100, 200)
        alert = ed.verificar()
        assert alert is not None
        assert len(alert.suspicious_renames) == 2

    def test_entropy_spike(self, config: AntiRansomConfig) -> None:
        config.encryption_rate_threshold = 1
        ed = EncryptionDetector(config)
        ed.registar_modificacao("/test/doc.txt", 200, 5000)
        alert = ed.verificar()
        assert alert is not None
        assert alert.entropy_spike_detected is True

    def test_callback(self, config: AntiRansomConfig) -> None:
        config.encryption_rate_threshold = 2
        ed = EncryptionDetector(config)
        alerts = []
        ed.set_alert_callback(lambda a: alerts.append(a))
        for i in range(5):
            ed.registar_modificacao(f"/test/file_{i}.txt", 100, 5000)
        ed.verificar()
        assert len(alerts) == 1

    def test_limpar_eventos_antigos(self, config: AntiRansomConfig) -> None:
        config.encryption_time_window = 1.0
        config.encryption_rate_threshold = 5
        ed = EncryptionDetector(config)
        for i in range(10):
            ed.registar_modificacao(f"/test/file_{i}.txt", 100, 10000)
        time.sleep(2)
        assert ed.verificar() is None


# ── HoneypotManager ────────────────────────────────────────

class TestHoneypotManager:
    def test_criar_e_remover(self, config: AntiRansomConfig, test_dir: Path) -> None:
        hm = HoneypotManager(config)
        count = hm.criar_honeypots()
        assert count > 0
        assert hm.honeypots_activos() == count

        removed = hm.remover_honeypots()
        assert removed == count
        assert hm.honeypots_activos() == 0

    def test_honeypots_disabled(self, config: AntiRansomConfig, test_dir: Path) -> None:
        config.honeypot_enabled = False
        hm = HoneypotManager(config)
        assert hm.criar_honeypots() == 0

    def test_nao_duplicar(self, config: AntiRansomConfig, test_dir: Path) -> None:
        hm = HoneypotManager(config)
        hm.criar_honeypots()
        count2 = hm.criar_honeypots()
        assert count2 == 0


# ── FolderShield ───────────────────────────────────────────

class TestFolderShield:
    def test_iniciar_e_parar(self, config: AntiRansomConfig, test_dir: Path) -> None:
        fs = FolderShield(config)
        honeypots = fs.iniciar()
        assert fs.esta_activo() is True
        assert honeypots > 0
        fs.parar()
        assert fs.esta_activo() is False

    def test_status(self, config: AntiRansomConfig, test_dir: Path) -> None:
        config.protected_dirs = [str(test_dir)]
        fs = FolderShield(config)
        fs.iniciar()
        s = fs.status()
        assert s["activo"] is True
        assert s["pastas_protegidas"] == 1
        fs.parar()

    def test_backup_automatico(self, config: AntiRansomConfig, test_dir: Path) -> None:
        fs = FolderShield(config)
        fs.iniciar()

        f = test_dir / "importante.txt"
        f.write_text("original")
        time.sleep(0.5)

        f.write_text("modificado")
        time.sleep(1)

        versoes = fs.backup.listar_versoes(str(f))
        assert len(versoes) >= 1

        fs.parar()

    def test_callback_amemaca(self, config: AntiRansomConfig, test_dir: Path) -> None:
        fs = FolderShield(config)
        ameacas = []
        fs.set_threat_callback(lambda a: ameacas.append(a))
        fs.iniciar()
        fs.parar()
