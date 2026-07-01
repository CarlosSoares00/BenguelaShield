"""Testes do módulo de scan agendado."""

import os
import tempfile
import pytest
from pathlib import Path
from datetime import datetime


class TestSchedulerConfig:
    def test_default_config(self):
        from modules.scheduler.config import SchedulerConfig
        config = SchedulerConfig()
        assert config.quick_scan_hour == 2
        assert config.full_scan_hour == 3
        assert config.quick_scan_days == [0, 1, 2, 3, 4, 5, 6]
        assert config.full_scan_days == [6]

    def test_custom_config(self):
        from modules.scheduler.config import SchedulerConfig
        config = SchedulerConfig(
            quick_scan_hour=6,
            full_scan_hour=22,
            full_scan_days=[5, 6],
        )
        assert config.quick_scan_hour == 6
        assert config.full_scan_hour == 22
        assert config.full_scan_days == [5, 6]


class TestScheduledScanner:
    def test_init(self):
        from modules.scheduler.config import SchedulerConfig
        from modules.scheduler.scanner import ScheduledScanner
        config = SchedulerConfig()
        scanner = ScheduledScanner(config)
        assert scanner is not None

    def test_get_next_quick_scan(self):
        from modules.scheduler.config import SchedulerConfig
        from modules.scheduler.scanner import ScheduledScanner
        config = SchedulerConfig()
        scanner = ScheduledScanner(config)
        proximo = scanner.get_next_quick_scan()
        assert proximo is not None
        assert "/" in proximo

    def test_get_next_full_scan(self):
        from modules.scheduler.config import SchedulerConfig
        from modules.scheduler.scanner import ScheduledScanner
        config = SchedulerConfig()
        scanner = ScheduledScanner(config)
        proximo = scanner.get_next_full_scan()
        assert proximo is not None


class TestScanScheduler:
    def test_init(self):
        from modules.scheduler.config import SchedulerConfig
        from modules.scheduler.scheduler import ScanScheduler
        config = SchedulerConfig()
        scheduler = ScanScheduler(config)
        assert scheduler is not None

    def test_status(self):
        from modules.scheduler.config import SchedulerConfig
        from modules.scheduler.scheduler import ScanScheduler
        config = SchedulerConfig()
        scheduler = ScanScheduler(config)
        status = scheduler.get_status()
        assert "activo" in status
        assert "proximo_rapido" in status
        assert "historial" in status

    def test_history(self):
        from modules.scheduler.config import SchedulerConfig
        from modules.scheduler.scheduler import ScanScheduler
        config = SchedulerConfig()
        scheduler = ScanScheduler(config)
        history = scheduler.get_history()
        assert isinstance(history, list)

    def test_iniciar_parar(self):
        from modules.scheduler.config import SchedulerConfig
        from modules.scheduler.scheduler import ScanScheduler
        config = SchedulerConfig()
        scheduler = ScanScheduler(config)
        scheduler.iniciar()
        assert scheduler._thread is not None
        assert scheduler._thread.is_alive()
        scheduler.parar()
        assert scheduler._parar is True
        scheduler._thread.join(timeout=35)


class TestScheduledScanResult:
    def test_result_fields(self):
        from modules.scheduler.scanner import ScheduledScanResult
        result = ScheduledScanResult(
            scan_type="quick",
            paths_scanned=["C:\\test"],
            files_scanned=10,
            threats_found=1,
            duration_seconds=5.0,
            quarantined=1,
            errors=[],
        )
        assert result.scan_type == "quick"
        assert result.files_scanned == 10
        assert result.threats_found == 1