"""Testes do scanner anti-vírus BenguelaShield."""

from __future__ import annotations

import os
import socket
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules.antivirus.scanner import (
    ClamAVConnectionError,
    ClamAVScanner,
    ScanResult,
    ScanTimeoutError,
)
from modules.antivirus.config import AntiVirusConfig


@pytest.fixture
def config(tmp_path: Path) -> AntiVirusConfig:
    """Cria uma configuração para testes."""
    return AntiVirusConfig(
        clamd_host="127.0.0.1",
        clamd_port=3310,
        scan_timeout=5,
        base_dir=tmp_path,
        quarantine_dir=tmp_path / "quarantine",
        db_path=tmp_path / "config" / "test.db",
    )


@pytest.fixture
def scanner(config: AntiVirusConfig) -> ClamAVScanner:
    """Cria um scanner para testes."""
    return ClamAVScanner(config=config)


class TestClamAVConnectionError:
    def test_is_exception(self) -> None:
        assert issubclass(ClamAVConnectionError, Exception)

    def test_can_be_raised(self) -> None:
        with pytest.raises(ClamAVConnectionError):
            raise ClamAVConnectionError("teste")


class TestScanTimeoutError:
    def test_is_exception(self) -> None:
        assert issubclass(ScanTimeoutError, Exception)


class TestScanResult:
    def test_defaults(self) -> None:
        result = ScanResult(filepath="/test/file.exe", status="OK")
        assert result.filepath == "/test/file.exe"
        assert result.status == "OK"
        assert result.threat_name is None
        assert result.scan_time == 0.0
        assert result.action_taken is None
        assert result.error_message is None

    def test_found(self) -> None:
        result = ScanResult(
            filepath="/test/malware.exe",
            status="FOUND",
            threat_name="EICAR-Test-File",
            scan_time=1.5,
        )
        assert result.status == "FOUND"
        assert result.threat_name == "EICAR-Test-File"


class TestClamAVScannerPing:
    def test_ping_returns_false_on_connection_refused(
        self, scanner: ClamAVScanner
    ) -> None:
        """PING deve retornar False quando clamd não está a correr."""
        assert scanner.ping() is False

    def test_ping_success(self, scanner: ClamAVScanner) -> None:
        """PING deve retornar True quando clamd responde PONG."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"PONG\n"
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch("socket.create_connection", return_value=mock_sock):
            assert scanner.ping() is True

    def test_ping_wrong_response(self, scanner: ClamAVScanner) -> None:
        """PING deve retornar False quando clamd responde algo inesperado."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"ERROR\n"
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch("socket.create_connection", return_value=mock_sock):
            assert scanner.ping() is False


class TestClamAVScannerVersion:
    def test_version_returns_none_on_failure(
        self, scanner: ClamAVScanner
    ) -> None:
        assert scanner.get_version() is None

    def test_version_success(self, scanner: ClamAVScanner) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"VERSION: ClamAV 1.5.2\n"
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch("socket.create_connection", return_value=mock_sock):
            version = scanner.get_version()
            assert version is not None
            assert "1.5.2" in version


class TestClamAVScannerScanFile:
    def test_scan_nonexistent_file(self, scanner: ClamAVScanner) -> None:
        result = scanner.scan_file("/nonexistent/file.exe")
        assert result.status == "ERROR"
        assert "não encontrado" in (result.error_message or "")

    def test_scan_file_ok(self, scanner: ClamAVScanner, tmp_path: Path) -> None:
        test_file = tmp_path / "clean.txt"
        test_file.write_text("conteúdo limpo")

        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [b"clean.txt: OK\n", b""]
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.shutdown = MagicMock()

        with patch("socket.create_connection", return_value=mock_sock):
            result = scanner.scan_file(str(test_file))
            assert result.status == "OK"
            assert result.threat_name is None

    def test_scan_file_found(
        self, scanner: ClamAVScanner, tmp_path: Path
    ) -> None:
        test_file = tmp_path / "suspect_test.txt"
        test_file.write_bytes(b"\x00" * 100)

        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [b"suspect_test.txt: Test-Signature FOUND\n", b""]
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.shutdown = MagicMock()

        with patch("socket.create_connection", return_value=mock_sock):
            result = scanner.scan_file(str(test_file))
            assert result.status == "FOUND"
            assert result.threat_name is not None
            assert "Test-Signature" in result.threat_name

    def test_scan_file_clamd_unavailable(
        self, scanner: ClamAVScanner, tmp_path: Path
    ) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("teste")

        with patch(
            "socket.create_connection",
            side_effect=ConnectionRefusedError("Connection refused"),
        ):
            with pytest.raises(ClamAVConnectionError):
                scanner.scan_file(str(test_file))


class TestClamAVScannerParseResponse:
    def test_parse_ok(self) -> None:
        status, threat = ClamAVScanner._parse_clamd_response("file.txt: OK")
        assert status == "OK"
        assert threat is None

    def test_parse_found(self) -> None:
        status, threat = ClamAVScanner._parse_clamd_response(
            "malware.exe: EICAR-Signature FOUND"
        )
        assert status == "FOUND"
        assert threat == "EICAR-Signature"

    def test_parse_empty(self) -> None:
        status, threat = ClamAVScanner._parse_clamd_response("")
        assert status == "ERROR"

    def test_parse_unknown_format(self) -> None:
        status, threat = ClamAVScanner._parse_clamd_response("something weird")
        assert status == "ERROR"


class TestClamAVScannerQuickScan:
    def test_quick_scan_empty_paths(self, config: AntiVirusConfig) -> None:
        config.quick_scan_paths = []
        scanner = ClamAVScanner(config=config)
        results = scanner.quick_scan()
        assert results == []


class TestClamAVScannerCustomScan:
    def test_custom_scan_nonexistent_path(self, scanner: ClamAVScanner) -> None:
        results = scanner.custom_scan(["/nonexistent/path"])
        assert len(results) == 1
        assert results[0].status == "ERROR"

    def test_custom_scan_empty_list(self, scanner: ClamAVScanner) -> None:
        results = scanner.custom_scan([])
        assert results == []
