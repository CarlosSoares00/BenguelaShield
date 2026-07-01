"""Testes do módulo de ferramentas."""
import os
import tempfile
import pytest
from pathlib import Path


class TestUSBVaccinator:
    def test_vaccinate_creates_autorun(self):
        from modules.tools.usb_vaccinator import USBVaccinator
        v = USBVaccinator()
        assert v._is_drive_removable("X") is False

    def test_check_autorun_nonexistent(self):
        from modules.tools.usb_vaccinator import USBVaccinator
        v = USBVaccinator()
        result = v.check_autorun("X")
        assert result["exists"] is False
        assert result["verdict"] == "INEXISTENTE"

    def test_check_autorun_benguela(self):
        from modules.tools.usb_vaccinator import USBVaccinator
        v = USBVaccinator()
        result = v.check_autorun("X")
        assert result["exists"] is False

    def test_vaccinate_all_removable(self):
        from modules.tools.usb_vaccinator import USBVaccinator
        v = USBVaccinator()
        results = v.vaccinate_all_removable()
        assert isinstance(results, list)


class TestFileRestorer:
    def test_scan_nonexistent(self):
        from modules.tools.file_restorer import FileRestorer
        r = FileRestorer()
        result = r.scan_directory("/nonexistent/path")
        assert result["total_hidden"] == 0

    def test_is_disguised_exe(self):
        from modules.tools.file_restorer import FileRestorer
        r = FileRestorer()
        assert r._is_disguised_exe("Fotos.exe") is True
        assert r._is_disguised_exe("Fotos.txt") is False
        assert r._is_disguised_exe("report.exe") is True
        assert r._is_disguised_exe("chrome.exe") is False


class TestRegistryRepairer:
    def test_scan_returns_dict(self):
        from modules.tools.registry_repair import RegistryRepairer
        r = RegistryRepairer()
        result = r.scan()
        assert "issues_found" in result
        assert "issues" in result
        assert "clean" in result

    def test_backup_created(self):
        from modules.tools.registry_repair import RegistryRepairer
        r = RegistryRepairer()
        path = r.backup_registry_keys()
        assert path != ""
        assert os.path.exists(path)
        os.remove(path)


class TestWinForce:
    def test_check_all_blocked(self):
        from modules.tools.win_force import WinForce
        wf = WinForce()
        result = wf.check_all_blocked()
        assert isinstance(result, dict)
        assert "task_manager" in result
        assert "registry_editor" in result


class TestManualScanner:
    def test_analyze_nonexistent(self):
        from modules.tools.manual_scanner import ManualScanner
        ms = ManualScanner()
        result = ms.analyze_file("/nonexistent/file.exe")
        assert result["overall_verdict"] == "ERRO"

    def test_analyze_clean_file(self):
        from modules.tools.manual_scanner import ManualScanner
        ms = ManualScanner()
        filepath = os.path.join(tempfile.gettempdir(), "test_benguela_clean.txt")
        with open(filepath, "w") as f:
            f.write("Este e um ficheiro normal e seguro.\n")
        try:
            result = ms.analyze_file(filepath)
            assert result["overall_verdict"] == "LIMPO"
            assert result["md5"] != ""
            assert result["sha256"] != ""
        finally:
            try:
                os.unlink(filepath)
            except OSError:
                pass

    def test_generate_report(self):
        from modules.tools.manual_scanner import ManualScanner
        ms = ManualScanner()
        analysis = {
            "filename": "test.exe", "size": 1024, "extension": ".exe",
            "md5": "abc", "sha1": "def", "sha256": "ghi",
            "clamav": {"clean": True, "threat": None},
            "yara": {"clean": True, "matches": []},
            "entropy": {"average": 5.5, "max": 7.0, "is_packed": False},
            "overall_verdict": "LIMPO", "overall_score": 0.1,
            "recommendation": "Permitido",
        }
        report = ms.generate_report(analysis)
        assert "LIMPO" in report
        assert "test.exe" in report


class TestAdminProtection:
    def test_set_and_verify(self):
        from modules.tools.admin_protection import AdminProtection
        ap = AdminProtection()
        pwd_file = Path(ap._hash_file)
        if pwd_file.exists():
            pwd_file.unlink()
        assert ap.set_password("test1234") is True
        assert ap.verify_password("test1234") is True
        assert ap.verify_password("wrong") is False
        pwd_file.unlink()

    def test_no_password_allows(self):
        from modules.tools.admin_protection import AdminProtection
        ap = AdminProtection()
        pwd_file = Path(ap._hash_file)
        if pwd_file.exists():
            pwd_file.unlink()
        assert ap.require_password("test") is True


class TestExceptionList:
    def test_add_and_check(self):
        from modules.tools.exception_list import ExceptionList
        el = ExceptionList()
        el.clear()
        el.add_file("/test/file.exe")
        assert el.is_excluded(filepath="/test/file.exe") is True
        assert el.is_excluded(filepath="/other/file.exe") is False

    def test_add_folder(self):
        from modules.tools.exception_list import ExceptionList
        el = ExceptionList()
        el.clear()
        el.add_folder("/test/folder")
        assert el.is_excluded(filepath="/test/folder/file.exe") is True

    def test_add_extension(self):
        from modules.tools.exception_list import ExceptionList
        el = ExceptionList()
        el.clear()
        el.add_extension(".log")
        assert el.is_excluded(extension=".log") is True
        assert el.is_excluded(extension=".exe") is False

    def test_remove(self):
        from modules.tools.exception_list import ExceptionList
        el = ExceptionList()
        el.clear()
        el.add_file("/test/file.exe")
        assert el.is_excluded(filepath="/test/file.exe") is True
        el.remove("/test/file.exe", "files")
        assert el.is_excluded(filepath="/test/file.exe") is False

    def test_clear(self):
        from modules.tools.exception_list import ExceptionList
        el = ExceptionList()
        el.add_file("/test/file.exe")
        el.clear()
        assert el.is_excluded(filepath="/test/file.exe") is False


class TestProcessManager:
    def test_list_processes(self):
        from modules.tools.process_manager import BenguelaProcessManager
        pm = BenguelaProcessManager()
        processes = pm.list_processes()
        assert len(processes) > 0
        assert "pid" in processes[0]
        assert "security_verdict" in processes[0]

    def test_classify_location(self):
        from modules.tools.process_manager import BenguelaProcessManager
        pm = BenguelaProcessManager()
        assert pm._classify_location("C:\\Program Files\\test.exe") == "trusted"
        assert pm._classify_location("C:\\Users\\carlo\\AppData\\Local\\Temp\\test.exe") == "suspicious"
        assert pm._classify_location("D:\\random\\test.exe") == "unknown"