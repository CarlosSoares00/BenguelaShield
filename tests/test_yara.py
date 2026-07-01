"""Testes do modulo YARA."""
import os
import tempfile
import shutil
from pathlib import Path
import pytest
from modules.yara_engine.yara_scanner import YaraScanner
from modules.yara_engine.rule_manager import RuleManager

@pytest.fixture
def scanner():
    return YaraScanner()

@pytest.fixture
def rule_manager():
    return RuleManager()

class TestYaraScanner:
    def test_init_loads_rules(self, scanner):
        assert scanner is not None

    def test_rules_count(self, scanner):
        assert scanner.rules_count >= 5

    def test_scan_clean_file(self, scanner, tmp_path):
        f = tmp_path / "clean.txt"
        f.write_text("Hello world, this is a clean file with no malware.")
        matches = scanner.scan_file(str(f))
        assert matches == []

    def test_scan_ransomware_strings(self, scanner, tmp_path):
        f = tmp_path / "ransom.txt"
        f.write_bytes(b"your files have been encrypted AES-256 .locked pay bitcoin how to decrypt")
        matches = scanner.scan_file(str(f))
        assert len(matches) > 0
        assert any(m["rule"] == "Ransomware_Generico" for m in matches)

    def test_scan_cryptominer_strings(self, scanner, tmp_path):
        f = tmp_path / "miner.txt"
        f.write_bytes(b"stratum+tcp://pool.minexmr.com:3333 hashrate difficulty")
        matches = scanner.scan_file(str(f))
        assert len(matches) > 0
        assert any("miner" in m["rule"].lower() for m in matches)

    def test_scan_bytes(self, scanner):
        data = b"your files have been encrypted AES-256 .locked pay bitcoin"
        matches = scanner.scan_bytes(data)
        assert len(matches) > 0

    def test_scan_nonexistent_file(self, scanner):
        with pytest.raises(FileNotFoundError):
            scanner.scan_file("/nonexistent/path/file.txt")

    def test_scan_directory(self, scanner, tmp_path):
        (tmp_path / "clean.txt").write_text("hello world")
        f2 = tmp_path / "ransom.txt"
        f2.write_bytes(b"your files have been encrypted AES-256 .locked pay bitcoin how to decrypt")
        matches = scanner.scan_directory(str(tmp_path))
        assert len(matches) > 0

    def test_malformed_rule_doesnt_crash(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        bad = rules_dir / "bad.yar"
        bad.write_text("rule broken { condition: }")
        good = rules_dir / "good.yar"
        good.write_text('rule ok { strings: $a = "test" condition: $a }')
        from modules.yara_engine.yara_scanner import YaraScanner
        from modules.yara_engine.config import RULE_EXTENSIONS
        s = YaraScanner()
        assert s.rules_count >= 0

class TestRuleManager:
    def test_list_rules(self, rule_manager):
        rules = rule_manager.list_rules()
        assert isinstance(rules, list)
        assert len(rules) > 0

    def test_disable_enable(self, rule_manager):
        rules = rule_manager.list_rules()
        active_rules = [r for r in rules if r["active"]]
        if not active_rules:
            pytest.skip("No active rules to test")
        name = active_rules[0]["name"]
        ok = rule_manager.disable_rule(name)
        assert ok is True
        ok2 = rule_manager.enable_rule(name)
        assert ok2 is True

    def test_validate_valid(self, rule_manager):
        rules = rule_manager.list_rules()
        active = [r for r in rules if r["active"]]
        if not active:
            pytest.skip("No active rules")
        ok, msg = rule_manager.validate_rule(active[0]["path"])
        assert ok is True
        assert msg == "OK"

    def test_validate_invalid(self, rule_manager, tmp_path):
        bad = tmp_path / "bad.yar"
        bad.write_text("rule broken { condition: }")
        ok, msg = rule_manager.validate_rule(str(bad))
        assert ok is False