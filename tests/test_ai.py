import sys, os, tempfile
import pytest
from pathlib import Path

class TestEntropyAnalyzer:
    def test_entropy_zeros(self):
        from modules.ai.entropy_analyzer import EntropyAnalyzer
        ea = EntropyAnalyzer()
        data = bytes(256)
        assert ea._calculate_entropy(data) == 0.0

    def test_analyze_nonexistent(self):
        from modules.ai.entropy_analyzer import EntropyAnalyzer
        ea = EntropyAnalyzer()
        assert ea.analyze("/nonexistent/file.exe") is None

class TestFeatureExtractor:
    def test_feature_names(self):
        from modules.ai.feature_extractor import FeatureExtractor
        fe = FeatureExtractor()
        assert len(fe.feature_names) == 22

class TestFileClassifier:
    def test_verdict_clean(self):
        from modules.ai.file_classifier import FileClassifier
        fc = FileClassifier()
        assert fc.get_verdict(0.1) == "LIMPO"

    def test_verdict_malware(self):
        from modules.ai.file_classifier import FileClassifier
        fc = FileClassifier()
        assert fc.get_verdict(0.8) == "MALWARE"

    def test_verdict_none(self):
        from modules.ai.file_classifier import FileClassifier
        fc = FileClassifier()
        assert fc.get_verdict(None) == "INDISPONIVEL"

class TestModelManager:
    def test_model_info(self):
        from modules.ai.model_manager import ModelManager
        mm = ModelManager()
        info = mm.get_model_info()
        assert "exists" in info
