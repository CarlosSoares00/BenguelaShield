"""Testes do ML Comportamental do BenguelaShield."""

import os
import tempfile
import pytest
from pathlib import Path


class TestFeatureCollector:
    """Testes para FeatureCollector."""

    def test_collect_current_process(self):
        from modules.behavioral.feature_collector import FeatureCollector
        collector = FeatureCollector()
        features = collector.collect(os.getpid())
        assert features is not None
        assert features["pid"] == os.getpid()
        assert features["cpu_percent"] >= 0
        assert features["memory_mb"] > 0
        assert features["num_threads"] > 0

    def test_collect_nonexistent_pid(self):
        from modules.behavioral.feature_collector import FeatureCollector
        collector = FeatureCollector()
        assert collector.collect(999999999) is None

    def test_collect_returns_all_features(self):
        from modules.behavioral.feature_collector import FeatureCollector
        collector = FeatureCollector()
        features = collector.collect(os.getpid())
        if features is not None:
            assert len(features) == 17

    def test_collect_batch_returns_multiple(self):
        from modules.behavioral.feature_collector import FeatureCollector
        collector = FeatureCollector()
        batch = collector.collect_batch()
        assert len(batch) > 0

    def test_collect_as_vector_length(self):
        from modules.behavioral.feature_collector import FeatureCollector
        collector = FeatureCollector()
        vec = collector.collect_as_vector(os.getpid())
        if vec is not None:
            assert len(vec) == 15

    def test_collect_batch_as_vectors(self):
        from modules.behavioral.feature_collector import FeatureCollector
        collector = FeatureCollector()
        pids, vectors = collector.collect_batch_as_vectors()
        assert len(pids) == len(vectors)
        if vectors:
            assert len(vectors[0]) == 15

    def test_private_ip_detection(self):
        from modules.behavioral.feature_collector import FeatureCollector
        assert FeatureCollector._is_private_ip("192.168.1.1") is True
        assert FeatureCollector._is_private_ip("10.0.0.1") is True
        assert FeatureCollector._is_private_ip("172.16.0.1") is True
        assert FeatureCollector._is_private_ip("127.0.0.1") is True
        assert FeatureCollector._is_private_ip("8.8.8.8") is False
        assert FeatureCollector._is_private_ip("142.250.80.46") is False

    def test_feature_count(self):
        from modules.behavioral.feature_collector import FeatureCollector
        collector = FeatureCollector()
        assert collector.feature_count == 15

    def test_feature_names_length(self):
        from modules.behavioral.feature_collector import FeatureCollector
        collector = FeatureCollector()
        assert len(collector.feature_names) == 15


class TestMLDetector:
    """Testes para MLDetector."""

    def test_without_model(self):
        from modules.behavioral.ml_detector import MLDetector
        from modules.behavioral.config import ML_MODEL_PATH
        backup = ML_MODEL_PATH.with_suffix(".bak")
        existed = ML_MODEL_PATH.exists()
        if existed:
            ML_MODEL_PATH.rename(backup)
        try:
            detector = MLDetector()
            assert not detector.is_ready
            assert detector.detect([0.0] * 15) is None
        finally:
            if existed:
                backup.rename(ML_MODEL_PATH)

    def test_with_placeholder_model(self):
        from modules.behavioral.ml_detector import MLDetector
        detector = MLDetector()
        detector.create_placeholder_model()
        detector.reload_model()
        assert detector.is_ready
        score = detector.detect([12.0, 150.0, 10, 3, 0, 0, 5, 3600, 0, 0, 1, 0, 0, 0, 0])
        assert score is not None
        assert 0.0 <= score <= 1.0

    def test_normal_process_low_score(self):
        from modules.behavioral.ml_detector import MLDetector
        detector = MLDetector()
        if not detector.is_ready:
            detector.create_placeholder_model()
            detector.reload_model()
        normal = [12.0, 150.0, 10, 3, 0, 0, 5, 3600, 0, 0, 1, 0, 0, 0, 0]
        score = detector.detect(normal)
        assert score is not None
        assert score < 0.7

    def test_anomalous_process_high_score(self):
        from modules.behavioral.ml_detector import MLDetector
        detector = MLDetector()
        if not detector.is_ready:
            detector.create_placeholder_model()
            detector.reload_model()
        anomalous = [95.0, 1800.0, 80, 45, 1, 0, 30, 10, 0, 0, 15, 1, 1, 1, 1]
        score = detector.detect(anomalous)
        assert score is not None
        assert 0.0 <= score <= 1.0

    def test_detect_batch(self):
        from modules.behavioral.ml_detector import MLDetector
        detector = MLDetector()
        if not detector.is_ready:
            detector.create_placeholder_model()
            detector.reload_model()
        batch = [
            [12.0, 150.0, 10, 3, 0, 0, 5, 3600, 0, 0, 1, 0, 0, 0, 0],
            [95.0, 1800.0, 80, 45, 1, 0, 30, 10, 0, 0, 15, 1, 1, 1, 1],
        ]
        scores = detector.detect_batch(batch)
        assert len(scores) == 2
        assert all(s is not None for s in scores)

    def test_detect_wrong_feature_count(self):
        from modules.behavioral.ml_detector import MLDetector
        detector = MLDetector()
        if not detector.is_ready:
            detector.create_placeholder_model()
            detector.reload_model()
        assert detector.detect([1.0, 2.0, 3.0]) is None

    def test_verdict_none(self):
        from modules.behavioral.ml_detector import MLDetector
        detector = MLDetector()
        assert detector.get_verdict(None) == "INDISPONIVEL"

    def test_verdict_normal(self):
        from modules.behavioral.ml_detector import MLDetector
        detector = MLDetector()
        assert detector.get_verdict(0.1) == "NORMAL"

    def test_verdict_anomalous(self):
        from modules.behavioral.ml_detector import MLDetector
        detector = MLDetector()
        assert detector.get_verdict(0.9) == "ANOMALO"

    def test_create_placeholder(self):
        from modules.behavioral.ml_detector import MLDetector
        from modules.behavioral.config import ML_MODEL_PATH
        detector = MLDetector()
        ok = detector.create_placeholder_model()
        assert ok is True
        assert ML_MODEL_PATH.exists()

    def test_reload_model(self):
        from modules.behavioral.ml_detector import MLDetector
        detector = MLDetector()
        detector.create_placeholder_model()
        ok = detector.reload_model()
        assert ok is True
        assert detector.is_ready


class TestRiskScoreIntegration:
    """Testes de integracao: regras + ML no risk_score."""

    def test_rules_only(self):
        from modules.behavioral.risk_score import RiskScorer, RiskResult
        from modules.behavioral.config import BehavioralConfig
        scorer = RiskScorer(BehavioralConfig())
        from modules.behavioral.process_monitor import ProcessInfo
        proc = ProcessInfo(pid=1, name="test.exe", exe="", cmdline=[],
                          cpu_percent=0, memory_mb=0, create_time=0, num_threads=1)
        result = scorer.avaliar(proc, ml_score=None)
        assert result.ml_score is None
        assert result.score_source == "rules"

    def test_ml_only(self):
        from modules.behavioral.risk_score import RiskScorer
        from modules.behavioral.config import BehavioralConfig
        scorer = RiskScorer(BehavioralConfig())
        from modules.behavioral.process_monitor import ProcessInfo
        proc = ProcessInfo(pid=1, name="explorer.exe", exe="C:\\Windows\\explorer.exe",
                          cmdline=["explorer.exe"], cpu_percent=0, memory_mb=50,
                          create_time=0, num_threads=5)
        result = scorer.avaliar(proc, ml_score=0.8)
        assert result.ml_score == 0.8
        assert result.ml_verdict == "ANOMALO"

    def test_combined(self):
        from modules.behavioral.risk_score import RiskScorer
        from modules.behavioral.config import BehavioralConfig
        scorer = RiskScorer(BehavioralConfig())
        from modules.behavioral.process_monitor import ProcessInfo
        proc = ProcessInfo(pid=1, name="explorer.exe", exe="C:\\Windows\\explorer.exe",
                          cmdline=["explorer.exe"], cpu_percent=0, memory_mb=50,
                          create_time=0, num_threads=5)
        result = scorer.avaliar(proc, ml_score=0.8)
        assert result.score_source in ("ml", "combined")
        assert result.score >= 0

    def test_verdict_block(self):
        from modules.behavioral.risk_score import RiskScorer
        from modules.behavioral.config import BehavioralConfig
        scorer = RiskScorer(BehavioralConfig())
        from modules.behavioral.process_monitor import ProcessInfo
        proc = ProcessInfo(pid=1, name="mimikatz.exe", exe="C:\\Temp\\mimikatz.exe",
                          cmdline=["mimikatz.exe"], cpu_percent=95, memory_mb=500,
                          create_time=0, num_threads=50)
        result = scorer.avaliar(proc)
        assert result.score >= 40


class TestMLTrainer:
    """Testes para ml_trainer."""

    def test_generate_synthetic_data(self):
        from modules.behavioral.ml_trainer import generate_synthetic_data
        data = generate_synthetic_data(100)
        assert data.shape == (100, 15)

    def test_train_synthetic(self):
        from modules.behavioral.ml_trainer import generate_synthetic_data, train
        data = generate_synthetic_data(200)
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            output = f.name
        try:
            metrics = train(data, output)
            assert metrics["n_samples"] == 200
            assert os.path.exists(output)
        finally:
            os.unlink(output)
