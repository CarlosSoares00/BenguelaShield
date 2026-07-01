"""Detector de anomalias por Machine Learning do BenguelaShield.

Usa Isolation Forest do scikit-learn para detectar comportamentos
anómalos em processos. Aprende o que é "normal" e detecta desvios.
"""

from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Optional

try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
except ImportError:
    IsolationForest = None
    np = None

from modules.behavioral.config import (
    ML_MODEL_PATH,
    ML_CONTAMINATION,
    ML_N_ESTIMATORS,
    ML_RANDOM_STATE,
    ML_ANOMALY_THRESHOLD,
    ML_WARNING_THRESHOLD,
    FEATURE_ORDER,
)

logger = logging.getLogger("BenguelaShield.Behavioral.ML")


class MLDetector:
    """Detector de comportamento anómalo usando Isolation Forest."""

    def __init__(self) -> None:
        self.model: Optional[IsolationForest] = None
        self._load_model()

    def _load_model(self) -> bool:
        """Carrega modelo Isolation Forest do disco."""
        if IsolationForest is None:
            logger.error("scikit-learn não instalado")
            return False

        if not ML_MODEL_PATH.exists():
            logger.warning("Modelo comportamental não encontrado: %s", ML_MODEL_PATH)
            return False

        try:
            with open(ML_MODEL_PATH, "rb") as f:
                self.model = pickle.load(f)
            logger.info("Modelo comportamental carregado: %s", ML_MODEL_PATH)
            return True
        except Exception as e:
            logger.error("Erro ao carregar modelo comportamental: %s", e)
            return False

    def detect(self, features: list[float]) -> Optional[float]:
        """Calcula score de anomalia para um processo.

        Args:
            features: Lista de 15 floats (vector do feature_collector).

        Returns:
            float entre 0.0 (normal) e 1.0 (anómalo), ou None se erro.
        """
        if self.model is None:
            return None
        if len(features) != len(FEATURE_ORDER):
            return None

        try:
            features_array = np.array([features])
            score_raw = self.model.decision_function(features_array)[0]
            score = max(0.0, min(1.0, 0.5 - score_raw))
            return float(score)
        except Exception as e:
            logger.error("Erro no ML detect: %s", e)
            return None

    def detect_batch(self, features_batch: list[list[float]]) -> list[Optional[float]]:
        """Calcula score de anomalia para múltiplos processos."""
        if self.model is None:
            return [None] * len(features_batch)

        valid_indices = [i for i, f in enumerate(features_batch) if len(f) == len(FEATURE_ORDER)]
        if not valid_indices:
            return [None] * len(features_batch)

        valid_features = [features_batch[i] for i in valid_indices]

        try:
            features_array = np.array(valid_features)
            scores_raw = self.model.decision_function(features_array)
            scores = [max(0.0, min(1.0, 0.5 - s)) for s in scores_raw]

            results: list[Optional[float]] = [None] * len(features_batch)
            for i, idx in enumerate(valid_indices):
                results[idx] = float(scores[i])
            return results
        except Exception as e:
            logger.error("Erro no ML detect_batch: %s", e)
            return [None] * len(features_batch)

    @property
    def is_ready(self) -> bool:
        """True se modelo está carregado e pronto."""
        return self.model is not None

    def get_verdict(self, score: Optional[float]) -> str:
        """Converte score em veredicto legível."""
        if score is None:
            return "INDISPONIVEL"
        if score < 0.3:
            return "NORMAL"
        if score < 0.5:
            return "ATENCAO"
        if score < 0.7:
            return "SUSPEITO"
        return "ANOMALO"

    def create_placeholder_model(self) -> bool:
        """Cria modelo treinado com dados sintéticos como placeholder."""
        if IsolationForest is None or np is None:
            logger.warning("scikit-learn/numpy nao disponiveis")
            return False

        n = 1000
        np.random.seed(ML_RANDOM_STATE)
        data = np.column_stack([
            np.clip(np.random.normal(12, 10, n), 0, 100),
            np.clip(np.random.normal(150, 100, n), 5, 2000),
            np.clip(np.random.normal(12, 6, n), 1, 100).astype(float),
            np.clip(np.random.normal(4, 3, n), 0, 50).astype(float),
            np.random.binomial(1, 0.5, n).astype(float),
            np.random.binomial(1, 0.3, n).astype(float),
            np.clip(np.random.normal(5, 3, n), 0, 50).astype(float),
            np.clip(np.random.normal(3600, 1800, n), 1, 86400).astype(float),
            np.random.binomial(1, 0.3, n).astype(float),
            np.random.binomial(1, 0.02, n).astype(float),
            np.clip(np.random.normal(1, 1, n), 0, 10).astype(float),
            np.random.binomial(1, 0.05, n).astype(float),
            np.random.binomial(1, 0.05, n).astype(float),
            np.random.binomial(1, 0.05, n).astype(float),
            np.random.binomial(1, 0.05, n).astype(float),
        ])

        model = IsolationForest(
            contamination=ML_CONTAMINATION,
            n_estimators=ML_N_ESTIMATORS,
            random_state=ML_RANDOM_STATE,
            n_jobs=-1,
        )
        model.fit(data)

        ML_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(ML_MODEL_PATH, "wb") as f:
            pickle.dump(model, f)

        logger.info("Modelo placeholder criado com %d samples", n)
        return True

    def reload_model(self) -> bool:
        """Recarrega modelo do disco."""
        self.model = None
        return self._load_model()
