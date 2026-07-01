import logging
from pathlib import Path
try:
    import lightgbm as lgb
except ImportError:
    lgb = None
from modules.ai.config import CLASSIFIER_MODEL_PATH, MALWARE_THRESHOLD, SUSPICIOUS_THRESHOLD, FEATURE_NAMES
from modules.ai.feature_extractor import FeatureExtractor

logger = logging.getLogger("BenguelaShield.AI.Classifier")

class FileClassifier:
    def __init__(self):
        self.model = None
        self.feature_extractor = FeatureExtractor()
        self._load_model()

    def _load_model(self) -> bool:
        if lgb is None:
            return False
        if not CLASSIFIER_MODEL_PATH.exists():
            return False
        try:
            self.model = lgb.Booster(model_file=str(CLASSIFIER_MODEL_PATH))
            logger.info("Modelo LightGBM carregado")
            return True
        except Exception as e:
            logger.error("Erro ao carregar modelo: %s", e)
            self.model = None
            return False

    def classify(self, filepath: str) -> float | None:
        if self.model is None:
            return None
        vec = self.feature_extractor.extract_to_vector(filepath)
        if vec is None:
            return None
        try:
            score = float(self.model.predict([vec])[0])
            return max(0.0, min(1.0, score))
        except Exception as e:
            logger.error("Erro classificar %s: %s", filepath, e)
            return None

    def classify_features(self, features: list[float]) -> float | None:
        if self.model is None:
            return None
        if len(features) != len(FEATURE_NAMES):
            return None
        try:
            return float(self.model.predict([features])[0])
        except Exception:
            return None

    @property
    def is_ready(self) -> bool:
        return self.model is not None

    def get_verdict(self, score: float | None) -> str:
        if score is None:
            return "INDISPONIVEL"
        if score >= MALWARE_THRESHOLD:
            return "MALWARE"
        if score >= SUSPICIOUS_THRESHOLD:
            return "SUSPEITO"
        return "LIMPO"

    def get_verdict_details(self, score: float | None) -> dict:
        if score is None:
            return {"score": None, "verdict": "INDISPONIVEL", "color": "gray", "action": "PERMITIR", "confidence": "nenhuma"}
        if score < 0.2:
            return {"score": score, "verdict": "LIMPO", "color": "green", "action": "PERMITIR", "confidence": "alta"}
        if score < 0.4:
            return {"score": score, "verdict": "LIMPO", "color": "green", "action": "PERMITIR", "confidence": "media"}
        if score < 0.55:
            return {"score": score, "verdict": "SUSPEITO", "color": "yellow", "action": "QUARENTENA", "confidence": "baixa"}
        if score < 0.7:
            return {"score": score, "verdict": "SUSPEITO", "color": "yellow", "action": "QUARENTENA", "confidence": "media"}
        if score < 0.85:
            return {"score": score, "verdict": "MALWARE", "color": "red", "action": "BLOQUEAR", "confidence": "alta"}
        return {"score": score, "verdict": "MALWARE", "color": "red", "action": "BLOQUEAR", "confidence": "muito alta"}

    def reload_model(self) -> bool:
        self.model = None
        return self._load_model()