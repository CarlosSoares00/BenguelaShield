import logging, time
from datetime import datetime
from pathlib import Path
try:
    import lightgbm as lgb
    import numpy as np
except ImportError:
    lgb = None
    np = None
from modules.ai.config import MODELS_DIR, CLASSIFIER_MODEL_PATH, FEATURE_NAMES, LGBM_PARAMS

logger = logging.getLogger("BenguelaShield.AI.ModelManager")

class ModelManager:
    def __init__(self):
        MODELS_DIR.mkdir(parents=True, exist_ok=True)

    def load_classifier(self):
        if lgb is None or not CLASSIFIER_MODEL_PATH.exists():
            return None
        try:
            return lgb.Booster(model_file=str(CLASSIFIER_MODEL_PATH))
        except Exception:
            return None

    def update_model(self, source_path: str) -> bool:
        src = Path(source_path)
        if not src.exists():
            return False
        try:
            lgb.Booster(model_file=str(src))
            import shutil
            shutil.copy2(str(src), str(CLASSIFIER_MODEL_PATH))
            return True
        except Exception as e:
            logger.error("Modelo invalido: %s", e)
            return False

    def get_model_info(self) -> dict:
        exists = CLASSIFIER_MODEL_PATH.exists()
        info = {"exists": exists, "path": str(CLASSIFIER_MODEL_PATH), "num_features": len(FEATURE_NAMES)}
        if exists:
            st = CLASSIFIER_MODEL_PATH.stat()
            info["size_bytes"] = st.st_size
            info["size_mb"] = round(st.st_size / (1024 * 1024), 2)
            info["modified"] = datetime.fromtimestamp(st.st_mtime).isoformat()
            info["version"] = "placeholder"
        else:
            info["size_bytes"] = 0
            info["size_mb"] = 0
            info["modified"] = None
            info["version"] = "nenhum"
        return info

    def create_placeholder_model(self) -> bool:
        if lgb is None or np is None:
            logger.warning("lightgbm/numpy nao disponiveis")
            return False
        logger.info("A criar modelo placeholder...")
        n = 1000
        np.random.seed(42)
        clean = np.column_stack([
            np.clip(np.random.normal(6, 2, n), 1, 15),
            np.clip(np.random.normal(6.0, 0.5, n), 2, 8),
            np.clip(np.random.normal(6.8, 0.5, n), 3, 8),
            np.clip(np.random.normal(4.5, 1.0, n), 0, 7),
            np.clip(np.random.normal(100, 50, n), 0, 500),
            np.clip(np.random.normal(1, 1, n), 0, 10),
            np.random.binomial(1, 0.2, n), np.random.binomial(1, 0.05, n),
            np.random.binomial(1, 0.02, n), np.random.binomial(1, 0.1, n),
            np.clip(np.random.normal(200000, 100000, n), 1000, 5000000),
            np.clip(np.random.normal(10000, 5000, n), 0, 100000),
            np.random.binomial(1, 0.05, n), np.random.binomial(1, 0.7, n),
            np.clip(np.random.normal(10, 5, n), 0, 30),
            np.random.binomial(1, 0.05, n),
            np.clip(np.random.normal(1024, 256, n), 256, 4096),
            np.clip(np.random.normal(1700000000, 50000000, n), 1000000000, 2000000000),
            np.random.binomial(1, 0.05, n), np.random.binomial(1, 0.2, n),
            np.random.binomial(1, 0.9, n), np.random.binomial(1, 0.02, n),
        ])
        malware = np.column_stack([
            np.clip(np.random.normal(3, 1, n), 1, 8),
            np.clip(np.random.normal(7.2, 0.4, n), 5, 8),
            np.clip(np.random.normal(7.6, 0.3, n), 6, 8),
            np.clip(np.random.normal(6.5, 0.8, n), 4, 8),
            np.clip(np.random.normal(20, 15, n), 0, 100),
            np.clip(np.random.normal(6, 2, n), 0, 15),
            np.random.binomial(1, 0.8, n), np.random.binomial(1, 0.6, n),
            np.random.binomial(1, 0.4, n), np.random.binomial(1, 0.5, n),
            np.clip(np.random.normal(50000, 30000, n), 1000, 500000),
            np.clip(np.random.normal(1000, 500, n), 0, 10000),
            np.random.binomial(1, 0.3, n), np.random.binomial(1, 0.1, n),
            np.clip(np.random.normal(1, 1, n), 0, 5),
            np.random.binomial(1, 0.8, n),
            np.clip(np.random.normal(512, 128, n), 256, 2048),
            np.random.choice([0, 1700000000, 1600000000], n),
            np.random.binomial(1, 0.3, n), np.random.binomial(1, 0.6, n),
            np.random.binomial(1, 0.4, n), np.random.binomial(1, 0.4, n),
        ])
        X = np.vstack([clean, malware]).astype(np.float32)
        y = np.array([0] * n + [1] * n)
        idx = np.random.permutation(len(y))
        X, y = X[idx], y[idx]
        train = lgb.Dataset(X[:1600], label=y[:1600], feature_name=FEATURE_NAMES)
        valid = lgb.Dataset(X[1600:], label=y[1600:], feature_name=FEATURE_NAMES)
        model = lgb.train(LGBM_PARAMS, train, valid_sets=[valid], num_boost_round=200, callbacks=[lgb.log_evaluation(50)])
        model.save_model(str(CLASSIFIER_MODEL_PATH))
        preds = (model.predict(X[1600:]) >= 0.5).astype(int)
        acc = float(np.mean(preds == y[1600:]))
        logger.info("Modelo placeholder criado. Accuracy: %.2f%%", acc * 100)
        return True

    def validate_model(self, model_path: str) -> tuple[bool, str]:
        p = Path(model_path)
        if not p.exists():
            return False, "Ficheiro nao existe"
        try:
            m = lgb.Booster(model_file=str(p))
            return True, f"OK ({m.num_feature()} features)"
        except Exception as e:
            return False, str(e)