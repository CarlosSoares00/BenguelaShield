"""Script de treino do modelo comportamental do BenguelaShield.

Executar: python -m modules.behavioral.ml_trainer --synthetic
"""

from __future__ import annotations

import logging
import pickle
import sys
from pathlib import Path

try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
except ImportError as e:
    print(f"Dependência em falta: {e}\nInstale: pip install scikit-learn numpy")
    sys.exit(1)

from modules.behavioral.config import (
    ML_MODEL_PATH,
    ML_CONTAMINATION,
    ML_N_ESTIMATORS,
    ML_RANDOM_STATE,
    FEATURE_ORDER,
)

logger = logging.getLogger("BenguelaShield.Behavioral.Trainer")


def generate_synthetic_data(n_samples: int = 1000) -> np.ndarray:
    """Gera dados sintéticos de comportamento normal."""
    np.random.seed(ML_RANDOM_STATE)
    data = np.column_stack([
        np.clip(np.random.normal(12, 10, n_samples), 0, 100),
        np.clip(np.random.normal(150, 100, n_samples), 5, 2000),
        np.clip(np.random.normal(12, 6, n_samples), 1, 100).astype(float),
        np.clip(np.random.normal(4, 3, n_samples), 0, 50).astype(float),
        np.random.binomial(1, 0.5, n_samples).astype(float),
        np.random.binomial(1, 0.3, n_samples).astype(float),
        np.clip(np.random.normal(5, 3, n_samples), 0, 50).astype(float),
        np.clip(np.random.normal(3600, 1800, n_samples), 1, 86400).astype(float),
        np.random.binomial(1, 0.3, n_samples).astype(float),
        np.random.binomial(1, 0.02, n_samples).astype(float),
        np.clip(np.random.normal(1, 1, n_samples), 0, 10).astype(float),
        np.random.binomial(1, 0.05, n_samples).astype(float),
        np.random.binomial(1, 0.05, n_samples).astype(float),
        np.random.binomial(1, 0.05, n_samples).astype(float),
        np.random.binomial(1, 0.05, n_samples).astype(float),
    ])
    return data


def train(data: np.ndarray, output_path: str | None = None) -> dict:
    """Treina modelo Isolation Forest com dados recolhidos."""
    if output_path is None:
        output_path = str(ML_MODEL_PATH)

    print("=" * 60)
    print("BENGUELA SHIELD - TREINO COMPORTAMENTAL")
    print("=" * 60)
    print(f"Samples: {len(data)}")
    print(f"Features: {data.shape[1]}")
    print(f"Contamination: {ML_CONTAMINATION}")
    print(f"Estimators: {ML_N_ESTIMATORS}")

    model = IsolationForest(
        contamination=ML_CONTAMINATION,
        n_estimators=ML_N_ESTIMATORS,
        random_state=ML_RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(data)

    scores = model.decision_function(data)
    predictions = model.predict(data)
    n_anomalies = int((predictions == -1).sum())

    print(f"Score medio: {scores.mean():.4f}")
    print(f"Score desvio: {scores.std():.4f}")
    print(f"Score min: {scores.min():.4f}")
    print(f"Score max: {scores.max():.4f}")
    print(f"Anomalias detectadas nos dados de treino: {n_anomalies}/{len(data)}")
    print("=" * 60)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        pickle.dump(model, f)
    print(f"Modelo guardado: {output_path}")

    return {
        "n_samples": len(data),
        "n_features": int(data.shape[1]),
        "contamination": ML_CONTAMINATION,
        "n_estimators": ML_N_ESTIMATORS,
        "anomaly_scores_mean": float(scores.mean()),
        "anomaly_scores_std": float(scores.std()),
        "output_path": output_path,
    }


def main() -> None:
    """Ponto de entrada do script de treino."""
    import argparse

    parser = argparse.ArgumentParser(description="Treino comportamental BenguelaShield")
    parser.add_argument("--synthetic", action="store_true", help="Gerar dados sintéticos")
    parser.add_argument("--samples", type=int, default=1000, help="Número de samples")
    parser.add_argument("--output", type=str, default=str(ML_MODEL_PATH), help="Caminho saída")
    args = parser.parse_args()

    if args.synthetic:
        data = generate_synthetic_data(args.samples)
        train(data, args.output)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
