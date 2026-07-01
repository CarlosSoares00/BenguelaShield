import sys, logging, argparse
from pathlib import Path
try:
    import lightgbm as lgb
    import numpy as np
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
except ImportError as e:
    print(f"Dependencia: {e}\nInstale: pip install lightgbm numpy scikit-learn")
    sys.exit(1)
from modules.ai.config import MODELS_DIR, CLASSIFIER_MODEL_PATH, FEATURE_NAMES, LGBM_PARAMS
logger = logging.getLogger("BenguelaShield.AI.Trainer")

def generate_synthetic():
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
    return X[idx], y[idx]

def train_model(X, y, output_path):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    train_data = lgb.Dataset(X_train, label=y_train, feature_name=FEATURE_NAMES)
    test_data = lgb.Dataset(X_test, label=y_test, feature_name=FEATURE_NAMES)
    model = lgb.train(LGBM_PARAMS, train_data, valid_sets=[test_data], num_boost_round=200, callbacks=[lgb.log_evaluation(50)])
    y_pred = (model.predict(X_test) >= 0.5).astype(int)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    print("=" * 60)
    print("BENGUELA SHIELD — RELATORIO DE TREINO IA")
    print("=" * 60)
    print(f"Dataset: {len(y)} ({sum(y==0)} clean, {sum(y==1)} malware)")
    print(f"Treino: {len(y_train)} | Teste: {len(y_test)}")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print("=" * 60)
    model.save_model(output_path)
    print(f"Modelo guardado: {output_path}")
    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1}

def main():
    parser = argparse.ArgumentParser(description="Treino IA BenguelaShield")
    parser.add_argument("--synthetic", action="store_true")
    parser.add_argument("--output", type=str, default=str(CLASSIFIER_MODEL_PATH))
    args = parser.parse_args()
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    if args.synthetic:
        X, y = generate_synthetic()
        train_model(X, y, args.output)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()