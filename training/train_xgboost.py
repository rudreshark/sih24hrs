"""Supervised XGBoost training and artifact export for DIODESHIELD."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np

try:
    import xgboost as xgb
except ImportError:
    xgb = None


def train_xgboost_synthetic(
    output_dir: Path,
    X_train: np.ndarray,
    y_train: np.ndarray,
    feature_names: list[str],
) -> dict[str, Any]:
    """Train XGBoost classifier on synthetic features and serialize artifacts."""
    if xgb is None:
        return {"status": "skipped", "reason": "xgboost not installed"}

    model = xgb.XGBClassifier(
        n_estimators=30,
        max_depth=3,
        learning_rate=0.1,
        subsample=0.8,
        random_state=42,
        eval_metric="logloss",
    )
    model.fit(X_train, y_train)

    output_dir.mkdir(parents=True, exist_ok=True)
    model_file = output_dir / "xgboost.json"
    model.get_booster().save_model(str(model_file))

    preds_proba = model.predict_proba(X_train)[:, 1]
    preds = preds_proba >= 0.5
    tp = int(np.sum((preds == 1) & (y_train == 1)))
    fp = int(np.sum((preds == 1) & (y_train == 0)))
    fn = int(np.sum((preds == 0) & (y_train == 1)))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    metadata: dict[str, Any] = {
        "model_name": "xgboost",
        "model_version": f"xgboost-{model.n_estimators}.0.0",
        "feature_schema_version": "1.0.0",
        "feature_columns": feature_names,
        "backend": "xgboost",
        "training_status": "trained",
        "streaming_compatible": True,
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "samples": len(X_train),
        },
        "provenance": {
            "dataset_name": "synthetic_lab_evaluation",
            "license": "CC0-1.0",
            "training_mode": "prototype_trained_on_synthetic_data",
        },
    }
    encoded = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    metadata["integrity"] = {"sha256": hashlib.sha256(encoded).hexdigest(), "bytes": len(encoded)}
    (output_dir / "xgboost_artifact.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Train XGBoost model")
    parser.add_argument("--output", default="models/xgboost.json")
    args = parser.parse_args()
    print("XGBoost training script ready; use train_all_models.py --synthetic to train across all branches.")


if __name__ == "__main__":
    main()
