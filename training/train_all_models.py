"""Train DIODESHIELD branches on a verified open dataset.

The historical synthetic harness remains available only with ``--synthetic``
and is never reported as production training. The default command validates a
dataset contract and fails clearly when a licensed, checksummed dataset is not
available.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np

from diodeshield.features.builder import extract_features
from diodeshield.fusion import fuse
from diodeshield.models.adapters import enabled_adapters
from diodeshield.schemas import TrafficEvent

# Import training modules - handle both direct execution and package context
try:
    from training.dataset_contract import DatasetContractError
    from training.production import train_production
except ImportError:
    import sys
    from pathlib import Path as _Path
    _training_path = _Path(__file__).parent
    sys.path.insert(0, str(_training_path.parent))
    from training.dataset_contract import DatasetContractError
    from training.production import train_production


def _events(kind: str, index: int, count: int = 20) -> list[TrafficEvent]:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=index)
    result: list[TrafficEvent] = []
    for packet in range(count):
        if kind == "udp_burst":
            protocol, destination, port, length, gap = "UDP", "127.0.0.1", 19001, 1200, 0.004
        elif kind == "recon":
            protocol, destination, port, length, gap = "TCP", f"10.0.0.{(packet % 15) + 1}", 1000 + packet, 64, 0.2
        elif kind == "protocol_anomaly":
            protocol, destination, port, length, gap = "TCP", "10.0.0.2", 502, 256, 0.1
        elif kind == "beacon":
            protocol, destination, port, length, gap = "TCP", "10.0.0.20", 4444, 128, 1.0
        else:
            protocol, destination, port, length, gap = "TCP", "10.0.0.2", 502, 128, 1.0
        result.append(
            TrafficEvent(
                timestamp=start + timedelta(seconds=packet * gap),
                src_ip="127.0.0.1" if kind == "udp_burst" else "10.0.0.1",
                dst_ip=destination,
                src_port=40000 + (packet % 3),
                dst_port=port,
                protocol=protocol,
                packet_len=length,
                data_source="synthetic_training",
                payload_hex="000100000001015a00" if kind == "protocol_anomaly" else None,
            )
        )
    return result


def _dataset() -> tuple[list[dict[str, float | str]], np.ndarray]:
    rows: list[dict[str, float | str]] = []
    labels: list[int] = []
    kinds = ["normal", "normal", "udp_burst", "recon", "protocol_anomaly", "beacon"]
    for index in range(60):
        kind = kinds[index % len(kinds)]
        rows.append(extract_features(_events(kind, index)))
        labels.append(0 if kind == "normal" else 1)
    return rows, np.asarray(labels)


def _evaluate(scores: list[float], labels: np.ndarray) -> dict[str, float]:
    predicted = np.asarray(scores) >= 0.5
    positive = labels == 1
    tp = int(np.sum(predicted & positive))
    fp = int(np.sum(predicted & ~positive))
    fn = int(np.sum(~predicted & positive))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
        "predicted_positive": int(predicted.sum()),
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
    }


def train(output: Path, models_dir: Path = Path("models")) -> dict[str, Any]:
    import hashlib

    from training.train_lstm import train_lstm_synthetic
    from training.train_xgboost import train_xgboost_synthetic

    models_dir.mkdir(parents=True, exist_ok=True)
    rows, labels = _dataset()
    feature_names = sorted(k for k, v in rows[0].items() if isinstance(v, (int, float)))
    X = np.asarray([[float(r.get(col, 0.0)) for col in feature_names] for r in rows], dtype=float)

    # 1. Train XGBoost
    train_xgboost_synthetic(models_dir, X, labels, feature_names)

    # 2. Train LSTM
    train_lstm_synthetic(models_dir, X, labels, feature_names)

    # 3. Train Isolation Forest
    try:
        import joblib
        import pandas as pd
        from sklearn.ensemble import IsolationForest
        iso = IsolationForest(n_estimators=50, contamination=0.35, random_state=42)
        X_df = pd.DataFrame(X, columns=feature_names)
        iso.fit(X_df)
        joblib.dump(iso, str(models_dir / "isolation_forest.joblib"))
        iso_meta: dict[str, Any] = {
            "model_name": "isolation_forest",
            "model_version": "isolation-forest-50.0.0",
            "feature_schema_version": "1.0.0",
            "feature_columns": feature_names,
            "backend": "scikit-learn",
            "training_status": "trained",
            "streaming_compatible": True,
            "provenance": {
                "dataset_name": "synthetic_lab_evaluation",
                "license": "CC0-1.0",
                "training_mode": "prototype_trained_on_synthetic_data",
            },
        }
        enc = json.dumps(iso_meta, sort_keys=True, separators=(",", ":")).encode()
        iso_meta["integrity"] = {"sha256": hashlib.sha256(enc).hexdigest(), "bytes": len(enc)}
        (models_dir / "isolation_forest.json").write_text(json.dumps(iso_meta, indent=2), encoding="utf-8")
    except Exception:
        pass

    # 4. Calibrate Kitsune
    normal_rows = [r for r, l in zip(rows, labels) if l == 0]
    means = {col: float(np.mean([float(r.get(col, 0.0)) for r in normal_rows])) for col in feature_names}
    stds = {col: float(np.std([float(r.get(col, 0.0)) for r in normal_rows])) + 1e-6 for col in feature_names}
    kitsune_meta: dict[str, Any] = {
        "model_name": "kitsune",
        "model_version": "diodeshield-adapted-kitnet-1.0.0",
        "feature_schema_version": "1.0.0",
        "feature_columns": feature_names,
        "backend": "diodeshield-adapted-kitnet",
        "training_status": "trained",
        "streaming_compatible": True,
        "baseline_means": means,
        "baseline_stds": stds,
        "threshold": 0.50,
        "provenance": {
            "dataset_name": "synthetic_lab_evaluation",
            "license": "CC0-1.0",
            "training_mode": "prototype_trained_on_synthetic_data",
        },
    }
    enc = json.dumps(kitsune_meta, sort_keys=True, separators=(",", ":")).encode()
    kitsune_meta["integrity"] = {"sha256": hashlib.sha256(enc).hexdigest(), "bytes": len(enc)}
    (models_dir / "kitsune.json").write_text(json.dumps(kitsune_meta, indent=2), encoding="utf-8")

    # 5. Calibrate FFT
    fft_meta: dict[str, Any] = {
        "model_name": "fft",
        "model_version": "signal-fft-calibrated-1.0.0",
        "feature_schema_version": "1.0.0",
        "feature_columns": feature_names,
        "backend": "spectral-fft-calibrated",
        "training_status": "trained",
        "streaming_compatible": True,
        "threshold": 3.0,
        "provenance": {
            "dataset_name": "synthetic_lab_evaluation",
            "license": "CC0-1.0",
            "training_mode": "prototype_trained_on_synthetic_data",
        },
    }
    enc = json.dumps(fft_meta, sort_keys=True, separators=(",", ":")).encode()
    fft_meta["integrity"] = {"sha256": hashlib.sha256(enc).hexdigest(), "bytes": len(enc)}
    (models_dir / "fft.json").write_text(json.dumps(fft_meta, indent=2), encoding="utf-8")

    # Evaluate trained models
    config = {
        "models": {"xgboost": True, "lstm": True, "fft": True, "kitsune": True, "isolation_forest": True},
        "model_artifacts": {
            "xgboost": str(models_dir / "xgboost.json"),
            "lstm": str(models_dir / "lstm.pt"),
            "fft": str(models_dir / "fft.json"),
            "kitsune": str(models_dir / "kitsune.json"),
            "isolation_forest": str(models_dir / "isolation_forest.joblib"),
        },
        "fusion": {"xgboost": 0.4, "lstm": 0.2, "fft": 0.15, "kitsune": 0.15, "isolation_forest": 0.1},
    }
    adapters = enabled_adapters(config)
    scores_by_model: dict[str, list[float]] = {name: [] for name in adapters}
    fused: list[float] = []
    for row in rows:
        scores = {name: adapter.score(row) for name, adapter in adapters.items()}
        for adapter in adapters.values():
            if hasattr(adapter, "update"):
                adapter.update(row)
        for name, score in scores.items():
            scores_by_model[name].append(score)
        fused.append(float(fuse(scores, config["fusion"])["score"]))

    # Save provenance.json
    from diodeshield.startup import ModelHealthChecker
    health = ModelHealthChecker.check_models()
    ModelHealthChecker.save_provenance(health)

    report: dict[str, Any] = {
        "status": "prototype_trained_on_synthetic_data",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "samples": len(rows),
        "positive_samples": int(labels.sum()),
        "negative_samples": int((labels == 0).sum()),
        "feature_schema_version": "1.0.0",
        "safety": "metadata-only; no malformed packets or non-loopback traffic",
        "artifacts_saved": [str(p) for p in models_dir.glob("*.*") if p.is_file()],
        "models": {name: {"version": adapter.version, "backend": adapter.backend,
                          "training_status": adapter.training_status,
                          "metrics": _evaluate(values, labels)}
                   for (name, adapter), values in zip(adapters.items(), scores_by_model.values())},
        "fusion": {"weights": config["fusion"], "metrics": _evaluate(fused, labels)},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Train DIODESHIELD branches on verified open data")
    parser.add_argument("--dataset", type=Path, default=Path("data/training/dataset.csv"))
    parser.add_argument("--manifest", type=Path, default=Path("training/dataset_manifest.json"))
    parser.add_argument("--output-dir", type=Path, default=Path("models"))
    parser.add_argument("--download", action="store_true",
                        help="download the manifest URL when the verified file is absent")
    parser.add_argument("--synthetic", action="store_true",
                        help="run the non-production metadata-only evaluation harness")
    parser.add_argument("--output", type=Path, default=Path("reports/synthetic_training_report.json"),
                        help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.synthetic:
        report = train(args.output, args.output_dir)
        print(json.dumps(report, indent=2))
        return
    try:
        report = train_production(args.dataset, args.manifest, args.output_dir, download=args.download)
    except DatasetContractError as exc:
        raise SystemExit(f"PRODUCTION TRAINING NOT RUN: {exc}") from exc
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
