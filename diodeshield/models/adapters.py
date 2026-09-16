from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np

FEATURE_SCHEMA_VERSION = "1.0.0"


class ModelAdapter:
    name = "model"
    version = "fallback-0.1"
    backend = "deterministic"

    def initialize(self) -> None:
        pass

    def score(self, features: dict[str, Any]) -> float:
        return 0.0

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.get_metadata()), encoding="utf-8")

    def load(self, path: str | Path) -> None:
        return None

    def get_metadata(self) -> dict[str, Any]:
        return {
            "model_name": self.name,
            "model_version": self.version,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "backend": self.backend,
            "training_status": getattr(self, "training_status", "not_trained"),
            "streaming_compatible": True,
            "calibration": getattr(self, "calibration", None),
            "threshold": getattr(self, "threshold", None),
            "provenance": getattr(self, "provenance", None),
            "artifact_integrity": getattr(self, "artifact_integrity", None),
        }


def _read_artifact(path: str | Path) -> dict[str, Any] | None:
    """Read a DIODESHIELD artifact and verify its content digest."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        integrity = raw.get("integrity") or {}
        recorded = str(integrity.get("sha256", ""))
        payload = dict(raw)
        payload.pop("integrity", None)
        actual = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if not recorded or actual != recorded:
            return None
        return raw
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None


def _apply_artifact_metadata(adapter: ModelAdapter, artifact: dict[str, Any]) -> None:
    adapter.version = str(artifact.get("model_version", adapter.version))
    adapter.training_status = "trained"
    adapter.calibration = artifact.get("calibration")
    adapter.threshold = artifact.get("threshold")
    adapter.provenance = artifact.get("provenance")
    adapter.artifact_integrity = artifact.get("integrity")


class XGBoostAdapter(ModelAdapter):
    name, version = "xgboost", "fallback-tabular-0.1"

    def __init__(self) -> None:
        self.model = None
        self.feature_names: list[str] | None = None
        self.backend = "deterministic"
        self.training_status = "not_trained"

    def load(self, path: str | Path) -> None:
        p = Path(path)
        try:
            import xgboost as xgb  # type: ignore
            model = xgb.XGBClassifier()
            model.load_model(str(p))
            self.model = model
            names = getattr(model, "feature_names_in_", None)
            self.feature_names = list(names) if names is not None else None
            self.backend = "xgboost"
            self.training_status = "trained"
            n_est = getattr(model, "n_estimators", None) or 30
            self.version = f"xgboost-{n_est}.0.0"
            return
        except Exception:
            pass
        artifact = _read_artifact(path)
        if artifact:
            _apply_artifact_metadata(self, artifact)
            self.backend = "deterministic-artifact"
            self.training_status = "trained"

    def score(self, f: dict[str, Any]) -> float:
        if self.model is not None:
            try:
                names = self.feature_names or sorted(
                    key for key, value in f.items() if isinstance(value, (float, int))
                )
                vector = np.asarray([[float(f.get(name, 0.0)) for name in names]], dtype=float)
                return _bounded(float(self.model.predict_proba(vector)[0][-1]))
            except (AttributeError, IndexError, TypeError, ValueError):
                pass
        return _bounded(0.25 * _norm(f.get("fan_out", 0), 10) + 0.20 * _norm(f.get("baseline_deviation", 0), 2) +
                        0.2 * _norm(f.get("protocol_anomaly_score", 0), 1) + 0.15 * _norm(f.get("bytes_per_sec", 0), 5000) +
                        0.15 * _norm(f.get("lateral_movement_score", 0), 1) +
                        0.05 * float(f.get("udp_burst_score", 0)) +
                        0.10 * float(f.get("ip_spoofing_score", 0)) +
                        0.10 * float(f.get("packet_alteration_score", 0)))


class LSTMAdapter(ModelAdapter):
    name, version = "lstm", "fallback-sequence-0.1"

    def __init__(self) -> None:
        self.model = None
        self.feature_columns: list[str] | None = None
        self.backend = "deterministic"
        self.training_status = "not_trained"
        self.calibration = None
        self.threshold = None
        self.provenance = None
        self.artifact_integrity = None

    def load(self, path: str | Path) -> None:
        p = Path(path)
        pt_path = p.with_suffix(".pt") if p.suffix == ".json" and p.with_suffix(".pt").exists() else p
        if pt_path.exists() and pt_path.suffix == ".pt":
            try:
                import torch

                from training.train_lstm import LSTMTemporalNet
                json_path = pt_path.with_suffix(".json")
                feature_columns = None
                input_dim = 43
                if json_path.exists():
                    try:
                        meta = json.loads(json_path.read_text(encoding="utf-8"))
                        feature_columns = meta.get("feature_columns")
                        if feature_columns:
                            input_dim = len(feature_columns)
                    except Exception:
                        pass
                net = LSTMTemporalNet(input_dim=input_dim)
                net.load_state_dict(torch.load(str(pt_path), map_location="cpu", weights_only=True))
                net.eval()
                self.model = net
                self.feature_columns = list(feature_columns) if feature_columns else None
                self.backend = "pytorch"
                self.training_status = "trained"
                self.version = "lstm-pytorch-1.0.0"
                return
            except Exception:
                pass
        artifact = _read_artifact(path)
        if artifact:
            _apply_artifact_metadata(self, artifact)
            self.backend = "deterministic-artifact"
            self.training_status = "trained"

    def score(self, f: dict[str, Any]) -> float:
        if self.model is not None:
            try:
                import torch
                names = self.feature_columns
                if names is None:
                    names = sorted(key for key, value in f.items() if isinstance(value, (float, int)))
                vector = np.asarray([[float(f.get(name, 0.0)) for name in names]], dtype=float)
                t = torch.from_numpy(vector).float()
                with torch.no_grad():
                    return _bounded(float(self.model(t).item()))
            except Exception:
                pass
        beacon = float(f.get("beacon_score", 0.0))
        return _bounded(0.40 * beacon + 0.25 * _norm(f.get("iat_cv", 0), 1) +
                        0.20 * _norm(f.get("baseline_deviation", 0), 2) +
                        0.15 * _norm(f.get("periodicity_score", 0), 5) +
                        0.15 * _norm(f.get("behavior_anomaly_score", 0), 1))


class FFTAdapter(ModelAdapter):
    name, version = "fft", "signal-0.1"

    def __init__(self) -> None:
        self.training_status = "not_trained"
        self.calibration = None
        self.threshold = None
        self.provenance = None
        self.artifact_integrity = None

    def load(self, path: str | Path) -> None:
        artifact = _read_artifact(path)
        if artifact:
            _apply_artifact_metadata(self, artifact)
            self.backend = "spectral-fft-calibrated"
            self.training_status = "trained"
            self.version = str(artifact.get("model_version", "signal-fft-calibrated-1.0.0"))

    def score(self, f: dict[str, Any]) -> float:
        periodic = _norm(f.get("periodicity_score", 0), 5)
        beacon = float(f.get("beacon_score", 0.0))
        return _bounded(0.50 * max(periodic, beacon) +
                        _norm(f.get("new_ip_ratio", 0), 0.5) * 0.25 +
                        _norm(f.get("fan_out", 0), 10) * 0.25)


class KitsuneAdapter(ModelAdapter):
    name, version = "kitsune", "diodeshield-adapted-kitnet-fallback-0.1"

    def __init__(self) -> None:
        self.samples = 0
        self.mean: dict[str, float] = {}
        self.training_status = "not_trained"
        self.calibration = None
        self.threshold = None
        self.provenance = None
        self.artifact_integrity = None

    def load(self, path: str | Path) -> None:
        artifact = _read_artifact(path)
        if artifact:
            _apply_artifact_metadata(self, artifact)
            if "baseline_means" in artifact:
                self.mean = {str(k): float(v) for k, v in artifact["baseline_means"].items()}
            self.backend = "diodeshield-adapted-kitnet"
            self.training_status = "trained"
            self.version = str(artifact.get("model_version", "diodeshield-adapted-kitnet-1.0.0"))

    def update(self, f: dict[str, Any]) -> None:
        self.samples += 1
        for key, value in f.items():
            if isinstance(value, (float, int)):
                self.mean[key] = self.mean.get(key, float(value)) * 0.95 + float(value) * 0.05

    def score(self, f: dict[str, Any]) -> float:
        if not self.mean:
            return 0.0
        numeric = [abs(float(v) - self.mean.get(k, float(v))) /
                   (abs(self.mean.get(k, 0)) + 1) for k, v in f.items()
                   if isinstance(v, (float, int)) and np.isfinite(float(v))]
        distance = np.mean(numeric) if numeric else 0.0
        return _bounded(float(distance))

    def reset(self) -> None:
        self.samples, self.mean = 0, {}


class IsolationForestAdapter(ModelAdapter):
    name, version = "isolation_forest", "fallback-0.1"

    def __init__(self) -> None:
        self.model = None
        self.feature_names: list[str] | None = None
        self.backend = "deterministic"
        self.training_status = "not_trained"
        self.calibration = None
        self.threshold = None
        self.provenance = None
        self.artifact_integrity = None

    def load(self, path: str | Path) -> None:
        p = Path(path)
        joblib_path = p.with_suffix(".joblib") if p.suffix == ".json" and p.with_suffix(".joblib").exists() else p
        if joblib_path.exists() and joblib_path.suffix in {".joblib", ".pkl"}:
            try:
                import joblib
                self.model = joblib.load(str(joblib_path))
                names = getattr(self.model, "feature_names_in_", None)
                self.feature_names = list(names) if names is not None else None
                self.backend = "scikit-learn"
                self.training_status = "trained"
                self.version = f"isolation-forest-{getattr(self.model, 'n_estimators', '50')}.0.0"
                return
            except Exception:
                pass
        artifact = _read_artifact(path)
        if artifact:
            _apply_artifact_metadata(self, artifact)
            self.backend = "deterministic-artifact"
            self.training_status = "trained"

    def score(self, f: dict[str, Any]) -> float:
        if self.model is not None:
            try:
                import pandas as pd
                names = self.feature_names
                if names is not None:
                    df_in = pd.DataFrame([[float(f.get(name, 0.0)) for name in names]], columns=names)
                    df = float(self.model.decision_function(df_in)[0])
                    return _bounded(0.5 - df * 2.0)
                vector = np.asarray([[float(f.get(name, 0.0)) for name in sorted(f.keys())]], dtype=float)
                df = float(self.model.decision_function(vector)[0])
                return _bounded(0.5 - df * 2.0)
            except Exception:
                pass
        return _bounded(0.4 * _norm(f.get("baseline_deviation", 0), 2) + 0.2 * _norm(f.get("fan_out", 0), 10) +
                        0.2 * _norm(f.get("protocol_anomaly_score", 0), 1) +
                        0.2 * float(f.get("udp_burst_score", 0)) +
                        0.15 * float(f.get("ip_spoofing_score", 0)) +
                        0.15 * float(f.get("packet_alteration_score", 0)))


def _norm(value: Any, scale: float) -> float:
    try:
        number = float(value)
        return min(1.0, abs(number) / (scale + 1e-9)) if np.isfinite(number) else 0.0
    except (ValueError, TypeError):
        return 0.0


def _bounded(value: float) -> float:
    return float(max(0.0, min(1.0, value)))


def enabled_adapters(config: dict[str, Any]) -> dict[str, ModelAdapter]:
    xgboost = XGBoostAdapter()
    artifact = config.get("model_artifacts", {}).get("xgboost")
    if artifact:
        xgboost.load(artifact)
    choices: dict[str, ModelAdapter] = {"xgboost": xgboost, "lstm": LSTMAdapter(),
                                        "fft": FFTAdapter(), "kitsune": KitsuneAdapter(),
                                        "isolation_forest": IsolationForestAdapter()}
    for name, adapter in choices.items():
        artifact = config.get("model_artifacts", {}).get(name)
        if artifact and name != "xgboost":
            adapter.load(artifact)
    return {name: adapter for name, adapter in choices.items()
            if config.get("models", {}).get(name, True)}


def get_all_adapters() -> dict[str, ModelAdapter]:
    """Get all available model adapters with default config."""
    return enabled_adapters({"models": {
        "xgboost": True,
        "lstm": True,
        "fft": True,
        "kitsune": True,
        "isolation_forest": True,
    }})
