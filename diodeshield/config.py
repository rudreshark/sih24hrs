from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG = {
    "system": {"mode": "live_capture", "sensor_version": "0.1.0", "live_capture": True},
    "window": {"size_seconds": 5, "slide_seconds": 1},
    "models": {"xgboost": True, "lstm": True, "fft": True, "kitsune": True, "isolation_forest": True},
    "model_artifacts": {},
    "fusion": {"xgboost": 0.4, "lstm": 0.2, "fft": 0.15, "kitsune": 0.15, "isolation_forest": 0.1},
    "risk": {"critical": 0.85, "high": 0.7, "medium": 0.5, "low": 0.3},
    "persistence": {"enabled": True, "consecutive_windows": 3, "cooldown_seconds": 30},
    "retention": {"raw_events_days": 7, "features_days": 30, "alerts_days": 365},
    "security": {"api_key_required": False, "allow_payload": False},
}


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    path = Path(path or os.getenv("DIODESHIELD_CONFIG", "configs/default.yaml"))
    result = _merge({}, DEFAULT_CONFIG)
    if path.exists():
        with path.open(encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        _merge(result, loaded)
    live_capture = os.getenv("DIODESHIELD_LIVE_CAPTURE", "").lower()
    if live_capture in {"1", "true", "yes"}:
        result["system"]["live_capture"] = True
    elif live_capture in {"0", "false", "no"}:
        result["system"]["live_capture"] = False
    return result
