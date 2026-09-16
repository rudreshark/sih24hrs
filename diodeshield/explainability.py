"""Auditable feature explanations with an optional SHAP integration.

The receive-side prototype must remain runnable without optional ML packages.
When a trained tree model is unavailable, this module produces deterministic
contributions from the same signals used by the fallback adapters.  The output
labels the method explicitly so it cannot be mistaken for calibrated TreeSHAP.
"""
from __future__ import annotations

from typing import Any

EXPLANATION_SCHEMA_VERSION = "1.0.0"

_SIGNALS: dict[str, dict[str, float]] = {
    "xgboost": {
        "fan_out": 0.25, "baseline_deviation": 0.20,
        "protocol_anomaly_score": 0.20, "bytes_per_sec": 0.15,
        "lateral_movement_score": 0.15, "udp_burst_score": 0.05,
        "ip_spoofing_score": 0.20, "packet_alteration_score": 0.20,
    },
    "lstm": {
        "iat_cv": 0.55, "baseline_deviation": 0.25,
        "periodicity_score": 0.20, "behavior_anomaly_score": 0.20,
    },
    "fft": {
        "periodicity_score": 0.45, "new_ip_ratio": 0.30,
        "fan_out": 0.25,
    },
    "kitsune": {"behavior_anomaly_score": 0.50, "baseline_deviation": 0.50},
    "isolation_forest": {
        "baseline_deviation": 0.40, "fan_out": 0.20,
        "protocol_anomaly_score": 0.20, "udp_burst_score": 0.20,
    },
}


def _normalized(value: Any, feature: str) -> float:
    scales = {
        "fan_out": 10.0, "baseline_deviation": 2.0,
        "protocol_anomaly_score": 1.0, "bytes_per_sec": 5000.0,
        "lateral_movement_score": 1.0, "udp_burst_score": 1.0,
        "ip_spoofing_score": 1.0, "packet_alteration_score": 1.0,
        "iat_cv": 1.0, "periodicity_score": 10.0, "new_ip_ratio": 0.5,
        "behavior_anomaly_score": 1.0,
    }
    try:
        return max(-1.0, min(1.0, float(value) / scales.get(feature, 1.0)))
    except (TypeError, ValueError):
        return 0.0


def _fallback_model_explanation(
    model: str, features: dict[str, Any], score: float,
) -> dict[str, Any]:
    contributions = []
    for feature, weight in _SIGNALS.get(model, {}).items():
        value = features.get(feature, 0.0)
        contribution = _normalized(value, feature) * weight
        if contribution:
            contributions.append({
                "feature": feature,
                "value": value,
                "contribution": round(contribution, 6),
                "direction": "positive" if contribution > 0 else "negative",
            })
    contributions.sort(key=lambda item: abs(float(item["contribution"])), reverse=True)
    return {
        "model": model,
        "method": "deterministic-fallback",
        "model_score": round(float(score), 6),
        "base_value": 0.0,
        "features": contributions,
        "top_positive": [x for x in contributions if x["contribution"] > 0][:5],
        "top_negative": [x for x in contributions if x["contribution"] < 0][:5],
    }


def build_explanation(
    features: dict[str, Any], scores: dict[str, float], tree_model: Any = None,
) -> dict[str, Any]:
    """Build stable per-model evidence for an alert.

    A future trained XGBoost adapter can replace one model entry with true
    TreeSHAP values; the schema remains the same.  No raw payload is included.
    """
    models = {
        name: _fallback_model_explanation(name, features, score)
        for name, score in scores.items()
    }
    method = "deterministic-fallback"
    if tree_model is not None:
        shap_result = tree_shap_values(tree_model, features)
        if shap_result is not None and "xgboost" in models:
            models["xgboost"] = {
                "model": "xgboost",
                "model_score": round(float(scores["xgboost"]), 6),
                "base_value": 0.0,
                **shap_result,
            }
            method = "TreeSHAP (xgboost) + deterministic-fallback"
    combined: dict[str, dict[str, Any]] = {}
    for explanation in models.values():
        for item in explanation["features"]:
            feature = str(item["feature"])
            current = combined.setdefault(feature, {
                "feature": feature, "value": item["value"], "contribution": 0.0,
            })
            current["contribution"] += float(item["contribution"])
    ranked = sorted(combined.values(), key=lambda item: abs(item["contribution"]), reverse=True)
    for item in ranked:
        item["contribution"] = round(float(item["contribution"]), 6)
        item["direction"] = "positive" if item["contribution"] > 0 else "negative"
    return {
        "schema_version": EXPLANATION_SCHEMA_VERSION,
        "method": method,
        "models": models,
        "top_positive": [x for x in ranked if x["contribution"] > 0][:10],
        "top_negative": [x for x in ranked if x["contribution"] < 0][:10],
    }


def tree_shap_values(model: Any, features: dict[str, Any]) -> dict[str, Any] | None:
    """Return TreeSHAP values when both a trained tree model and ``shap`` exist.

    This is deliberately opt-in and lazy: the normal receive-side fallback has
    no dependency on SHAP or an artifact.  Callers should persist the returned
    feature names alongside the model version.
    """
    try:
        import numpy as np
        import shap  # type: ignore
    except Exception:  # noqa: BLE001 - optional SHAP must never break ingestion
        return None
    names = [key for key, value in features.items() if isinstance(value, (int, float))]
    if not names:
        return None
    try:
        values = np.asarray([[float(features[name]) for name in names]], dtype=float)
        raw = shap.TreeExplainer(model)(values)
        shap_values = raw.values[0] if hasattr(raw, "values") else raw[0]
    except Exception:  # noqa: BLE001 - incompatible artifacts use fallback evidence
        return None
    contributions = [
        {"feature": name, "value": features[name], "contribution": round(float(value), 6),
         "direction": "positive" if float(value) > 0 else "negative"}
        for name, value in zip(names, shap_values)
        if float(value) != 0
    ]
    contributions.sort(key=lambda item: abs(float(item["contribution"])), reverse=True)
    return {
        "method": "TreeSHAP",
        "features": contributions,
        "top_positive": [x for x in contributions if x["contribution"] > 0][:10],
        "top_negative": [x for x in contributions if x["contribution"] < 0][:10],
    }
