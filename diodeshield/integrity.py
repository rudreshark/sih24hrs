from __future__ import annotations

import hashlib
import json
from typing import Any

JSON_FIELDS = (
    "model_scores", "protocol_evidence", "feature_values", "top_features",
    "threat_intel", "vulnerability_context", "gateway_context", "diode_health",
    "explanation", "reasons",
)


def _normalize_alert(alert: dict[str, Any]) -> dict[str, Any]:
    norm = dict(alert)
    for field in JSON_FIELDS:
        val = norm.get(field)
        if isinstance(val, str):
            try:
                norm[field] = json.loads(val)
            except (json.JSONDecodeError, TypeError):
                pass
    return norm


def compute_alert_payload(alert: dict[str, Any]) -> str:
    norm = _normalize_alert(alert)
    # Exclude chain-control fields AND any fields that may be added asynchronously
    # after the original hash was computed (e.g. explanation_llm added by Task 2).
    _EXCLUDED = frozenset({
        "previous_hash", "evidence_hash", "chain_sequence",
        "explanation_llm",  # Added asynchronously; must not invalidate existing chains
    })
    payload_dict = {k: v for k, v in norm.items() if k not in _EXCLUDED}
    return json.dumps(payload_dict, sort_keys=True, default=str, separators=(",", ":"))


def compute_alert_hash(alert: dict[str, Any], previous_hash: str | None = None) -> str:
    prev = previous_hash if previous_hash is not None else alert.get("previous_hash", "0" * 64)
    payload = compute_alert_payload(alert)
    return hashlib.sha256((prev + payload + str(alert.get("timestamp", ""))).encode()).hexdigest()


def verify_alert(alert: dict[str, Any]) -> bool:
    if not isinstance(alert, dict):
        return False
    evidence_hash = alert.get("evidence_hash")
    previous_hash = alert.get("previous_hash")
    if not evidence_hash or previous_hash is None:
        return False
    expected = compute_alert_hash(alert, previous_hash=previous_hash)
    return expected == evidence_hash


def verify_chain(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    if not alerts:
        return {"valid": True, "count": 0, "broken_index": None, "broken_alert_id": None, "reason": "empty_chain"}

    sorted_alerts = sorted(alerts, key=lambda a: int(a.get("chain_sequence") or 0))
    expected_previous = "0" * 64
    for idx, alert in enumerate(sorted_alerts):
        seq = alert.get("chain_sequence")
        if alert.get("previous_hash") != expected_previous:
            return {
                "valid": False,
                "count": len(sorted_alerts),
                "broken_index": idx,
                "broken_sequence": seq,
                "broken_alert_id": alert.get("alert_id"),
                "reason": f"Hash chain broken at sequence {seq}: previous_hash does not match preceding evidence_hash",
            }
        if not verify_alert(alert):
            return {
                "valid": False,
                "count": len(sorted_alerts),
                "broken_index": idx,
                "broken_sequence": seq,
                "broken_alert_id": alert.get("alert_id"),
                "reason": f"Tampered alert payload detected at sequence {seq} (alert_id: {alert.get('alert_id')})",
            }
        expected_previous = str(alert.get("evidence_hash", ""))

    return {
        "valid": True,
        "count": len(sorted_alerts),
        "head_sequence": sorted_alerts[-1].get("chain_sequence"),
        "head_hash": sorted_alerts[-1].get("evidence_hash"),
        "broken_index": None,
        "broken_alert_id": None,
        "reason": "verified",
    }


class HashChain:
    def __init__(self, repository: Any = None) -> None:
        self.repository = repository
        self.previous = "0" * 64
        self.sequence = 0
        self._sync()

    def _sync(self) -> None:
        if self.repository is not None:
            try:
                rows = self.repository._rows(
                    "SELECT chain_sequence, evidence_hash FROM alerts WHERE evidence_hash IS NOT NULL ORDER BY chain_sequence DESC LIMIT 1"
                )
                if rows:
                    self.sequence = int(rows[0]["chain_sequence"] or 0)
                    self.previous = str(rows[0]["evidence_hash"] or ("0" * 64))
            except Exception:
                pass

    def append(self, alert: dict[str, Any]) -> dict[str, Any]:
        self._sync()
        self.sequence += 1
        previous = self.previous
        digest = compute_alert_hash(alert, previous_hash=previous)
        self.previous = digest
        alert["previous_hash"], alert["evidence_hash"], alert["chain_sequence"] = previous, digest, self.sequence
        return alert


    @staticmethod
    def verify_alert(alert: dict[str, Any]) -> bool:
        return verify_alert(alert)

    @staticmethod
    def verify_chain(alerts: list[dict[str, Any]]) -> dict[str, Any]:
        return verify_chain(alerts)

