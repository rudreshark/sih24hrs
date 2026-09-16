from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any


class PersistenceEngine:
    def __init__(self, consecutive_windows: int = 3, cooldown_seconds: int = 30):
        self.required = max(1, consecutive_windows)
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self.counts: defaultdict[str, int] = defaultdict(int)
        self.last_alert: dict[str, datetime] = {}

    def observe(self, key: str, score: float, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        self.counts[key] = self.counts[key] + 1 if score >= 0.5 else 0
        if self.counts[key] < self.required:
            return False
        if now - self.last_alert.get(key, datetime.min.replace(tzinfo=timezone.utc)) < self.cooldown:
            return False
        self.last_alert[key] = now
        return True


class RiskEngine:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.thresholds = config.get("risk", {})
        self.consensus_cfg = config.get("consensus", {})
        p = config.get("persistence", {})
        self.persistence = PersistenceEngine(p.get("consecutive_windows", 3), p.get("cooldown_seconds", 30))

    def evaluate(self, fusion: dict[str, Any], features: dict[str, Any], protocol: dict[str, Any] | None = None,
                 asset_criticality: float = 0.5, key: str = "global") -> dict[str, Any]:
        protocol = protocol or {}
        # Independent protocol evidence is deliberately material but not a verdict:
        # malformed/unexpected traffic is an investigation signal, not proof of compromise.
        score = min(1.0, float(fusion["score"]) * 0.75 +
                    float(protocol.get("protocol_anomaly_score", 0)) * 0.45 +
                    float(features.get("udp_burst_score", 0)) * 0.45 +
                    float(features.get("ttl_anomaly_score", 0)) * 0.35 +
                    float(features.get("payload_integrity_anomaly", 0)) * 0.35 +
                    float(features.get("ip_spoofing_score", features.get("identity_anomaly_score", 0))) * 0.45 +
                    float(features.get("packet_alteration_score", 0)) * 0.45 +
                    float(features.get("beacon_score", 0)) * 0.50 +
                    float(features.get("behavior_anomaly_score", 0)) * 0.25 +
                    min(1.0, float(features.get("fan_out", 0)) / 10.0) * 0.30 +
                    min(1.0, float(features.get("port_diversity", 0)) / 10.0) * 0.15 +
                    float(asset_criticality) * 0.05)
        t = self.thresholds
        consensus_cfg = self.consensus_cfg
        min_agreeing = int(consensus_cfg.get("min_agreeing_models", 2))
        vote_threshold = float(consensus_cfg.get("vote_threshold", 0.50))
        high_override = float(consensus_cfg.get("high_confidence_override", 0.90))

        branch_votes = {
            name: bool(float(v) >= vote_threshold)
            for name, v in fusion.get("scores", {}).items()
        }
        agreeing_models = sum(1 for vote in branch_votes.values() if vote)
        high_models = sum(1 for v in fusion.get("scores", {}).values() if float(v) >= high_override)
        consensus_met = agreeing_models >= min_agreeing

        is_critical = score >= t.get("critical", 0.85) or high_models >= min_agreeing
        crit_thresh = t.get("critical", 0.85)
        warn_thresh = t.get("warning", t.get("high", 0.60))
        info_thresh = t.get("info", t.get("medium", 0.35))
        level = "CRITICAL" if is_critical else "WARNING" if score >= warn_thresh else "INFO" if score >= info_thresh else "LOW"
        reasons = []
        if features.get("fan_out", 0) > 5:
            reasons.append("unusual destination fan-out")
        if features.get("baseline_deviation", 0) > 0.5:
            reasons.append("behavior differs from baseline")
        if protocol.get("protocol_anomaly_score", 0) > 0:
            reasons.append("protocol anomaly observed")
        if features.get("udp_burst_score", 0) >= 0.5:
            reasons.append("high-rate UDP burst observed")
        if features.get("ttl_anomaly_score", 0) >= 0.5:
            reasons.append("unexpected TTL variation observed")
        if features.get("payload_integrity_anomaly", 0) > 0:
            reasons.append("payload integrity mismatch metadata observed")
        if features.get("ip_spoofing_score", features.get("identity_anomaly_score", 0)) > 0:
            reasons.append("source identity mismatch metadata observed")
        if features.get("packet_alteration_score", 0) > 0:
            reasons.append("packet alteration or checksum mismatch metadata observed")
        if features.get("beacon_score", 0) >= 0.4:
            reasons.append("periodic beaconing behavior observed")

        if features.get("behavior_anomaly_score", 0) >= 0.5:
            reasons.append("packet behavior differs from the receive-side baseline")

        decision_log = {
            "branch_details": fusion.get("branch_details", {}),
            "raw_scores": fusion.get("raw_scores", {}),
            "normalized_scores": fusion.get("scores", {}),
            "branch_votes": branch_votes,
            "agreeing_models": agreeing_models,
            "min_agreeing_models_required": min_agreeing,
            "consensus_met": consensus_met,
            "high_models": high_models,
        }

        return {
            "risk_score": score,
            "risk_level": level,
            "confidence": max(0.0, 1.0 - fusion.get("model_disagreement", 0)),
            "reasons": reasons,
            "persistent": self.persistence.observe(key, score),
            "agreeing_models": agreeing_models,
            "consensus_met": consensus_met,
            "decision_log": decision_log,
        }

