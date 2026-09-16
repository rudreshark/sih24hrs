from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any

from diodeshield.config import load_config
from diodeshield.db import Repository
from diodeshield.explainability import build_explanation
from diodeshield.features.builder import extract_features
from diodeshield.fusion import fuse
from diodeshield.ingestion.window import SlidingWindow
from diodeshield.integrity import HashChain
from diodeshield.models.adapters import enabled_adapters
from diodeshield.protocol.modbus import parse_modbus_tcp
from diodeshield.risk import RiskEngine
from diodeshield.schemas import TrafficEvent
from diodeshield.threat_intel.ioc import LocalIOCStore


class DetectionPipeline:
    def __init__(self, repository: Repository | None = None, config: dict[str, Any] | None = None):
        self.config = config or load_config()
        self.repository = repository or Repository()
        window = self.config["window"]
        self.window = SlidingWindow(window["size_seconds"], window["slide_seconds"])
        self.adapters = enabled_adapters(self.config)
        self.risk = RiskEngine(self.config)
        self.hash_chain = HashChain(self.repository)
        self.ioc_store = LocalIOCStore()
        self.baseline: dict[str, float] = {}
        self.latest_health = {"status": "HEALTHY", "visibility": "traffic_observed", "queue_depth": 0}
        self.subscribers: list[Any] = []

    def subscribe(self, callback: Any) -> None:
        self.subscribers.append(callback)

    def ingest(self, event: TrafficEvent) -> list[dict[str, Any]]:
        alerts = []
        for window_events in self.window.add(event):
            result = self.process_window(window_events)
            if result:
                alerts.append(result)
        return alerts

    def process_window(self, events: list[TrafficEvent]) -> dict[str, Any] | None:
        features = extract_features(events, self.baseline)
        latencies: dict[str, float] = {}
        scores: dict[str, float] = {}
        for name, adapter in self.adapters.items():
            started = time.perf_counter_ns()
            scores[name] = adapter.score(features)
            latencies[name] = round((time.perf_counter_ns() - started) / 1_000_000, 6)
        # Score before updating the online branch so a novel window is not
        # normalized away by its own observation.
        for adapter in self.adapters.values():
            if hasattr(adapter, "update"):
                adapter.update(features)
        result = fuse(scores, self.config.get("fusion", {}))
        protocol = {}
        for event in events:
            if (event.dst_port == 502 or event.src_port == 502) and event.payload_hex:
                protocol = parse_modbus_tcp(event.payload_hex)
                break
        features.update({k: v for k, v in protocol.items() if isinstance(v, (float, int))})
        risk = self.risk.evaluate(result, features, protocol, key=f"{events[0].src_ip if events else 'empty'}")
        timestamp = (events[-1].timestamp if events else datetime.now(timezone.utc)).isoformat()
        self.repository.save_features(timestamp, events[0].asset_id if events else None, features)
        self.repository.save_model_score(timestamp, result["scores"])
        self.repository.save_flow({"timestamp": timestamp, "src_ip": events[0].src_ip if events else None,
                                  "dst_ip": events[0].dst_ip if events else None, "protocol": features.get("protocol"),
                                  "packets": features.get("packets", 0), "bytes": features.get("bytes", 0),
                                  "anomaly_score": risk["risk_score"], "asset_id": events[0].asset_id if events else None})
        self.latest_health.update({"status": "HEALTHY", "last_event": timestamp, "queue_depth": 0,
                                   "model_latency_ms": latencies,
                                   "streaming_compatible": True,
                                   "data_source": events[-1].data_source if events else "unknown"})
        for event in events:
            self.latest_health["data_source"] = event.data_source
        # Do not persist routine or weakly anomalous live windows as alerts.
        # WARNING requires persistence; CRITICAL is independently gated by
        # RiskEngine to strong UDP-flood or spoofing evidence.
        if risk["risk_level"] in {"INFO", "LOW", "MEDIUM"}:
            return None
        if risk["risk_level"] == "WARNING" and not risk["persistent"]:
            return None
        # Explanation generation (especially optional TreeSHAP) is only needed
        # for persisted alerts. Keeping it off the hot path preserves the
        # exact scoring and alert policy while improving live throughput.
        tree_model = getattr(self.adapters.get("xgboost"), "model", None)
        explanation = build_explanation(features, scores, tree_model)
        ioc_hit = None
        if events:
            for ip in (events[0].src_ip, events[0].dst_ip):
                if ip:
                    res = self.ioc_store.lookup(ip)
                    if res.get("match"):
                        ioc_hit = {"indicator": ip, **res}
                        break
        threat_intel = {"status": "match", **ioc_hit} if ioc_hit else {"status": "clean", "checked": True}
        alert = {
            "alert_id": str(uuid.uuid4()), "timestamp": timestamp, "first_seen": timestamp, "last_seen": timestamp,
            "src_ip": events[0].src_ip if events else None, "dst_ip": events[0].dst_ip if events else None,
            "src_port": events[0].src_port if events else None, "dst_port": events[0].dst_port if events else None,
            "protocol": features.get("protocol"), "asset_id": events[0].asset_id if events else None,
            "asset_criticality": 0.5, "attack_category": _category(features, protocol),
            "risk_score": risk["risk_score"], "risk_level": risk["risk_level"], "confidence": risk["confidence"],
            "model_disagreement": result["model_disagreement"], "model_scores": result["scores"],
            "protocol_evidence": protocol, "baseline_deviation": features.get("baseline_deviation", 0),
            "feature_values": features,
            "top_features": explanation["top_positive"][:10],
            "explanation": explanation,
            "threat_intel": threat_intel, "vulnerability_context": {"status": "context_only"},
            "gateway_context": {"visibility_status": "unavailable"}, "diode_health": self.latest_health,
            "model_version": ",".join(a.version for a in self.adapters.values()),
            "feature_schema_version": "1.0.0", "configuration_version": "default-1",
            "sensor_version": self.config["system"]["sensor_version"], "incident_id": None,
            "reasons": risk["reasons"],
        }
        self.hash_chain.append(alert)
        self.repository.save_alert(alert)
        for callback in list(self.subscribers):
            try:
                callback(alert)
            except (RuntimeError, ValueError, TypeError, OSError):
                continue
        return alert


def _top_features(features: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = [(key, abs(float(value))) for key, value in features.items() if isinstance(value, (int, float))]
    return [{"feature": k, "value": features[k], "contribution": v} for k, v in sorted(candidates, key=lambda x: x[1], reverse=True)[:10]]


def _category(features: dict[str, Any], protocol: dict[str, Any]) -> str:
    if features.get("ip_spoofing_score", 0) >= 0.5:
        return "IP_SPOOFING"
    if features.get("packet_alteration_score", 0) >= 0.5:
        return "PACKET_ALTERATION"
    if features.get("udp_burst_score", 0) >= 0.5:
        return "UDP_FLOOD"
    if features.get("ttl_anomaly_score", 0) >= 0.5:
        return "TTL_ANOMALY"
    if protocol.get("protocol_anomaly_score", 0) >= 0.5:
        return "PROTOCOL_ANOMALY"
    if features.get("fan_out", 0) >= 10 and features.get("lateral_movement_score", 0) >= 0.5:
        return "FAN_OUT_ANOMALY"
    if features.get("beacon_score", 0) >= 0.65 and features.get("periodicity_score", 0) >= 2.5:
        return "C2_BEACON"
    if features.get("behavior_anomaly_score", 0) >= 0.5:
        return "ABNORMAL_BEHAVIOR"
    return "NOVEL_BEHAVIOR"
