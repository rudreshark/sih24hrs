"""Offline, metadata-only threat scenarios for DIODESHIELD validation."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure project root is in sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from diodeshield.pipeline import DetectionPipeline
from diodeshield.schemas import TrafficEvent


def run(scenario: str, count: int, batch_size: int) -> dict[str, object]:
    pipeline = DetectionPipeline()
    alerts: list[dict[str, object]] = []
    captured = 0
    start = datetime.now(timezone.utc)
    for offset in range(0, count, batch_size):
        batch: list[TrafficEvent] = []
        for index in range(offset, min(offset + batch_size, count)):
            meta = {}
            if scenario == "ttl":
                ttl = 32 + (index % 8)
                source, protocol, length, port = "10.0.0.7", "TCP", 128, 502
                destination = "10.0.0.8"
            elif scenario == "spoof":
                ttl = 64
                source = f"198.18.0.{(index % 32) + 1}"
                protocol, length, port = "UDP", 256, 19001
                destination = "10.0.0.8"
                meta = {"virtual_identity": True}
            elif scenario == "altered":
                ttl, source, protocol, length, port = 64, "10.0.0.7", "TCP", 180, 502
                destination = "10.0.0.8"
                meta = {"payload_altered": True}
            elif scenario == "beacon":
                ttl, source, protocol, length, port = 64, "10.0.0.7", "TCP", 64, 4444
                destination = "198.18.0.50"
                meta = {"beacon": True}
            elif scenario == "recon":
                ttl, source, protocol, length = 64, "10.0.0.7", "TCP", 64
                destination = f"10.0.1.{(index % 16) + 1}"
                port = 502 + (index % 8)
                meta = {"scan": True}
            elif scenario == "behavior":
                ttl, source, protocol, length, port = 64, "10.0.0.7", "TCP", 96, 1000 + index % 32
                destination = f"10.0.1.{(index % 32) + 1}"
            else:
                ttl, source, protocol, length, port = 64, "10.0.0.7", "UDP", 1200, 19001
                destination = "10.0.0.8"
                meta = {"flood": True}
            batch.append(
                TrafficEvent(
                    timestamp=start + timedelta(milliseconds=index),
                    src_ip=source,
                    dst_ip=destination,
                    src_port=40000 + index % 32,
                    dst_port=port,
                    protocol=protocol,
                    packet_len=length,
                    ttl=ttl,
                    data_source="offline_threat_lab",
                    metadata=meta,
                )
            )
        captured += len(batch)
        result = pipeline.process_window(batch)
        if result:
            alerts.append(result)
    return {
        "offline_only": True,
        "scenario": scenario,
        "generated_events": count,
        "processed_events": captured,
        "alerts": len(alerts),
        "risk_levels": sorted({str(a["risk_level"]) for a in alerts}),
        "categories": sorted({str(a["attack_category"]) for a in alerts}),
        "max_risk": round(max((float(a["risk_score"]) for a in alerts), default=0.0), 4),
        "evidence": [
            {"risk_score": round(float(a["risk_score"]), 4), "category": a["attack_category"],
             "reasons": a["reasons"], "features": {
                 key: a["feature_values"].get(key)
                 for key in ("udp_burst_score", "source_diversity", "ttl_anomaly_score",
                             "payload_integrity_anomaly", "ip_spoofing_score",
                             "packet_alteration_score", "behavior_anomaly_score",
                             "packets_per_sec")
             }}
            for a in alerts[-3:]
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline DIODESHIELD threat validation")
    parser.add_argument("--scenario", choices=["flood", "spoof", "ttl", "altered", "behavior", "beacon", "recon"], default="flood")
    parser.add_argument("--count", type=int, default=800_000)
    parser.add_argument("--batch-size", type=int, default=500)
    args = parser.parse_args()
    if not 1 <= args.count <= 1_000_000:
        parser.error("--count must be between 1 and 1000000")
    if not 1 <= args.batch_size <= 5000:
        parser.error("--batch-size must be between 1 and 5000")
    print(json.dumps(run(args.scenario, args.count, args.batch_size), indent=2))


if __name__ == "__main__":
    main()
