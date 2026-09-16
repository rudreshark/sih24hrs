from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from diodeshield.api.main import app
from diodeshield.config import load_config
from diodeshield.db import Repository
from diodeshield.features.builder import extract_features
from diodeshield.fusion import fuse
from diodeshield.ingestion.events import tshark_row
from diodeshield.ingestion.zeek import read_zeek_conn
from diodeshield.pipeline import DetectionPipeline
from diodeshield.protocol.modbus import parse_modbus_tcp
from diodeshield.risk import PersistenceEngine
from diodeshield.schemas import TrafficEvent


def event(i: int, **kwargs):
    values = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "packet_len": 100}
    values.update(kwargs)
    return TrafficEvent(timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=i),
                        **values)


def test_features_and_fft():
    result = extract_features([event(i) for i in range(5)])
    assert result["packets"] == 5
    assert result["iat_mean"] == 1
    assert "dominant_frequency" in result


def test_modbus_parser():
    result = parse_modbus_tcp("000100000006010300000002")
    assert result["function_code"] == 3
    assert result["starting_address"] == 0


def test_fusion_and_persistence():
    result = fuse({"xgboost": .8, "fft": .2}, {"xgboost": .5, "fft": .5})
    assert 0 < result["score"] < 1
    p = PersistenceEngine(2, 0)
    assert not p.observe("a", .8)
    assert p.observe("a", .8)


def test_udp_burst_feature_is_explainable():
    events = [event(i, protocol="UDP", dst_port=19001) for i in range(5)]
    result = extract_features(events)
    assert result["udp_ratio"] == 1
    assert result["udp_burst_score"] > 0


def test_ttl_and_integrity_evidence():
    events = [
        event(i, ttl=32 + i, metadata={"payload_altered": i == 2})
        for i in range(5)
    ]
    result = extract_features(events)
    assert result["ttl_anomaly_score"] > 0
    assert result["payload_integrity_anomaly"] > 0


def test_metadata_only_spoof_alteration_and_behavior_evidence():
    events = [
        event(i, src_ip="10.0.0.7", metadata={
            "observed_socket_src_ip": "10.0.0.99",
            "payload_sha256": "bad",
            "expected_payload_sha256": "good",
        })
        for i in range(8)
    ]
    result = extract_features(events)
    assert result["ip_spoofing_score"] == 1
    assert result["packet_alteration_score"] == 1
    assert result["behavior_anomaly_score"] >= 0


def test_alert_contains_explanation_and_categories(tmp_path):
    repository = Repository(tmp_path / "evidence.db")
    config = load_config()
    config["persistence"] = {"consecutive_windows": 1, "cooldown_seconds": 0}
    config["risk"] = {"critical": .85, "high": .7, "medium": .3, "low": .1}
    pipeline = DetectionPipeline(repository=repository, config=config)
    events = [event(i, metadata={"virtual_identity": True}) for i in range(12)]
    alert = pipeline.process_window(events)
    assert alert is not None
    assert alert["attack_category"] == "IP_SPOOFING"
    assert "TreeSHAP" in alert["explanation"]["method"] or alert["explanation"]["method"] == "deterministic-fallback"
    assert alert["top_features"]
    assert repository.alert(alert["alert_id"])["explanation"]
    repository.close()


def test_zeek_and_tshark_metadata_ingestion(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text(
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\n"
        "1704067200.0\tC1\t10.0.0.1\t1234\t10.0.0.2\t502\ttcp\tmodbus\t1.0\t10\t20\n",
        encoding="utf-8",
    )
    zeek_event = next(read_zeek_conn(path))
    assert zeek_event.packet_len == 30
    tshark_event = tshark_row({
        "frame.time_epoch": "1704067200",
        "ip.src": "10.0.0.1",
        "ip.dst": "10.0.0.2",
        "frame.len": "64",
        "ip.checksum.status": "Bad",
        "tcp.payload": "secret",
    })
    assert tshark_event.metadata["checksum_valid"] is False
    assert "tcp.payload" not in tshark_event.metadata


def test_api_health():
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/api/models").json()


def test_hash_chain_tamper_detection(tmp_path):
    from diodeshield.integrity import HashChain, verify_alert, verify_chain

    hc = HashChain()
    a1 = hc.append({"alert_id": "a-1", "timestamp": "2026-09-12T00:00:00Z", "src_ip": "10.0.0.1", "risk_score": 0.9})
    a2 = hc.append({"alert_id": "a-2", "timestamp": "2026-09-12T00:00:01Z", "src_ip": "10.0.0.2", "risk_score": 0.85})

    # Legitimate chain must verify
    assert verify_alert(a1) is True
    assert verify_alert(a2) is True
    chain_result = verify_chain([a1, a2])
    assert chain_result["valid"] is True
    assert chain_result["count"] == 2

    # Tampering with any payload attribute breaks alert verification
    tampered_a1 = dict(a1)
    tampered_a1["risk_score"] = 0.10
    assert verify_alert(tampered_a1) is False

    tampered_a2 = dict(a2)
    tampered_a2["attack_category"] = "FALSE_NORMAL"
    assert verify_alert(tampered_a2) is False

    # Tampered item breaks chain verification
    broken_chain = verify_chain([tampered_a1, a2])
    assert broken_chain["valid"] is False
    assert broken_chain["broken_alert_id"] == "a-1"

    # Breaking previous_hash link breaks chain verification
    unlinked_a2 = dict(a2)
    unlinked_a2["previous_hash"] = "f" * 64
    broken_link = verify_chain([a1, unlinked_a2])
    assert broken_link["valid"] is False
    assert broken_link["broken_sequence"] == 2


def test_repository_tamper_detection(tmp_path):
    import sqlite3

    from diodeshield.config import load_config
    from diodeshield.pipeline import DetectionPipeline

    repo = Repository(tmp_path / "tamper_test.db")
    config = load_config()
    config["persistence"] = {"consecutive_windows": 1, "cooldown_seconds": 0}
    pipeline = DetectionPipeline(repository=repo, config=config)

    events = [event(i, metadata={"virtual_identity": True}) for i in range(12)]
    alert = pipeline.process_window(events)
    assert alert is not None
    alert_id = alert["alert_id"]

    # Initial state is verified
    check1 = repo.verify_integrity()
    assert check1["valid"] is True
    assert check1["count"] == 1

    # Tamper with the database row directly
    conn = sqlite3.connect(tmp_path / "tamper_test.db")
    conn.execute(f"UPDATE alerts SET risk_score = 0.05 WHERE alert_id = '{alert_id}'")
    conn.commit()
    conn.close()

    # Re-checking through repository detects the tampering
    tampered_repo = Repository(tmp_path / "tamper_test.db")
    check2 = tampered_repo.verify_integrity()
    assert check2["valid"] is False
    assert check2["broken_alert_id"] == alert_id
    tampered_repo.close()

