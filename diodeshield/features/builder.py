from __future__ import annotations

from collections import Counter
from typing import Any

import numpy as np

from diodeshield.schemas import TrafficEvent


def _entropy(values: list[Any]) -> float:
    if not values:
        return 0.0
    counts = Counter(values)
    probs = np.array(list(counts.values()), dtype=float) / len(values)
    return float(-(probs * np.log2(probs)).sum())


def _skew(values: np.ndarray) -> float:
    if len(values) < 3 or values.std() == 0:
        return 0.0
    return float(((values - values.mean()) ** 3).mean() / values.std() ** 3)


def _kurtosis(values: np.ndarray) -> float:
    if len(values) < 4 or values.std() == 0:
        return 0.0
    return float(((values - values.mean()) ** 4).mean() / values.std() ** 4 - 3)


def _metadata_flag(event: TrafficEvent, *names: str) -> bool:
    """Read a boolean observation without treating arbitrary strings as truthy."""
    for name in names:
        value = event.metadata.get(name)
        if value is True or (isinstance(value, str) and value.lower() in {"true", "yes", "1"}):
            return True
    return False


def _ip_mismatch(event: TrafficEvent) -> bool:
    """Detect an observed identity mismatch using capture metadata only.

    The capture source may provide the address seen on the local socket, TAP, or
    an asset profile.  This is an indicator for investigation, not proof of
    spoofing, because NAT and proxying can create legitimate mismatches.
    """
    for key in ("observed_socket_src_ip", "observed_src_ip", "wire_src_ip", "expected_src_ip"):
        observed = event.metadata.get(key)
        if observed and str(observed) != event.src_ip:
            return True
    return False


def _alteration_indicator(event: TrafficEvent) -> bool:
    """Return true for explicit integrity evidence supplied by a safe sensor."""
    if _metadata_flag(event, "payload_altered", "packet_altered", "checksum_mismatch",
                      "ip_checksum_invalid", "tcp_checksum_invalid", "udp_checksum_invalid"):
        return True
    if event.metadata.get("checksum_valid") is False:
        return True
    for actual, expected in (("payload_sha256", "expected_payload_sha256"),
                             ("payload_hash", "expected_payload_hash"),
                             ("packet_hash", "expected_packet_hash")):
        if event.metadata.get(actual) and event.metadata.get(expected):
            return str(event.metadata[actual]).lower() != str(event.metadata[expected]).lower()
    return False


def spectral_features(iats: list[float]) -> dict[str, float]:
    if len(iats) < 4:
        return {"dominant_frequency": 0.0, "spectral_flatness": 0.0, "harmonic_ratio": 0.0,
                "spectral_centroid": 0.0, "periodicity_score": 0.0}
    signal = np.asarray(iats, dtype=float)
    signal = signal - signal.mean()
    magnitude = np.abs(np.fft.rfft(signal))[1:]
    if not len(magnitude) or magnitude.max() == 0:
        return {"dominant_frequency": 0.0, "spectral_flatness": 0.0, "harmonic_ratio": 0.0,
                "spectral_centroid": 0.0, "periodicity_score": 0.0}
    freqs = np.fft.rfftfreq(len(signal), d=max(float(np.mean(iats)), 1e-6))[1:]
    dominant = int(np.argmax(magnitude))
    geometric = float(np.exp(np.mean(np.log(magnitude + 1e-12))))
    arithmetic = float(np.mean(magnitude))
    return {"dominant_frequency": float(freqs[dominant]), "spectral_flatness": geometric / (arithmetic + 1e-12),
            "harmonic_ratio": float(magnitude[dominant] / (magnitude.sum() + 1e-12)),
            "spectral_centroid": float((freqs * magnitude).sum() / (magnitude.sum() + 1e-12)),
            "periodicity_score": float(magnitude[dominant] / (magnitude.mean() + 1e-12))}


def extract_features(events: list[TrafficEvent], baseline: dict[str, float] | None = None) -> dict[str, float | str]:
    baseline = baseline or {}
    if not events:
        return {"packets": 0.0, "bytes": 0.0, "packets_per_sec": 0.0, "bytes_per_sec": 0.0,
                "flow_count": 0.0, "empty_window": 1.0, "periodicity_score": 0.0}
    ordered = sorted(events, key=lambda event: event.timestamp)
    duration = max((ordered[-1].timestamp - ordered[0].timestamp).total_seconds(), 1.0)
    iats = np.diff([event.timestamp.timestamp() for event in ordered]).astype(float)
    lengths = [event.packet_len for event in ordered]
    dsts = [event.dst_ip for event in ordered]
    srcs = [event.src_ip for event in ordered]
    ports = [event.dst_port for event in ordered if event.dst_port is not None]
    ttl = [event.ttl for event in ordered if event.ttl is not None]
    values: dict[str, float | str] = {
        "packets": float(len(ordered)), "bytes": float(sum(lengths)),
        "packets_per_sec": len(ordered) / duration, "bytes_per_sec": sum(lengths) / duration,
        "flow_count": float(len({(e.src_ip, e.dst_ip, e.src_port, e.dst_port, e.protocol) for e in ordered})),
        "port_diversity": float(len(set(ports))), "destination_diversity": float(len(set(dsts))),
        "source_diversity": float(len(set(srcs))), "fan_out": float(len(set(dsts))),
        "fan_in": float(len(set(srcs))), "new_ip_ratio": float(len(set(dsts)) / len(ordered)),
        "subnet_diversity": float(len({x.rsplit(".", 1)[0] for x in dsts if "." in x})),
        "packet_len_mean": float(np.mean(lengths)), "packet_len_std": float(np.std(lengths)),
        "ttl_mean": float(np.mean(ttl)) if ttl else 0.0, "ttl_delta": float(max(ttl) - min(ttl)) if ttl else 0.0,
        "ip_id_entropy": _entropy([e.ip_id for e in ordered if e.ip_id is not None]),
        "ip_flags_entropy": _entropy([e.ip_flags for e in ordered if e.ip_flags is not None]),
        "tcp_flags_entropy": _entropy([e.tcp_flags for e in ordered if e.tcp_flags]),
        "dscp_entropy": _entropy([e.dscp for e in ordered if e.dscp is not None]),
        "iat_mean": float(np.mean(iats)) if len(iats) else 0.0,
        "iat_variance": float(np.var(iats)) if len(iats) else 0.0,
        "iat_std": float(np.std(iats)) if len(iats) else 0.0,
        "iat_skewness": _skew(iats), "iat_kurtosis": _kurtosis(iats),
    }
    values["iat_cv"] = float(values["iat_std"]) / (float(values["iat_mean"]) + 1e-9)
    values["baseline_deviation"] = float(np.mean([abs(float(v) - baseline.get(k, float(v))) / (abs(baseline.get(k, float(v))) + 1) for k, v in values.items() if isinstance(v, (float, int))])) if baseline else 0.0
    values.update(spectral_features(iats.tolist()))
    values["authorized_peer_status"] = 1.0 if baseline.get("authorized_peer_status", 1.0) else 0.0
    values["lateral_movement_score"] = min(1.0, float(values["fan_out"]) / 10.0)
    values["protocol"] = Counter(e.protocol.upper() for e in ordered).most_common(1)[0][0]
    udp_packets = sum(1 for event in ordered if event.protocol.upper() == "UDP")
    udp_ratio = udp_packets / len(ordered)
    values["udp_ratio"] = float(udp_ratio)
    values["udp_burst_score"] = float(min(1.0, udp_ratio * max(
        float(values["packets_per_sec"]) / 100.0,
        float(values["bytes_per_sec"]) / 100000.0,
    )))
    ttls = [event.ttl for event in ordered if event.ttl is not None]
    values["ttl_anomaly_score"] = float(min(1.0, max(0, len(set(ttls)) - 1) / 4.0))
    altered = sum(1 for event in ordered if _alteration_indicator(event))
    values["payload_integrity_anomaly"] = float(altered / len(ordered))
    values["packet_alteration_score"] = values["payload_integrity_anomaly"]
    spoofed = sum(1 for event in ordered if _ip_mismatch(event) or _metadata_flag(
        event, "virtual_identity", "ip_spoofing", "spoofed", "mac_ip_conflict"))
    values["ip_spoofing_score"] = float(spoofed / len(ordered))
    values["identity_anomaly_score"] = values["ip_spoofing_score"]

    # Beaconing and periodicity features distinguishing standard OT polling from C2 beaconing
    ot_ports = {502, 102, 20000, 44818, 4840}
    is_ot_port = any(p in ot_ports for p in ports if isinstance(p, (int, float)))
    # High client-side ports are normal for HTTPS, SaaS, and ephemeral TCP
    # connections.  Do not classify every regular cloud flow as C2 merely
    # because its destination port is above 1024.
    suspicious_c2 = any(p in {4444, 1337, 9001} for p in ports if isinstance(p, (int, float)))
    regularity = max(0.0, min(1.0, 1.0 - (values["iat_cv"] / 0.20))) if values["packets"] >= 4 and values["iat_mean"] > 0 else 0.0
    values["periodicity_score"] = float(max(values.get("periodicity_score", 0.0), regularity * 4.0))
    recurring_single_peer = values["fan_out"] <= 1 and values["new_ip_ratio"] <= 0.25
    unknown_peer_signal = values["fan_out"] > 1 or values["new_ip_ratio"] > 0.50
    if (is_ot_port or (recurring_single_peer and not suspicious_c2)) and not suspicious_c2:
        values["beacon_score"] = 0.0
    else:
        values["beacon_score"] = float(min(
            1.0,
            0.55 * regularity
            + 0.30 * (1.0 if suspicious_c2 else 0.0)
            + 0.15 * (1.0 if unknown_peer_signal else 0.0),
        ))

    # A bounded, explainable behavior signal combines independent metadata-only
    # indicators.  It intentionally does not classify an event by itself.
    values["behavior_anomaly_score"] = float(min(
        1.0,
        0.25 * _norm_feature(values.get("baseline_deviation", 0), 2.0)
        + 0.35 * _norm_feature(values.get("fan_out", 0), 10.0)
        + 0.15 * _norm_feature(values.get("port_diversity", 0), 10.0)
        + 0.15 * float(values.get("udp_burst_score", 0))
        + 0.10 * _norm_feature(values.get("periodicity_score", 0), 10.0)
        + 0.15 * float(values.get("beacon_score", 0)),
    ))

    # Embedded/IoT network dataset feature aliases
    values["packet_size"] = float(values.get("packet_len_mean", 0.0))
    values["inter_arrival_time"] = float(values.get("iat_mean", 0.0))
    values["packet_count_5s"] = float(values.get("packets", 0.0))
    values["mean_packet_size"] = float(values.get("packet_len_mean", 0.0))
    values["spectral_entropy"] = float(values.get("spectral_flatness", 0.0))
    values["frequency_band_energy"] = float(values.get("harmonic_ratio", 0.0))
    proto = str(values.get("protocol", "")).upper()
    values["protocol_type_TCP"] = 1.0 if proto == "TCP" else 0.0
    values["protocol_type_UDP"] = 1.0 if proto == "UDP" else 0.0
    src_ports = [event.src_port for event in ordered if event.src_port is not None]
    values["src_port"] = float(src_ports[0]) if src_ports else 0.0
    values["dst_port"] = float(ports[0]) if ports else 0.0
    for ip in ("192.168.1.2", "192.168.1.3"):
        values[f"src_ip_{ip}"] = 1.0 if any(e.src_ip == ip for e in ordered) else 0.0
    for ip in ("192.168.1.5", "192.168.1.6"):
        values[f"dst_ip_{ip}"] = 1.0 if any(e.dst_ip == ip for e in ordered) else 0.0
    flags_seen = set()
    for e in ordered:
        if e.tcp_flags:
            flags_seen.update(str(e.tcp_flags).upper().split(","))
    values["tcp_flags_FIN"] = 1.0 if "FIN" in flags_seen else 0.0
    values["tcp_flags_SYN"] = 1.0 if "SYN" in flags_seen and "ACK" not in flags_seen else 0.0
    values["tcp_flags_SYN-ACK"] = 1.0 if ("SYN" in flags_seen and "ACK" in flags_seen) or "SYN-ACK" in flags_seen else 0.0

    return values


def _norm_feature(value: Any, scale: float) -> float:
    try:
        return min(1.0, abs(float(value)) / max(scale, 1e-9))
    except (TypeError, ValueError):
        return 0.0
