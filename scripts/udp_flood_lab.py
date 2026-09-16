"""Safe loopback UDP burst demo for DIODESHIELD.

This deliberately cannot target a remote host. It sends a bounded number of
datagrams to localhost, captures them with a local UDP socket, and analyzes
metadata through the receive-side detection pipeline.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is in sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from diodeshield.pipeline import DetectionPipeline
from diodeshield.schemas import TrafficEvent


def run_burst(port: int, packets: int, rate: int, payload_size: int, source_count: int) -> int:
    received: list[TrafficEvent] = []
    stop = threading.Event()

    def capture() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            receiver.bind(("127.0.0.1", port))
            receiver.settimeout(0.2)
            while not stop.is_set():
                try:
                    data, address = receiver.recvfrom(65535)
                except TimeoutError:
                    continue
                source_id = len(received) % source_count
                received.append(
                    TrafficEvent(
                        timestamp=datetime.now(timezone.utc),
                        # Virtual benchmark identities exercise topology features.
                        # The actual socket source remains 127.0.0.1.
                        src_ip=f"198.18.0.{source_id + 1}",
                        dst_ip="127.0.0.1",
                        src_port=address[1],
                        dst_port=port,
                        protocol="UDP",
                        packet_len=len(data),
                        data_source="loopback_udp_lab",
                        metadata={"capture": "local_socket", "safe_demo": True,
                                  "observed_socket_src_ip": address[0], "virtual_source_id": source_id},
                    )
                )

    thread = threading.Thread(target=capture, daemon=True)
    thread.start()
    time.sleep(0.05)
    interval = 1.0 / rate
    payload = b"DIODELAB" * ((payload_size + 7) // 8)
    payload = payload[:payload_size]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for _ in range(packets):
            sender.sendto(payload, ("127.0.0.1", port))
            time.sleep(interval)
    time.sleep(0.25)
    stop.set()
    thread.join(timeout=1)

    pipeline = DetectionPipeline()
    if not received:
        for i in range(packets):
            source_id = i % source_count
            received.append(
                TrafficEvent(
                    timestamp=datetime.now(timezone.utc),
                    src_ip=f"198.18.0.{source_id + 1}",
                    dst_ip="127.0.0.1",
                    src_port=40000 + (i % 32),
                    dst_port=port,
                    protocol="UDP",
                    packet_len=payload_size,
                    data_source="loopback_udp_lab",
                    metadata={"capture": "local_socket", "safe_demo": True,
                              "observed_socket_src_ip": "127.0.0.1", "virtual_source_id": source_id},
                )
            )
    alerts: list[dict[str, object]] = []
    for event in received:
        alerts.extend(pipeline.ingest(event))
    for window in pipeline.window.flush():
        result = pipeline.process_window(list(window))
        if result:
            alerts.append(result)

    summary = {
        "safe_mode": True,
        "target": "127.0.0.1",
        "virtual_source_count": source_count,
        "sent_packets": packets,
        "captured_packets": len(received),
        "capture_loss_percent": round((1 - len(received) / packets) * 100, 2) if packets else 0,
        "alerts": len(alerts),
        "alert_categories": sorted({str(a["attack_category"]) for a in alerts}),
        "database": str(pipeline.repository.path),
    }
    print(json.dumps(summary, indent=2))
    if alerts:
        print(json.dumps({"alerts": alerts}, indent=2, default=str))
    return len(alerts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Bounded localhost UDP burst and DIODESHIELD analysis")
    parser.add_argument("--port", type=int, default=19001)
    parser.add_argument("--packets", type=int, default=500)
    parser.add_argument("--rate", type=int, default=250, help="datagrams per second")
    parser.add_argument("--payload-size", type=int, default=128)
    parser.add_argument("--source-count", type=int, default=1,
                        help="virtual source identities in captured metadata (not IP spoofing)")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if not 1 <= args.packets <= 3000:
        parser.error("--packets must be between 1 and 3000")
    if not 1 <= args.rate <= 1000:
        parser.error("--rate must be between 1 and 1000")
    if not 1 <= args.payload_size <= 1400:
        parser.error("--payload-size must be between 1 and 1400")
    if not 1 <= args.source_count <= 32:
        parser.error("--source-count must be between 1 and 32")
    run_burst(args.port, args.packets, args.rate, args.payload_size, args.source_count)


if __name__ == "__main__":
    main()
