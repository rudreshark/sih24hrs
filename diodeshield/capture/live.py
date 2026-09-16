"""Compatibility import for the receive-only live packet capture engine."""
from __future__ import annotations

from collections.abc import Callable

from diodeshield.capture.sniffer import LiveNetworkCapture
from diodeshield.schemas import TrafficEvent


class LiveCaptureWorker(LiveNetworkCapture):
    """Legacy name backed by the dual-engine live capture implementation."""

    def __init__(self, pipeline, interface: str = "auto",
                 on_event: Callable[[TrafficEvent], None] | None = None, **_: object):
        options = dict(_)
        super().__init__(
            interface=interface,
            on_event_callback=on_event or pipeline.ingest,
            **{key: value for key, value in options.items()
               if key in {"queue_maxsize", "bpf_filter", "engine", "native_bind_host",
                          "native_udp_ports", "native_tcp_port", "native_receive_size"}},
        )
