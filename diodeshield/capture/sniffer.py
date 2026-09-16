"""Production real-time network packet capture engine with dynamic interface selection,
bounded ring-buffer queueing, drop monitoring, and zero synthetic fallback.
"""
from __future__ import annotations

import platform
import queue
import sys
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import psutil
from scapy.all import conf, get_if_list, sniff
from scapy.packet import Packet

from diodeshield.decoder.packet import decode_scapy_packet
from diodeshield.schemas import TrafficEvent


class CaptureStats:
    def __init__(self) -> None:
        self.total_packets_received: int = 0
        self.total_packets_processed: int = 0
        self.total_packets_dropped: int = 0
        self.total_bytes_received: int = 0
        self.current_pps: float = 0.0
        self.current_bps: float = 0.0
        self.queue_depth: int = 0
        self.capture_start_time: str | None = None
        self.last_packet_time: str | None = None
        self.interface: str = "none"
        self.status: str = "STOPPED"
        self.error_message: str | None = None
        self._window_lock = threading.Lock()
        self._last_calc_time = time.time()
        self._window_packets = 0
        self._window_bytes = 0

    def record_packet(self, size: int) -> None:
        with self._window_lock:
            self.total_packets_received += 1
            self.total_bytes_received += size
            self._window_packets += 1
            self._window_bytes += size
            self.last_packet_time = datetime.now(timezone.utc).isoformat()
            self._update_rates_locked()

    def record_drop(self) -> None:
        with self._window_lock:
            self.total_packets_dropped += 1

    def _update_rates_locked(self) -> None:
        now = time.time()
        elapsed = now - self._last_calc_time
        if elapsed >= 1.0:
            self.current_pps = round(self._window_packets / elapsed, 2)
            self.current_bps = round((self._window_bytes * 8) / elapsed, 2)
            self._window_packets = 0
            self._window_bytes = 0
            self._last_calc_time = now

    def to_dict(self) -> dict[str, Any]:
        with self._window_lock:
            now = time.time()
            elapsed = now - self._last_calc_time
            if elapsed >= 2.0:
                # Idle decay
                self.current_pps = 0.0
                self.current_bps = 0.0
            return {
                "interface": self.interface,
                "status": self.status,
                "total_packets_received": self.total_packets_received,
                "total_packets_processed": self.total_packets_processed,
                "total_packets_dropped": self.total_packets_dropped,
                "total_bytes_received": self.total_bytes_received,
                "current_pps": self.current_pps,
                "current_bps": self.current_bps,
                "queue_depth": self.queue_depth,
                "capture_start_time": self.capture_start_time,
                "last_packet_time": self.last_packet_time,
                "error_message": self.error_message,
            }


def list_network_interfaces() -> list[dict[str, Any]]:
    """Enumerate all available physical and virtual network interfaces."""
    interfaces: list[dict[str, Any]] = []
    is_windows = platform.system() == "Windows"

    win_if_map: dict[str, dict[str, Any]] = {}
    if is_windows:
        try:
            from scapy.arch.windows import get_windows_if_list
            for w in get_windows_if_list():
                guid = w.get("guid", "")
                win_if_map[guid] = w
                win_if_map[w.get("name", "")] = w
        except Exception:
            pass

    psutil_addrs = psutil.net_if_addrs()
    psutil_stats = psutil.net_if_stats()

    for name, addrs in psutil_addrs.items():
        ipv4_list: list[str] = []
        ipv6_list: list[str] = []
        mac = ""

        for addr in addrs:
            if addr.family == psutil.AF_LINK:
                mac = addr.address
            elif addr.family == 2:  # AF_INET
                ipv4_list.append(addr.address)
            elif addr.family == 23 or addr.family == 10:  # AF_INET6
                ipv6_list.append(addr.address)

        stats = psutil_stats.get(name)
        is_up = stats.isup if stats else False
        speed = stats.speed if stats else 0

        # Match with scapy win_if_map
        win_info = win_if_map.get(name, {})
        description = win_info.get("description", name)
        guid = win_info.get("guid", "")
        scapy_id = f"\\Device\\NPF_{guid}" if guid and is_windows else name

        interfaces.append({
            "id": scapy_id if is_windows and guid else name,
            "name": name,
            "description": description,
            "ipv4": ipv4_list,
            "ipv6": ipv6_list,
            "mac": mac,
            "is_up": is_up,
            "speed_mbps": speed,
            "guid": guid,
        })

    return interfaces


class LiveNetworkCapture:
    """Production live packet capture worker using Scapy/Npcap with non-blocking queueing."""

    def __init__(
        self,
        interface: str = "auto",
        queue_maxsize: int = 20000,
        bpf_filter: str = "",
        on_event_callback: Callable[[TrafficEvent], None] | None = None,
    ) -> None:
        self.requested_interface = interface
        self.resolved_interface: str = "none"
        self.queue_maxsize = queue_maxsize
        self.bpf_filter = bpf_filter
        self.on_event = on_event_callback
        self.packet_queue: queue.Queue[Packet] = queue.Queue(maxsize=queue_maxsize)
        self.stats = CaptureStats()
        self.stop_event = threading.Event()
        self._capture_thread: threading.Thread | None = None
        self._worker_thread: threading.Thread | None = None
        self._local_ips: set[str] = set()

    def _resolve_interface(self) -> str:
        if self.requested_interface and self.requested_interface != "auto":
            return self.requested_interface

        interfaces = list_network_interfaces()
        io_counters = psutil.net_io_counters(pernic=True)

        # Virtual adapter identifiers to deprioritize
        virtual_patterns = ("virtual", "vmware", "vmnet", "vbox", "virtualbox", "vethernet", "loopback", "teredo")

        # Rank candidates: (not_virtual, active_traffic, is_up, speed)
        def _rank(iface: dict[str, Any]) -> tuple[int, int, int]:
            name = iface.get("name", "").lower()
            desc = iface.get("description", "").lower()
            is_virtual = any(p in name or p in desc for p in virtual_patterns)
            stats = io_counters.get(iface.get("name", ""))
            pkts = (stats.packets_recv + stats.packets_sent) if stats else 0
            is_up = 1 if iface.get("is_up") else 0
            return (0 if is_virtual else 1, is_up, pkts)

        valid_candidates = [iface for iface in interfaces if iface.get("ipv4")]
        if valid_candidates:
            best = max(valid_candidates, key=_rank)
            return str(best["id"])

        if interfaces:
            return str(interfaces[0]["id"])

        try:
            return str(conf.iface)
        except Exception:
            return "auto"

    def _collect_local_ips(self) -> None:
        self._local_ips.clear()
        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.address:
                    self._local_ips.add(addr.address)

    def start(self) -> bool:
        if self._capture_thread and self._capture_thread.is_alive():
            return True

        self.stop_event.clear()
        self.resolved_interface = self._resolve_interface()
        self.stats.interface = self.resolved_interface
        self.stats.status = "RUNNING"
        self.stats.capture_start_time = datetime.now(timezone.utc).isoformat()
        self.stats.error_message = None
        self._collect_local_ips()

        self._worker_thread = threading.Thread(
            target=self._process_queue_loop,
            name="diodeshield-queue-worker",
            daemon=True,
        )
        self._worker_thread.start()

        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            name="diodeshield-packet-capture",
            daemon=True,
        )
        self._capture_thread.start()
        return True

    def stop(self) -> None:
        self.stop_event.set()
        self.stats.status = "STOPPED"
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=1.0)
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=1.0)

    def _capture_loop(self) -> None:
        """Dedicated high-priority capture thread. Pushes packets directly into ring-buffer."""
        def packet_handler(pkt: Packet) -> None:
            if self.stop_event.is_set():
                return
            size = len(pkt)
            self.stats.record_packet(size)
            try:
                self.packet_queue.put_nowait(pkt)
            except queue.Full:
                self.stats.record_drop()

        try:
            kwargs: dict[str, Any] = {
                "prn": packet_handler,
                "store": False,
                "stop_filter": lambda _: self.stop_event.is_set(),
            }
            if self.bpf_filter:
                kwargs["filter"] = self.bpf_filter
            if self.resolved_interface and self.resolved_interface != "auto":
                kwargs["iface"] = self.resolved_interface

            sniff(**kwargs)
        except Exception as exc:
            self.stats.status = "ERROR"
            self.stats.error_message = str(exc)

    def _process_queue_loop(self) -> None:
        """Asynchronous worker decoding and routing events without delaying capture loop."""
        while not self.stop_event.is_set():
            try:
                pkt = self.packet_queue.get(timeout=0.2)
                self.stats.queue_depth = self.packet_queue.qsize()
                event = decode_scapy_packet(pkt, interface=self.resolved_interface, local_ips=self._local_ips)
                if event and self.on_event:
                    self.on_event(event)
                self.stats.total_packets_processed += 1
                self.packet_queue.task_done()
            except queue.Empty:
                self.stats.queue_depth = 0
                continue
            except Exception:
                pass
