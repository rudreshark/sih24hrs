"""Production real-time network packet capture engine with dynamic interface selection,
bounded ring-buffer queueing, drop monitoring, and zero synthetic fallback.
"""
from __future__ import annotations

import platform
import queue
import select
import socket
import sys
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import psutil
from scapy.all import conf, get_if_list, sniff
from scapy.packet import Packet

from diodeshield.decoder.packet import decode_scapy_packet, decode_socket_buffer
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
        self.engine: str = "scapy"
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
                "engine": self.engine,
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
        engine: str = "auto",
        native_bind_host: str = "0.0.0.0",
        native_udp_ports: tuple[int, ...] = (502, 102, 2404),
        native_tcp_port: int = 502,
        native_receive_size: int = 65535,
    ) -> None:
        self.requested_interface = interface
        self.resolved_interface: str = "none"
        self.queue_maxsize = queue_maxsize
        self.bpf_filter = bpf_filter
        self.on_event = on_event_callback
        self.engine = engine.lower()
        self.native_bind_host = native_bind_host
        self.native_udp_ports = tuple(sorted({int(p) for p in native_udp_ports if 0 < int(p) < 65536}))
        self.native_tcp_port = int(native_tcp_port)
        self.native_receive_size = max(1024, int(native_receive_size))
        self.packet_queue: queue.Queue[Packet] = queue.Queue(maxsize=queue_maxsize)
        self.stats = CaptureStats()
        self.stop_event = threading.Event()
        self._capture_thread: threading.Thread | None = None
        self._worker_thread: threading.Thread | None = None
        self._local_ips: set[str] = set()
        self._native_sockets: set[socket.socket] = set()
        self._native_clients: dict[socket.socket, tuple[str, int]] = {}
        self._engine_used = "scapy"

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
        self._close_native_sockets()

    def _close_native_sockets(self) -> None:
        sockets = tuple(self._native_sockets)
        self._native_sockets.clear()
        self._native_clients.clear()
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                continue

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
            if self.engine == "native":
                raise RuntimeError("native capture selected")
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
            if self.stop_event.is_set():
                return
            self._engine_used = "native_socket"
            self.stats.engine = self._engine_used
            self.stats.error_message = f"Scapy unavailable; using native sockets: {exc}"
            try:
                self._native_capture_loop()
            except Exception as native_exc:
                self.stats.status = "ERROR"
                self.stats.error_message = str(native_exc)

    def _bind_native_socket(self, sock_type: int, port: int) -> socket.socket:
        sock = socket.socket(socket.AF_INET, sock_type)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        sock.bind((self.native_bind_host, port))
        if sock_type == socket.SOCK_STREAM:
            sock.listen(64)
        self._native_sockets.add(sock)
        return sock

    def _native_capture_loop(self) -> None:
        """Observe traffic delivered to configured local UDP/TCP listener ports."""
        udp_sockets: list[socket.socket] = []
        for port in self.native_udp_ports:
            try:
                udp_sockets.append(self._bind_native_socket(socket.SOCK_DGRAM, port))
            except OSError:
                continue
        if not udp_sockets and self.native_tcp_port <= 0:
            raise OSError("no native listener ports could be bound")
        tcp_server = self._bind_native_socket(socket.SOCK_STREAM, self.native_tcp_port)
        self.resolved_interface = f"native:{self.native_bind_host}"
        self.stats.interface = self.resolved_interface
        self.stats.status = "RUNNING"
        self.stats.error_message = None
        readers: list[socket.socket] = [*udp_sockets, tcp_server]
        while not self.stop_event.is_set():
            readable, _, exceptional = select.select(readers, [], readers, 0.5)
            for sock in exceptional:
                self._remove_native_socket(sock, readers)
            for sock in readable:
                if sock is tcp_server:
                    try:
                        client, address = tcp_server.accept()
                        client.setblocking(False)
                        self._native_sockets.add(client)
                        self._native_clients[client] = (str(address[0]), int(address[1]))
                        readers.append(client)
                    except OSError:
                        continue
                elif sock in udp_sockets:
                    self._read_native_udp(sock)
                else:
                    self._read_native_tcp(sock, readers)
        self._close_native_sockets()

    def _remove_native_socket(self, sock: socket.socket, readers: list[socket.socket]) -> None:
        if sock in readers:
            readers.remove(sock)
        self._native_clients.pop(sock, None)
        self._native_sockets.discard(sock)
        try:
            sock.close()
        except OSError:
            pass

    def _emit_native(self, payload: bytes, peer: tuple[str, int],
                     local: tuple[str, int], protocol: str) -> None:
        self.stats.record_packet(len(payload))
        event = decode_socket_buffer(
            payload, src_addr=peer, dst_addr=local, protocol=protocol,
            interface=self.resolved_interface, local_ips=self._local_ips,
        )
        if self.on_event:
            self.on_event(event)
        self.stats.total_packets_processed += 1

    def _read_native_udp(self, sock: socket.socket) -> None:
        try:
            payload, peer = sock.recvfrom(self.native_receive_size)
            self._emit_native(payload, (str(peer[0]), int(peer[1])),
                              (self.native_bind_host, int(sock.getsockname()[1])), "UDP")
        except (BlockingIOError, ConnectionResetError, OSError):
            return

    def _read_native_tcp(self, sock: socket.socket, readers: list[socket.socket]) -> None:
        try:
            payload = sock.recv(self.native_receive_size)
            if not payload:
                self._remove_native_socket(sock, readers)
                return
            peer = self._native_clients.get(sock, ("0.0.0.0", 0))
            local = (self.native_bind_host, int(sock.getsockname()[1]))
            self._emit_native(payload, peer, local, "TCP")
        except (BlockingIOError, ConnectionResetError, OSError):
            self._remove_native_socket(sock, readers)

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
                self.stats.error_message = "Packet decode or downstream processing failed"
                self.packet_queue.task_done()


def _cli() -> None:
    capture = LiveNetworkCapture(interface="auto", engine="auto")
    capture.start()
    print("DIODESHIELD capture RUNNING; press Ctrl+C to stop.", flush=True)
    try:
        while True:
            time.sleep(5)
            stats = capture.stats.to_dict()
            print(
                f"engine={stats['engine']} status={stats['status']} "
                f"received={stats['total_packets_received']} "
                f"processed={stats['total_packets_processed']} "
                f"dropped={stats['total_packets_dropped']}",
                flush=True,
            )
    except KeyboardInterrupt:
        print("Stopping capture...", flush=True)
    finally:
        capture.stop()


if __name__ == "__main__":
    _cli()
