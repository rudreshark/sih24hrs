"""Convert observed Scapy packets into the pipeline's stable event schema."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet, Raw

from diodeshield.schemas import TrafficEvent


def decode_socket_buffer(
    payload: bytes,
    *,
    src_addr: tuple[str, int],
    dst_addr: tuple[str, int],
    protocol: str,
    interface: str = "native_socket",
    timestamp: datetime | None = None,
    local_ips: set[str] | None = None,
) -> TrafficEvent:
    """Normalize bytes received by a native UDP/TCP listener.

    Native sockets expose application payloads rather than full IP frames, so
    transport metadata comes from the socket addresses and packet fields that
    are unavailable are left unset.
    """
    src_ip, src_port = str(src_addr[0]), int(src_addr[1])
    dst_ip, dst_port = str(dst_addr[0]), int(dst_addr[1])
    metadata: dict[str, Any] = {
        "interface": interface,
        "capture_engine": "native_socket",
        "raw_payload": payload,
    }
    if local_ips and src_ip in local_ips:
        metadata["direction"] = "outbound"
    elif local_ips and dst_ip in local_ips:
        metadata["direction"] = "inbound"
    return TrafficEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol.upper(),
        packet_len=len(payload),
        payload_hex=payload.hex()[:128] if payload else None,
        data_source="native_socket_live",
        metadata=metadata,
    )


def _layer(packet: Packet, layer: Any) -> Any:
    return packet.getlayer(layer)


def decode_scapy_packet(
    packet: Packet,
    *,
    interface: str = "unknown",
    local_ips: set[str] | None = None,
) -> TrafficEvent | None:
    """Decode metadata only; payload bytes are not forwarded to persistence."""
    ip = _layer(packet, IP)
    ip_version = "IPv4"
    if ip is None:
        ip = _layer(packet, IPv6)
        ip_version = "IPv6"
    if ip is None:
        return None

    tcp = _layer(packet, TCP)
    udp = _layer(packet, UDP)
    transport = tcp or udp
    protocol = "TCP" if tcp is not None else "UDP" if udp is not None else ip_version
    payload = _layer(packet, Raw)
    metadata: dict[str, Any] = {
        "interface": interface,
        "ip_version": ip_version,
        "observed_socket_src_ip": str(getattr(ip, "src", "")),
    }
    if local_ips and str(getattr(ip, "src", "")) in local_ips:
        metadata["direction"] = "outbound"
    elif local_ips and str(getattr(ip, "dst", "")) in local_ips:
        metadata["direction"] = "inbound"

    return TrafficEvent(
        timestamp=datetime.now(timezone.utc),
        src_ip=str(getattr(ip, "src", "0.0.0.0")),
        dst_ip=str(getattr(ip, "dst", "0.0.0.0")),
        src_port=int(getattr(transport, "sport", 0)) if transport is not None else None,
        dst_port=int(getattr(transport, "dport", 0)) if transport is not None else None,
        protocol=protocol,
        packet_len=len(packet),
        ttl=getattr(ip, "hlim", None) if ip_version == "IPv6" else getattr(ip, "ttl", None),
        ip_id=getattr(ip, "id", None) if ip_version == "IPv4" else None,
        ip_flags=int(getattr(ip, "flags", 0)) if ip_version == "IPv4" else None,
        tcp_flags=str(getattr(tcp, "flags", "")) if tcp is not None else None,
        payload_hex=bytes(payload).hex()[:128] if payload is not None else None,
        data_source="scapy_live",
        metadata=metadata,
    )
