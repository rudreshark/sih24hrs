from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TrafficEvent(BaseModel):
    timestamp: datetime = Field(default_factory=utcnow)
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "TCP"
    packet_len: int = 0
    ttl: int | None = None
    ip_id: int | None = None
    ip_flags: int | None = None
    tcp_flags: str | None = None
    dscp: int | None = None
    payload_hex: str | None = None
    data_source: str = "synthetic"
    asset_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Feedback(BaseModel):
    alert_id: str
    label: str = Field(pattern="^(TRUE_POSITIVE|FALSE_POSITIVE|BENIGN|UNKNOWN)$")
    comment: str = ""


class BlockRequest(BaseModel):
    confirm: bool = False
    reason: str = ""


class ConfigUpdate(BaseModel):
    values: dict[str, Any]


class InterfaceSelectRequest(BaseModel):
    interface_id: str = Field(min_length=1)
