"""Explicit, audited host-firewall actions for validated indicators."""

from __future__ import annotations

import ipaddress
import hashlib
import os
import platform
import subprocess
from typing import Any


def _rule_name(address: ipaddress._BaseAddress) -> str:
    digest = hashlib.sha256(str(address).encode("ascii")).hexdigest()[:16]
    return f"DIODESHIELD-{digest}"


def _run_netsh(command: list[str]) -> None:
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "netsh failed")


def _require_enabled() -> None:
    if os.getenv("DIODESHIELD_FIREWALL_BLOCKING", "").lower() not in {"1", "true", "yes"}:
        raise PermissionError(
            "Firewall actions are disabled. Set DIODESHIELD_FIREWALL_BLOCKING=true "
            "and run the API with administrator rights."
        )


def block_ip(ip: str, alert_id: str = "", reason: str = "") -> dict[str, Any]:
    address = ipaddress.ip_address(ip)
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError("refusing to block loopback, unspecified, or multicast addresses")
    _require_enabled()
    if platform.system() != "Windows":
        raise RuntimeError("automatic firewall integration currently supports Windows only")
    name = _rule_name(address)
    common = ["netsh", "advfirewall", "firewall", "add", "rule", "action=block",
              f"remoteip={address}", "enable=yes", "profile=any"]
    directions = (("in", f"{name}-IN"), ("out", f"{name}-OUT"))
    try:
        for direction, direction_name in directions:
            _run_netsh([*common, f"name={direction_name}", f"dir={direction}"])
    except RuntimeError:
        # Do not leave a one-way block behind if the paired rule cannot be added.
        for _, direction_name in directions:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={direction_name}"],
                capture_output=True,
                text=True,
                check=False,
            )
        raise
    return {
        "status": "blocked",
        "dry_run": False,
        "ip": str(address),
        "rule": name,
        "rules": [f"{name}-IN", f"{name}-OUT"],
        "reason": reason,
    }


def unblock_ip(ip: str) -> dict[str, Any]:
    address = ipaddress.ip_address(ip)
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError("refusing to manage loopback, unspecified, or multicast addresses")
    _require_enabled()
    if platform.system() != "Windows":
        raise RuntimeError("automatic firewall integration currently supports Windows only")
    name = _rule_name(address)
    for direction in ("IN", "OUT"):
        _run_netsh(["netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={name}-{direction}"])
    return {
        "status": "unblocked",
        "dry_run": False,
        "ip": str(address),
        "rule": name,
        "rules": [f"{name}-IN", f"{name}-OUT"],
    }
