from __future__ import annotations

from diodeshield.protocol.modbus import parse_modbus_tcp

# OT/ICS and common IT port → service name mapping
_PORT_SERVICE_MAP: dict[int, str] = {
    20000: "DNP3",
    44818: "EtherNet/IP",
    4840:  "OPC UA",
    2404:  "IEC-60870-5-104",
    502:   "Modbus/TCP",
    102:   "S7comm/ISO-TSAP",
    19001: "Custom OT Telemetry",
    47808: "BACnet",
    1911:  "SRTP (GE SRTP)",
    18245: "GE EGD",
    4000:  "Emerson DeltaV",
    34980: "EtherNet/IP (UDP)",
    443:   "HTTPS",
    80:    "HTTP",
    53:    "DNS",
    22:    "SSH",
    23:    "Telnet",
    21:    "FTP",
    25:    "SMTP",
    123:   "NTP",
    161:   "SNMP",
    162:   "SNMP Trap",
    389:   "LDAP",
    445:   "SMB",
    3389:  "RDP",
    4444:  "C2/Reverse-Shell",
}


def resolve_service(port: int | None, protocol: str | None = None) -> str:
    """Return a human-readable service name for the given port number.

    Falls back to ``"unknown"`` for unmapped ports or ``None`` input.

    Args:
        port:     Destination (or source) port number.
        protocol: Optional protocol hint (currently unused but reserved for
                  future disambiguation between TCP/UDP services on the same
                  port number).

    Returns:
        A string service label, e.g. ``"Modbus/TCP"``, ``"DNP3"``, or
        ``"unknown"``.
    """
    if port is None:
        return "unknown"
    try:
        p = int(port)
    except (TypeError, ValueError):
        return "unknown"
    return _PORT_SERVICE_MAP.get(p, "unknown")


__all__ = ["parse_modbus_tcp", "resolve_service", "_PORT_SERVICE_MAP"]
