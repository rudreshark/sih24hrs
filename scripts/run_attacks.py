"""Convenient attack simulation runner for DIODESHIELD demonstrations.

Run individual attack scenarios or all in sequence:
  python scripts/run_attacks.py --scenario flood
  python scripts/run_attacks.py --scenario spoof
  python scripts/run_attacks.py --scenario altered
  python scripts/run_attacks.py --all
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Ensure project root is in sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import requests


def inject_via_api(scenario: str, count: int = 250) -> dict | None:
    url = "http://127.0.0.1:8000/api/simulator/inject"
    try:
        r = requests.post(url, json={"scenario": scenario, "count": count}, timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def run_scenario(name: str, count: int = 250):
    print(f"\n[>>>] Running attack simulation: {name.upper()} ({count} packets)...")
    res = inject_via_api(name, count)
    if res and res.get("status") == "injected":
        alert = res.get("latest_alert")
        print("[+] Injected via DIODESHIELD live server")
        print(f"    Packets sent:     {res.get('packets')}")
        print(f"    Alerts triggered: {res.get('alerts_generated')}")
        if alert:
            print(f"    Detected Attack:  {alert.get('attack_category')}")
            print(f"    Risk Level:       {alert.get('risk_level')} (score: {alert.get('risk_score')})")
            reasons = ", ".join(alert.get("reasons", []))
            print(f"    Evidence Reasons: {reasons}")
        return

    # Fallback to local offline runner
    from scripts.offline_threat_lab import run
    report = run(name, count=count, batch_size=count)
    print("[+] Injected via internal pipeline")
    print(f"    Alerts generated: {report.get('alerts')}")
    print(f"    Categories:       {', '.join(report.get('categories', []))}")
    print(f"    Max Risk:         {report.get('max_risk')}")


def main():
    parser = argparse.ArgumentParser(description="DIODESHIELD Attack Scenario Runner")
    parser.add_argument("--scenario", choices=["flood", "spoof", "altered", "beacon", "recon"],
                        default="flood", help="Attack scenario to simulate")
    parser.add_argument("--count", type=int, default=300, help="Number of packets to inject")
    parser.add_argument("--all", action="store_true", help="Run flood, spoof, and altered in sequence")
    args = parser.parse_args()

    if args.all:
        for s in ["flood", "spoof", "altered"]:
            run_scenario(s, args.count)
            time.sleep(1)
    else:
        run_scenario(args.scenario, args.count)


if __name__ == "__main__":
    main()
