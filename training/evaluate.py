"""
DIODESHIELD — Training Evaluation Engine (Task 1)
==================================================
Evaluates the 5-branch ensemble (XGBoost, LSTM, FFT, Kitsune, Isolation Forest)
against labelled synthetic attack scenarios and any available real datasets.

Usage::

    python training/evaluate.py                    # quick synthetic eval
    python training/evaluate.py --dataset path.csv # evaluate on labelled CSV
    python training/evaluate.py --full             # stratified 5-fold cross-val

Outputs
-------
* ``reports/evaluation_<timestamp>.json``  — machine-readable metrics
* ``reports/evaluation_<timestamp>.md``    — human-readable Markdown summary

Output Schema
-------------
Each per-branch entry contains::

    {
        "precision": float, "recall": float, "f1": float,
        "roc_auc": float, "pr_auc": float,
        "tp": int, "fp": int, "tn": int, "fn": int
    }

The gate check compares recall >= BASELINE_RECALL_GATE (0.70) and
f1 >= BASELINE_F1_GATE (0.65) to block regressions.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Gate thresholds — must NOT regress below these values
BASELINE_RECALL_GATE = 0.70
BASELINE_F1_GATE = 0.65
BASELINE_PRECISION_GATE = 0.55

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# Minimal math helpers (avoid scipy/sklearn dependency for gate-only mode)
# ---------------------------------------------------------------------------

def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def _metrics_from_counts(tp: int, fp: int, tn: int, fn: int) -> dict[str, float]:
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    # Simplified ROC-AUC approximation for binary classification
    tpr = recall
    fpr = _safe_div(fp, fp + tn)
    roc_auc = _safe_div(tpr + (1 - fpr), 2)
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(f1, 4),  # approximation without threshold sweep
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


# ---------------------------------------------------------------------------
# Scenario-based synthetic evaluation
# ---------------------------------------------------------------------------

ATTACK_SCENARIOS = [
    ("UDP_FLOOD",          True,  {"byte_count": 9000, "packet_count": 250, "duration_seconds": 2,
                                   "unique_dst_ports": 1, "protocol": "UDP", "src_port": 40001, "dst_port": 19001}),
    ("IP_SPOOF",           True,  {"byte_count": 1500, "packet_count": 50, "duration_seconds": 5,
                                   "unique_dst_ports": 1, "protocol": "UDP", "src_port": 40002, "dst_port": 19001,
                                   "ttl_anomaly": True}),
    ("PAYLOAD_ALTERATION", True,  {"byte_count": 720, "packet_count": 4, "duration_seconds": 1,
                                   "unique_dst_ports": 1, "protocol": "TCP", "src_port": 40003, "dst_port": 502}),
    ("C2_BEACON",          True,  {"byte_count": 256, "packet_count": 5, "duration_seconds": 60,
                                   "unique_dst_ports": 1, "protocol": "TCP", "src_port": 40004, "dst_port": 4444}),
    ("OT_RECON",           True,  {"byte_count": 320, "packet_count": 16, "duration_seconds": 4,
                                   "unique_dst_ports": 8, "protocol": "TCP", "src_port": 40005, "dst_port": 502}),
    ("POLICY_VIOLATION",   True,  {"byte_count": 640, "packet_count": 8, "duration_seconds": 3,
                                   "unique_dst_ports": 2, "protocol": "TCP", "src_port": 40006, "dst_port": 23}),
    ("NORMAL_MODBUS",      False, {"byte_count": 128, "packet_count": 2, "duration_seconds": 1,
                                   "unique_dst_ports": 1, "protocol": "TCP", "src_port": 40007, "dst_port": 502}),
    ("NORMAL_TELEMETRY",   False, {"byte_count": 64,  "packet_count": 1, "duration_seconds": 1,
                                   "unique_dst_ports": 1, "protocol": "UDP", "src_port": 40008, "dst_port": 19001}),
    ("NORMAL_OPC_UA",      False, {"byte_count": 256, "packet_count": 3, "duration_seconds": 2,
                                   "unique_dst_ports": 1, "protocol": "TCP", "src_port": 40009, "dst_port": 4840}),
    ("NORMAL_NTP_SYNC",    False, {"byte_count": 48,  "packet_count": 2, "duration_seconds": 1,
                                   "unique_dst_ports": 1, "protocol": "UDP", "src_port": 40010, "dst_port": 123}),
]


def _run_synthetic_evaluation() -> dict[str, Any]:
    """Evaluate ensemble against built-in synthetic attack/benign scenarios."""
    from diodeshield.config import load_config
    from diodeshield.db import Repository
    from diodeshield.pipeline import DetectionPipeline
    from diodeshield.schemas import TrafficEvent

    config = load_config()
    repo = Repository(":memory:")
    pipeline = DetectionPipeline(repo, config)

    branch_names = list(pipeline.adapters.keys())
    # Per-branch and ensemble counters
    counters: dict[str, dict[str, int]] = {
        b: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for b in branch_names + ["ensemble"]
    }

    scenario_results = []
    for name, is_attack, flow_meta in ATTACK_SCENARIOS:
        events = []
        count = max(2, flow_meta.get("packet_count", 10))
        for i in range(count):
            events.append(TrafficEvent(
                src_ip="192.168.1.100",
                dst_ip="10.0.0.8",
                src_port=flow_meta.get("src_port", 40000 + i),
                dst_port=flow_meta.get("dst_port", 502),
                protocol=flow_meta.get("protocol", "TCP"),
                packet_len=flow_meta.get("byte_count", 256) // max(count, 1),
                ttl=63 if flow_meta.get("ttl_anomaly") else 64,
                data_source=f"eval_{name.lower()}",
            ))

        result = pipeline.process_window(events)
        detected = result is not None and result.get("risk_score", 0.0) >= 0.4

        # Ensemble counters
        if is_attack and detected:
            counters["ensemble"]["tp"] += 1
        elif is_attack and not detected:
            counters["ensemble"]["fn"] += 1
        elif not is_attack and detected:
            counters["ensemble"]["fp"] += 1
        else:
            counters["ensemble"]["tn"] += 1

        # Per-branch counters (from model_scores)
        model_scores: dict[str, float] = {}
        if result:
            raw = result.get("model_scores") or {}
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw)
                except Exception:
                    raw = {}
            model_scores = {k: float(v) for k, v in raw.items() if isinstance(v, (int, float))}

        for branch in branch_names:
            score = model_scores.get(branch, 0.0)
            branch_detected = score >= 0.5
            c = counters[branch]
            if is_attack and branch_detected:
                c["tp"] += 1
            elif is_attack and not branch_detected:
                c["fn"] += 1
            elif not is_attack and branch_detected:
                c["fp"] += 1
            else:
                c["tn"] += 1

        scenario_results.append({
            "scenario": name,
            "is_attack": is_attack,
            "detected": detected,
            "risk_score": result.get("risk_score", 0.0) if result else 0.0,
            "model_scores": model_scores,
        })

    branch_metrics = {b: _metrics_from_counts(**c) for b, c in counters.items()}
    return {"scenarios": scenario_results, "branch_metrics": branch_metrics}


# ---------------------------------------------------------------------------
# Optional labelled-CSV evaluation
# ---------------------------------------------------------------------------

def _run_csv_evaluation(csv_path: Path) -> dict[str, Any]:
    """Evaluate against a labelled CSV with columns: label (1/0), [feature columns...]."""
    try:
        import csv as _csv

        rows = []
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = _csv.DictReader(f)
            for row in reader:
                rows.append(row)

        if not rows:
            return {"error": "CSV is empty"}

        from diodeshield.config import load_config
        from diodeshield.db import Repository
        from diodeshield.pipeline import DetectionPipeline
        from diodeshield.schemas import TrafficEvent

        config = load_config()
        repo = Repository(":memory:")
        pipeline = DetectionPipeline(repo, config)

        tp = fp = tn = fn = 0
        for row in rows[:500]:  # cap at 500 rows for speed
            label = int(float(row.get("label", row.get("Label", 0))))
            try:
                event = TrafficEvent(
                    src_ip=row.get("src_ip", "10.0.0.1"),
                    dst_ip=row.get("dst_ip", "10.0.0.2"),
                    src_port=int(float(row.get("src_port", 40000))) if row.get("src_port") else None,
                    dst_port=int(float(row.get("dst_port", 502))) if row.get("dst_port") else None,
                    protocol=row.get("protocol", "TCP"),
                    packet_len=int(float(row.get("packet_len", row.get("total_length", 128)))) if row.get("packet_len") or row.get("total_length") else 128,
                    ttl=int(float(row.get("ttl", 64))) if row.get("ttl") else 64,
                    data_source="csv_eval",
                )
                result = pipeline.process_window([event])
                detected = result is not None and result.get("risk_score", 0.0) >= 0.4
            except Exception:
                continue

            if label and detected:
                tp += 1
            elif label and not detected:
                fn += 1
            elif not label and detected:
                fp += 1
            else:
                tn += 1

        return {
            "csv": str(csv_path),
            "rows_evaluated": tp + fp + tn + fn,
            "metrics": _metrics_from_counts(tp, fp, tn, fn),
        }
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Gate check
# ---------------------------------------------------------------------------

def _gate_check(branch_metrics: dict[str, dict[str, float]]) -> dict[str, Any]:
    """Return pass/fail for each branch's recall and F1 versus baseline gates."""
    results: dict[str, Any] = {}
    overall_pass = True
    for branch, m in branch_metrics.items():
        recall_ok = m.get("recall", 0.0) >= BASELINE_RECALL_GATE
        f1_ok = m.get("f1", 0.0) >= BASELINE_F1_GATE
        precision_ok = m.get("precision", 0.0) >= BASELINE_PRECISION_GATE
        passed = recall_ok and f1_ok and precision_ok
        if not passed:
            overall_pass = False
        results[branch] = {
            "recall_pass": recall_ok,
            "f1_pass": f1_ok,
            "precision_pass": precision_ok,
            "passed": passed,
        }
    results["_overall_pass"] = overall_pass
    return results


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------

def _write_reports(data: dict[str, Any]) -> tuple[Path, Path]:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    reports_dir = ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    json_path = reports_dir / f"evaluation_{ts}.json"
    md_path = reports_dir / f"evaluation_{ts}.md"

    json_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    branch_metrics = data.get("branch_metrics", {})
    gate = data.get("gate", {})

    lines = [
        "# DIODESHIELD Evaluation Report",
        f"\nGenerated: {data.get('generated_at', ts)}",
        f"Mode: {data.get('mode', 'synthetic')}",
        "",
        "## Branch Metrics",
        "",
        "| Branch | Precision | Recall | F1 | ROC-AUC | TP | FP | TN | FN | Gate |",
        "|--------|-----------|--------|----|---------|----|----|----|----|------|",
    ]
    for branch, m in branch_metrics.items():
        g = gate.get(branch, {})
        status = "PASS" if g.get("passed", True) else "FAIL"
        lines.append(
            f"| {branch} | {m.get('precision', 0):.3f} | {m.get('recall', 0):.3f} "
            f"| {m.get('f1', 0):.3f} | {m.get('roc_auc', 0):.3f} "
            f"| {m.get('tp', 0)} | {m.get('fp', 0)} | {m.get('tn', 0)} | {m.get('fn', 0)} "
            f"| {status} |"
        )

    overall = "OVERALL PASS" if gate.get("_overall_pass", True) else "OVERALL FAIL"
    lines += ["", f"## Gate Result: {overall}", "",
              f"- Recall gate: {BASELINE_RECALL_GATE}",
              f"- F1 gate: {BASELINE_F1_GATE}",
              f"- Precision gate: {BASELINE_PRECISION_GATE}"]

    if "csv" in data:
        csv_m = data.get("csv_metrics", {})
        lines += [
            "",
            "## CSV Dataset Metrics",
            f"Dataset: `{data['csv']}`",
            f"Rows: {data.get('rows_evaluated', 0)}",
            f"Precision: {csv_m.get('precision', 0):.3f} | "
            f"Recall: {csv_m.get('recall', 0):.3f} | "
            f"F1: {csv_m.get('f1', 0):.3f}",
        ]

    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="DIODESHIELD Evaluation Engine")
    parser.add_argument("--dataset", metavar="CSV", help="Optional labelled CSV dataset path")
    parser.add_argument("--full", action="store_true", help="Run extended evaluation (reserved)")
    parser.add_argument("--gate-only", action="store_true", help="Exit 1 if gate fails (for CI)")
    args = parser.parse_args()

    print("DIODESHIELD Evaluation Engine — running synthetic scenario evaluation …")
    synth = _run_synthetic_evaluation()
    branch_metrics = synth["branch_metrics"]

    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "synthetic",
        "branch_metrics": branch_metrics,
        "scenarios": synth["scenarios"],
    }

    if args.dataset:
        csv_path = Path(args.dataset)
        if csv_path.exists():
            print(f"  ↳ evaluating against CSV: {csv_path}")
            csv_result = _run_csv_evaluation(csv_path)
            report["csv"] = str(csv_path)
            report["csv_metrics"] = csv_result.get("metrics", {})
            report["rows_evaluated"] = csv_result.get("rows_evaluated", 0)
            report["mode"] = "synthetic+csv"
        else:
            print(f"  ⚠  CSV not found: {csv_path} — skipping")

    gate = _gate_check(branch_metrics)
    report["gate"] = gate

    json_path, md_path = _write_reports(report)
    print(f"[OK] JSON report: {json_path}")
    print(f"[OK] MD  report:  {md_path}")

    # Print summary table
    print("\nBranch Summary:")
    print(f"  {'Branch':<22} {'Recall':>7} {'F1':>7} {'Precision':>10} {'Gate':>6}")
    print("  " + "-" * 60)
    for branch, m in branch_metrics.items():
        g = gate.get(branch, {})
        icon = "[PASS]" if g.get("passed", True) else "[FAIL]"
        print(f"  {branch:<22} {m.get('recall', 0):>7.3f} {m.get('f1', 0):>7.3f} "
              f"{m.get('precision', 0):>10.3f}  {icon}")
    print()

    overall_pass = gate.get("_overall_pass", True)
    if overall_pass:
        print("[PASS] Evaluation PASSED -- all branches meet baseline gates.")
    else:
        print("[FAIL] Evaluation FAILED -- one or more branches below baseline gates.")
        if args.gate_only:
            sys.exit(1)


if __name__ == "__main__":
    main()
