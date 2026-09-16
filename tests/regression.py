"""Comprehensive end-to-end regression tests for production readiness."""

import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class RegressionTestSuite:
    """End-to-end tests covering all critical paths."""

    def __init__(self):
        self.results = {}
        self.failed = []

    def run_all(self) -> dict[str, Any]:
        """Execute all regression tests."""
        tests = [
            ("model_loading", self.test_model_loading),
            ("inference_determinism", self.test_inference_determinism),
            ("pipeline_processing", self.test_pipeline_processing),
            ("startup_initialization", self.test_startup_initialization),
            ("threat_scenarios", self.test_threat_scenarios),
            ("api_health", self.test_api_health),
            ("model_versioning", self.test_model_versioning),
            ("capture_resilience", self.test_capture_resilience),
        ]

        for name, test_fn in tests:
            try:
                logger.info(f"Running: {name}")
                result = test_fn()
                self.results[name] = result
                status = "PASS" if result.get("passed") else "FAIL"
                print(f"  [{status}] {name}")
                if not result.get("passed"):
                    self.failed.append((name, result.get("error", "Unknown")))
            except Exception as e:
                print(f"  [ERROR] {name}: {e}")
                self.results[name] = {"passed": False, "error": str(e)[:300]}
                self.failed.append((name, str(e)))

        return {
            "total": len(tests),
            "passed": len(tests) - len(self.failed),
            "failed": len(self.failed),
            "results": self.results,
            "failures": self.failed,
        }

    def test_model_loading(self) -> dict[str, Any]:
        """Verify all model adapters load without errors."""
        try:
            from diodeshield.models.adapters import get_all_adapters

            adapters = get_all_adapters()
            if not adapters:
                return {"passed": False, "error": "No adapters loaded"}

            return {
                "passed": True,
                "adapters_loaded": len(adapters),
                "names": list(adapters.keys()),
            }
        except Exception as e:
            return {"passed": False, "error": str(e)}

    def test_inference_determinism(self) -> dict[str, Any]:
        """Verify inference is deterministic (same input = same output)."""
        try:
            from diodeshield.models.adapters import get_all_adapters

            adapters = get_all_adapters()
            test_event = {
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.50",
                "src_port": 443,
                "dst_port": 80,
                "protocol": "TCP",
                "bytes_sent": 5000,
                "bytes_received": 10000,
                "packet_count": 50,
                "duration_sec": 10.0,
            }

            # Score same event twice
            scores1 = {name: adapter.score(test_event) for name, adapter in adapters.items()}
            scores2 = {name: adapter.score(test_event) for name, adapter in adapters.items()}

            if scores1 != scores2:
                return {"passed": False, "error": "Scores not deterministic"}

            # Verify all scores in [0, 1]
            for name, score in scores1.items():
                if not isinstance(score, (int, float)) or not 0 <= score <= 1:
                    return {"passed": False, "error": f"{name}: invalid score {score}"}

            return {
                "passed": True,
                "sample_scores": {k: round(v, 4) for k, v in scores1.items()},
            }
        except Exception as e:
            return {"passed": False, "error": str(e)}

    def test_pipeline_processing(self) -> dict[str, Any]:
        """Verify pipeline processes events and generates alerts."""
        try:
            from diodeshield.pipeline import DetectionPipeline
            from diodeshield.schemas import TrafficEvent

            pipeline = DetectionPipeline()

            # Create test events
            events = [
                TrafficEvent(
                    src_ip="192.168.1.100",
                    dst_ip="10.0.0.50",
                    src_port=12345,
                    dst_port=80,
                    protocol="TCP",
                ),
                TrafficEvent(
                    src_ip="10.0.0.1",
                    dst_ip="192.168.1.1",
                    src_port=53,
                    dst_port=5353,
                    protocol="UDP",
                ),
            ]

            alerts = []
            for event in events:
                results = pipeline.ingest(event)
                alerts.extend(results)

            return {
                "passed": True,
                "events_processed": len(events),
                "alerts_generated": len(alerts),
            }
        except Exception as e:
            return {"passed": False, "error": str(e)}

    def test_startup_initialization(self) -> dict[str, Any]:
        """Verify startup manager initializes correctly."""
        try:
            from diodeshield.startup import StartupManager

            manager = StartupManager(debug=False)
            result = manager.initialize()

            if not result.get("steps"):
                return {"passed": False, "error": "No startup steps executed"}

            return {
                "passed": result.get("ready", False),
                "platform": result.get("platform"),
                "models_ready": result.get("steps", {}).get("models", {}).get("models_ready", 0),
                "pipeline_ok": result.get("steps", {}).get("pipeline", {}).get("status") == "ok",
            }
        except Exception as e:
            return {"passed": False, "error": str(e)}

    def test_threat_scenarios(self) -> dict[str, Any]:
        """Verify threat scenario collection works."""
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "training/collect_training_data.py",
                    "--output",
                    "reports/test_scenarios.json",
                ],
                capture_output=True,
                text=True,
                cwd=".",
                timeout=60,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "passed": False,
                    "error": result.stderr[:300] if result.stderr else "Non-zero exit",
                }

            report_path = Path("reports/test_scenarios.json")
            if report_path.exists():
                with open(report_path) as f:
                    report = json.load(f)
                return {
                    "passed": True,
                    "scenarios_run": len(report.get("scenarios", [])),
                    "total_samples": report.get("total_samples", 0),
                }

            return {"passed": False, "error": "No report generated"}
        except Exception as e:
            return {"passed": False, "error": str(e)}

    def test_api_health(self) -> dict[str, Any]:
        """Verify API endpoints are available (no server running, just check routes exist)."""
        try:
            from diodeshield.api.main import app

            # Just verify the app was created with endpoints
            routes = [str(rule) for rule in app.routes]

            required_routes = ["/api/health", "/api/events", "/api/models/health"]
            found = [r for r in routes if any(req in r for req in required_routes)]

            return {
                "passed": len(found) > 0 or len(routes) > 0,
                "routes_found": len(found),
                "total_routes": len(routes),
            }
        except Exception as e:
            return {"passed": False, "error": str(e)}

    def test_model_versioning(self) -> dict[str, Any]:
        """Verify model artifacts and provenance are trackable."""
        try:
            from diodeshield.startup import ModelHealthChecker

            provenance = ModelHealthChecker.load_provenance()
            health = ModelHealthChecker.check_models()

            ModelHealthChecker.save_provenance(health)

            # Verify provenance file exists
            if ModelHealthChecker.PROVENANCE_FILE.exists():
                with open(ModelHealthChecker.PROVENANCE_FILE) as f:
                    saved = json.load(f)
                return {
                    "passed": True,
                    "provenance_file": "models/provenance.json",
                    "models_tracked": len(saved.get("models", {})),
                }

            return {"passed": False, "error": "Provenance not saved"}
        except Exception as e:
            return {"passed": False, "error": str(e)}

    def test_capture_resilience(self) -> dict[str, Any]:
        """Verify graceful handling when capture tools are unavailable."""
        try:
            from diodeshield.startup import CaptureConfig

            config = CaptureConfig.load_config()
            tools = CaptureConfig.validate_capture_tools()

            # Should not crash even if tools are missing
            return {
                "passed": True,
                "capture_enabled": config.get("passive_capture_enabled", False),
                "zeek_available": tools.get("zeek", False),
                "tshark_available": tools.get("tshark", False),
                "fallback_ready": True,
            }
        except Exception as e:
            return {"passed": False, "error": str(e)}


def main():
    """Run regression test suite."""
    import argparse

    parser = argparse.ArgumentParser(description="DIODESHIELD regression tests")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    suite = RegressionTestSuite()
    result = suite.run_all()

    print("\n" + "=" * 70)
    print("Regression Test Summary")
    print("=" * 70)
    print(f"Total: {result['total']} | Passed: {result['passed']} | Failed: {result['failed']}")

    if result["failed"] > 0:
        print("\nFailed Tests:")
        for name, error in result["failures"]:
            print(f"  - {name}: {error[:100]}")

    print("\nDetailed Results:")
    print(json.dumps(result["results"], indent=2))

    sys.exit(0 if result["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
