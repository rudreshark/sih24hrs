"""Cross-platform startup, configuration, and model health initialization."""

import json
import logging
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from diodeshield.models.adapters import get_all_adapters
from diodeshield.pipeline import DetectionPipeline

logger = logging.getLogger(__name__)


class ModelHealthChecker:
    """Validate model artifacts, versions, and training provenance."""

    ARTIFACT_DIR = Path(__file__).parent.parent / "models"
    PROVENANCE_FILE = ARTIFACT_DIR / "provenance.json"

    @staticmethod
    def load_provenance() -> dict[str, Any]:
        """Load or create model provenance metadata."""
        if ModelHealthChecker.PROVENANCE_FILE.exists():
            try:
                with open(ModelHealthChecker.PROVENANCE_FILE) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Failed to load provenance: {e}")
                return {}
        return {
            "initialized_at": datetime.now(timezone.utc).isoformat(),
            "models": {},
            "status": "uninitialized",
        }

    @staticmethod
    def check_models() -> dict[str, Any]:
        """Verify all model adapters are loadable and return health status."""
        adapters = get_all_adapters()
        provenance = ModelHealthChecker.load_provenance()
        status = {}

        for name, adapter in adapters.items():
            try:
                # Test inference with dummy event
                dummy_event = {
                    "src_ip": "192.168.1.1",
                    "dst_ip": "10.0.0.1",
                    "src_port": 12345,
                    "dst_port": 80,
                    "protocol": "TCP",
                    "bytes_sent": 1024,
                    "bytes_received": 2048,
                    "packet_count": 100,
                    "duration_sec": 5.0,
                }
                score = adapter.score(dummy_event)
                if not isinstance(score, (int, float)) or not 0 <= score <= 1:
                    raise ValueError(f"Invalid score: {score}")

                status[name] = {
                    "ready": True,
                    "score_ok": True,
                    "type": adapter.__class__.__name__,
                    "tested_at": datetime.now(timezone.utc).isoformat(),
                }
            except (ValueError, AttributeError, TypeError) as e:
                logger.warning(f"Model {name} health check failed: {e}")
                status[name] = {
                    "ready": False,
                    "error": str(e)[:200],
                    "type": adapter.__class__.__name__,
                    "tested_at": datetime.now(timezone.utc).isoformat(),
                }

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": platform.system(),
            "python_version": platform.python_version(),
            "models": status,
            "all_ready": all(m.get("ready", False) for m in status.values()),
            "provenance": provenance.get("models", {}),
        }

    @staticmethod
    def save_provenance(health: dict[str, Any]) -> None:
        """Persist model health and provenance."""
        provenance = ModelHealthChecker.load_provenance()
        provenance["last_checked"] = datetime.now(timezone.utc).isoformat()
        provenance["models"] = health.get("models", {})
        provenance["platform"] = health.get("platform")

        ModelHealthChecker.ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
        try:
            with open(ModelHealthChecker.PROVENANCE_FILE, "w") as f:
                json.dump(provenance, f, indent=2)
            logger.info(f"Provenance saved to {ModelHealthChecker.PROVENANCE_FILE}")
        except OSError as e:
            logger.error(f"Failed to save provenance: {e}")


class CaptureConfig:
    """Load and validate passive capture configuration."""

    @staticmethod
    def load_config(config_path: str | None = None) -> dict[str, Any]:
        """Load capture configuration from file or environment."""
        if config_path and Path(config_path).exists():
            try:
                with open(config_path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")

        # Default to environment-based config
        return {
            "passive_capture_enabled": os.getenv("DIODESHIELD_CAPTURE", "true").lower() == "true",
            "capture_interface": os.getenv("DIODESHIELD_INTERFACE", "any" if platform.system() != "Windows" else ""),
            "packet_filter": os.getenv("DIODESHIELD_FILTER", "tcp or udp"),
            "snapshot_length": int(os.getenv("DIODESHIELD_SNAPLEN", "65535")),
            "zeek_enabled": os.getenv("DIODESHIELD_ZEEK", "false").lower() == "true",
            "tshark_enabled": os.getenv("DIODESHIELD_TSHARK", "false").lower() == "true",
            "dashboard_port": int(os.getenv("DIODESHIELD_DASHBOARD_PORT", "8080")),
            "api_port": int(os.getenv("DIODESHIELD_API_PORT", "5000")),
            "max_events_buffer": int(os.getenv("DIODESHIELD_BUFFER_SIZE", "10000")),
        }

    @staticmethod
    def validate_capture_tools() -> dict[str, bool]:
        """Check availability of optional capture tools (Zeek, tshark)."""
        tools_available = {}

        # Check Zeek
        try:
            result = subprocess.run(
                ["zeek", "--version"],
                capture_output=True,
                timeout=5,
                check=False,
            )
            tools_available["zeek"] = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            tools_available["zeek"] = False

        # Check tshark
        try:
            result = subprocess.run(
                ["tshark", "--version"],
                capture_output=True,
                timeout=5,
                check=False,
            )
            tools_available["tshark"] = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            tools_available["tshark"] = False

        return tools_available


class StartupManager:
    """Orchestrate initialization and validation on startup."""

    def __init__(self, config_path: str | None = None, debug: bool = False):
        self.debug = debug
        self.log_level = logging.DEBUG if debug else logging.INFO
        self._setup_logging()

        self.config = CaptureConfig.load_config(config_path)
        self.health = {}
        self.pipeline: DetectionPipeline | None = None

    def _setup_logging(self) -> None:
        """Configure logging for startup and runtime."""
        logging.basicConfig(
            level=self.log_level,
            format="[%(asctime)s] %(name)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def initialize(self) -> dict[str, Any]:
        """Full startup sequence: models, capture, pipeline, health check."""
        startup_result = {
            "timestamp": datetime.utcnow().isoformat(),
            "platform": platform.system(),
            "python_version": platform.python_version(),
            "steps": {},
        }

        # Step 1: Check model health
        logger.info("Checking model health...")
        try:
            self.health = ModelHealthChecker.check_models()
            ModelHealthChecker.save_provenance(self.health)
            startup_result["steps"]["models"] = {
                "status": "ok" if self.health.get("all_ready") else "degraded",
                "models_ready": sum(1 for m in self.health.get("models", {}).values() if m.get("ready")),
                "models_total": len(self.health.get("models", {})),
            }
            logger.info(f"Models: {startup_result['steps']['models']}")
        except Exception as e:
            logger.error(f"Model health check failed: {e}")
            startup_result["steps"]["models"] = {"status": "error", "error": str(e)[:200]}

        # Step 2: Check capture tools
        logger.info("Checking capture tools...")
        try:
            tools = CaptureConfig.validate_capture_tools()
            startup_result["steps"]["capture_tools"] = {
                "status": "ok",
                "tools": tools,
            }
            if self.config.get("passive_capture_enabled"):
                if not (tools.get("zeek") or tools.get("tshark")):
                    logger.warning("Passive capture enabled but no tools available; will use fallback")
            logger.info(f"Capture tools: {tools}")
        except Exception as e:
            logger.warning(f"Capture tool check failed: {e}")
            startup_result["steps"]["capture_tools"] = {"status": "ok"}

        # Step 3: Initialize pipeline
        logger.info("Initializing pipeline...")
        try:
            self.pipeline = DetectionPipeline()
            startup_result["steps"]["pipeline"] = {
                "status": "ok",
                "ready": True,
            }
            logger.info("Pipeline initialized")
        except Exception as e:
            logger.error(f"Pipeline initialization failed: {e}")
            startup_result["steps"]["pipeline"] = {"status": "error", "error": str(e)[:200]}

        # Step 4: Configuration summary
        startup_result["config"] = {
            "passive_capture": self.config.get("passive_capture_enabled", False),
            "dashboard_port": self.config.get("dashboard_port", 8080),
            "api_port": self.config.get("api_port", 5000),
            "buffer_size": self.config.get("max_events_buffer", 10000),
        }

        startup_result["ready"] = all(
            step.get("status") in ("ok", "degraded") for step in startup_result.get("steps", {}).values()
        )

        if startup_result["ready"]:
            logger.info("✓ DIODESHIELD startup complete and ready")
        else:
            logger.warning("⚠ DIODESHIELD startup completed with errors")

        return startup_result


def main():
    """CLI entry point for startup validation."""
    import argparse

    parser = argparse.ArgumentParser(description="DIODESHIELD startup and health check")
    parser.add_argument("--config", help="Path to configuration JSON")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--check-only", action="store_true", help="Check health only, do not initialize")

    args = parser.parse_args()

    if args.check_only:
        health = ModelHealthChecker.check_models()
        print(json.dumps(health, indent=2))
    else:
        manager = StartupManager(config_path=args.config, debug=args.debug)
        result = manager.initialize()
        print(json.dumps(result, indent=2))
        sys.exit(0 if result.get("ready") else 1)


if __name__ == "__main__":
    main()
