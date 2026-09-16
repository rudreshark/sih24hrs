"""Main application entry point with cross-platform startup."""

import logging
import sys

from diodeshield.startup import StartupManager

logger = logging.getLogger(__name__)


def run_app(config_path=None, debug=False):
    """Initialize and run DIODESHIELD application."""
    manager = StartupManager(config_path=config_path, debug=debug)
    startup_result = manager.initialize()

    if not startup_result.get("ready"):
        logger.error("Startup failed; check logs above")
        return 1

    if manager.pipeline:
        logger.info("DIODESHIELD is ready. Processing events...")
        # Note: Actual event processing would run in a separate thread/loop
        # For this implementation, we just confirm the pipeline is initialized

    return 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="DIODESHIELD Security Operations Center")
    parser.add_argument("--config", help="Path to configuration JSON")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    sys.exit(run_app(config_path=args.config, debug=args.debug))
