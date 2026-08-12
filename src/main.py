"""
Main Application Entry Point
Orchestrates all system components
"""

import logging
import sys
from pathlib import Path

import uvicorn

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.api.app import app
from src.config import Config

# Configure logging. The log directory is created here rather than assumed to
# exist, so importing this module never fails on a fresh clone or in a container
# whose volume has not been mounted yet.
LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "application.log"),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger(__name__)


def main():
    """Main application entry point"""
    logger.info("=" * 80)
    logger.info("WALMART NETWORK SECURITY AUTOMATION AI - STARTING")
    logger.info("=" * 80)

    try:
        # Load configuration
        config = Config()

        # Start FastAPI server
        logger.info("Starting FastAPI server...")
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

    except KeyboardInterrupt:
        logger.info("Shutting down gracefully...")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
