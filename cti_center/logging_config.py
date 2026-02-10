"""Centralized logging configuration for CTI-Center."""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_FILE = LOG_DIR / "cti_center.log"
LOG_FORMAT = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"


def setup_logging() -> None:
    """Configure the ``cti_center`` logger with file and console handlers.

    - **RotatingFileHandler** writes DEBUG-level output to ``logs/cti_center.log``
      (5 MB max, 3 backups).
    - **StreamHandler** writes INFO-level output to stderr.

    Safe to call multiple times; handlers are only added once.
    """
    LOG_DIR.mkdir(exist_ok=True)

    logger = logging.getLogger("cti_center")

    if logger.handlers:
        return

    logger.setLevel(logging.DEBUG)

    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
