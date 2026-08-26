"""
Main entry point for running C-GULL as a module: python -m cgull
"""

import sys
import logging
from .cli import main

logger = logging.getLogger(__name__)


if __name__ == "__main__":
    sys.exit(main())
