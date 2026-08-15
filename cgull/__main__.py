"""
Main entry point for running C-GULL as a module: python -m cgull
"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
