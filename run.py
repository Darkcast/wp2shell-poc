#!/usr/bin/env python3
"""Standalone launcher — equivalent to `python3 -m wp2shell`."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wp2shell.cli import main

if __name__ == "__main__":
    sys.exit(main())
