"""
Layer 1 of the hybrid detection system.
Sources loaded at startup into one unified Python set:
  Source 1: PhishTank CSV (static file)
  Source 2: blacklist.txt (runtime learning)
"""

import re
import os
import csv
from urllib.parse import urlparse

# The unified blacklist - all sources merged here at startup
BLACKLIST: set[str] = set()

_HERE           = os.path.dirname(os.path.abspath(__file__))
_PHISHTANK_PATH = os.path.join(_HERE, "phishtank.csv")
_RUNTIME_PATH   = os.path.join(_HERE, "blacklist.txt")