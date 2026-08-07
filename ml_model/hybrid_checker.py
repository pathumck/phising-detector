import os
import re
import sys
import json
import joblib
from urllib.parse import urlparse, parse_qs, unquote

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from domain_lists.blacklist import (check_blacklist,
                                     add_to_blacklist,
                                     initialise_blacklist,
                                     clean_against_whitelist)
from domain_lists.whitelist import (check_whitelist,
                                     initialise_whitelist,
                                     WHITELIST)
from domain_lists.lookalike_detector import check_lookalike
from feature_extractor import extract_features


# ML model globals
_MODEL_DIR   = os.path.join(_HERE, "models")
_model       = None
_scaler      = None
_uses_scaler = False
_model_name  = "unknown"