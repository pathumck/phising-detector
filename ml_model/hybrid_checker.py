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


def _load_model() -> None:
    """Load production model, scaler, and metadata from disk."""
    global _model, _scaler, _uses_scaler, _model_name

    model_path  = os.path.join(_MODEL_DIR, "phishing_model.pkl")
    scaler_path = os.path.join(_MODEL_DIR, "scaler.pkl")
    meta_path   = os.path.join(_MODEL_DIR, "model_metadata.json")

    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Model not found: {model_path}\n"
            f"Run ml_model/train_model.py first."
        )

    _model = joblib.load(model_path)

    if os.path.exists(meta_path):
        with open(meta_path, "r") as f:
            meta = json.load(f)
        _uses_scaler = meta.get("uses_scaler", False)
        _model_name  = meta.get("selected_model", "unknown")

    if _uses_scaler and os.path.exists(scaler_path):
        _scaler = joblib.load(scaler_path)

    print(f"[hybrid] Model: {_model_name}  "
          f"| Scaler: {'yes' if _uses_scaler else 'no'}")


# Initialisation guard
_initialised = False


def _initialise() -> None:
    """Full system startup — runs exactly once at module import."""
    global _initialised
    if _initialised:
        return
    _initialised = True

    print("\n[hybrid] ── Starting detection system ──")
    initialise_whitelist()
    initialise_blacklist()
    clean_against_whitelist(WHITELIST)
    _load_model()
    print("[hybrid] ── All layers ready ──\n")


_initialise()