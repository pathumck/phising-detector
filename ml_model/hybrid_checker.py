"""
Master orchestrator for the four-layer cascade detection system.

Single public function: check_url(url) → dict

Four-layer cascade — strict order, stops at first verdict:
  Layer 1  Blacklist         confidence 1.00
  Layer 2  Whitelist         confidence 0.99 (With Open-Redirect Inspection)
  Layer 3  Lookalike         
           Homograph         confidence 0.95
           TLD swap          confidence 0.92
           Typosquatting     confidence 0.92 / 0.75
  Layer 4  ML Model          confidence = model probability
           Auto-learn: probability > 0.95 → add to blacklist
"""


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


# Helper Functions: URL Normalization & Open Redirect Extractor
_TRAILING_FQDN_DOT_RE = re.compile(r'\.(?=[/?#]|$)')


def _normalize_url_and_host(raw_url: str):
    """
    Decodes, normalizes, and extracts the target hostname safely.
    Handles userinfo (@), port numbers, and FQDN trailing dots.
    """
    raw_url = str(raw_url).strip()
    if not raw_url:
        return "", ""

    if not raw_url.startswith(("http://", "https://")):
        raw_url = "http://" + raw_url

    # Iterative unquoting to handle double/triple percent encoding tricks
    decoded_url = raw_url
    for _ in range(3):
        new_url = unquote(decoded_url)
        if new_url == decoded_url:
            break
        decoded_url = new_url

    decoded_url = _TRAILING_FQDN_DOT_RE.sub("", decoded_url, count=1)
    parsed = urlparse(decoded_url)
    host = (parsed.hostname or "").rstrip(".").lower()

    return decoded_url, host


def _check_open_redirect_or_social_media(url: str, current_host: str, depth: int = 0) -> dict | None:
    """
    Inspects queries on whitelisted domains to check if they act as open redirectors.
    Includes depth tracking to prevent infinite recursion on circular redirects.
    """
    if depth > 2:
        return None

    REDIRECT_PARAMS = {
        "q", "url", "u", "target", "dest", "destination", 
        "redirect", "redirect_url", "link", "out", "next", "continue"
    }

    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    for param, values in query_params.items():
        if param.lower() in REDIRECT_PARAMS:
            for val in values:
                val = unquote(val).strip()
                if val.startswith(("http://", "https://", "www.")):
                    _, inner_host = _normalize_url_and_host(val)
                    
                    # Ensure redirect target isn't internal or a direct sub-domain of current host
                    if inner_host and not inner_host.endswith(current_host):
                        # Recursive check on wrapped URL passing incremented depth
                        inner_res = check_url(val, depth=depth + 1)
                        
                        # If wrapped target is malicious, flag immediately
                        if inner_res["is_phishing"]:
                            inner_res["explanation"] = (
                                f"Open Redirect Attack via '{current_host}': "
                                f"Redirects to malicious target -> {inner_res['explanation']}"
                            )
                            inner_res["detection_layer"] = f"open_redirect_{inner_res['detection_layer']}"
                            return inner_res
                        
                        # If target is not safe/whitelisted, strip the whitelist wrapper safety 
                        # and return the inner target's evaluation result directly
                        if inner_res["detection_layer"] != "whitelist":
                            return inner_res

    return None


def check_url(url: str, depth: int = 0) -> dict:
    """
    Run the four-layer cascade on a single URL.

    Parameters
    ----------
    url : str
        Raw URL from Chrome extension, social media link, or test script.
    depth : int
        Internal recursion tracker for open redirect unwrapping.

    Returns
    -------
    dict
        Standard output format across all layers.
    """
    response = {
        "verdict": "safe",
        "is_phishing": False,
        "confidence": 0.0,
        "detection_layer": "none",
        "explanation": "",
        "ml_score": None,
        "domain": "",
        "error": None,
    }

    try:
        normalized_url, host = _normalize_url_and_host(url)
        if not normalized_url or not host:
            response["error"] = "Empty or unparseable URL received"
            return response

        response["domain"] = host

        # Layer 1: Blacklist
        result = check_blacklist(normalized_url)
        if result:
            response.update(result)
            return response

        # Layer 2: Whitelist and Open Redirect Inspection
        result = check_whitelist(normalized_url)
        if result:
            redirect_result = _check_open_redirect_or_social_media(normalized_url, host, depth=depth)
            if redirect_result:
                return redirect_result

            response.update(result)
            return response

        # Layer 3: Lookalike Detection
        result = check_lookalike(normalized_url)
        if result:
            response.update(result)
            return response

        # Layer 4: Machine Learning Model
        features = extract_features(normalized_url)

        features_input = (
            _scaler.transform([features])
            if _uses_scaler and _scaler is not None
            else [features]
        )

        proba = float(_model.predict_proba(features_input)[0][1])
        response["ml_score"] = round(proba, 4)

        if proba > 0.5:
            response.update({
                "verdict": "phishing",
                "is_phishing": True,
                "confidence": round(proba, 4),
                "detection_layer": "ml_model",
                "explanation": (
                    f"Machine learning model classified this URL "
                    f"as phishing with {proba * 100:.1f}% probability "
                    f"based on structural and lexical features."
                ),
            })
            
            SHARED_HOSTS = {"github.io", "wordpress.com", "vercel.app", "netlify.app", "firebaseapp.com"}
            if proba > 0.95 and host not in SHARED_HOSTS:
                add_to_blacklist(host)
        else:
            response.update({
                "verdict": "safe",
                "is_phishing": False,
                "confidence": round(1 - proba, 4),
                "detection_layer": "ml_model",
                "explanation": (
                    f"URL appears legitimate based on structural "
                    f"analysis ({(1 - proba) * 100:.1f}% confidence)."
                ),
            })

        return response

    except Exception as e:
        response["error"] = str(e)
        response["explanation"] = f"Detection error: {str(e)}"
        return response