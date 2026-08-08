"""
Flask Backend API
Exposes the detection cascade (hybrid_checker.check_url)
"""

import os
import sys
import time


from flask import Flask, request, jsonify
from flask_cors import CORS

# Import local detection module and domain resources
import hybrid_checker
from domain_lists.blacklist import BLACKLIST
from domain_lists.whitelist import WHITELIST

# Configure module search path for local backend imports
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Initialize Flask application instance
app = Flask(__name__)

# Configure Cross-Origin Resource Sharing
CORS(app, resources={r"/*": {"origins": "*"}})


# Define helper function for URL normalization
def _normalise_input_url(raw_url: str) -> str:
    """Prepend default HTTP scheme if omitted."""
    raw_url = (raw_url or "").strip()
    if raw_url and not raw_url.startswith(("http://", "https://")):
        raw_url = "http://" + raw_url
    return raw_url
