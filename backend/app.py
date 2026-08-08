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


# Define route for system health check
@app.route("/health", methods=["GET"])
def health():
    """Returns API and loaded model status."""
    return jsonify({
        "status": "ok",
        "model_loaded": hybrid_checker._model is not None,
        "model_name": hybrid_checker._model_name,
        "uses_scaler": hybrid_checker._uses_scaler,
        "blacklist_domains": len(BLACKLIST),
        "whitelist_domains": len(WHITELIST),
    }), 200


# Define route for URL prediction and analysis
@app.route("/predict", methods=["POST"])
def predict():
    """Runs url evaluation and returns verdict JSON."""
    start = time.perf_counter()

    # Extract and validate payload presence
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({
            "verdict": "error",
            "is_phishing": False,
            "confidence": 0.0,
            "detection_layer": "none",
            "explanation": "Request body must be JSON with a 'url' field.",
            "ml_score": None,
            "domain": "",
            "error": "missing 'url' field",
        }), 400

    # Extract and normalize the target URL
    raw_url = data.get("url", "")
    url = _normalise_input_url(raw_url)

    # Validate non-empty URL string
    if not url:
        return jsonify({
            "verdict": "error",
            "is_phishing": False,
            "confidence": 0.0,
            "detection_layer": "none",
            "explanation": "Empty URL received.",
            "ml_score": None,
            "domain": "",
            "error": "empty url",
        }), 400

    # Execute URL inspection cascade
    result = hybrid_checker.check_url(url)

    # Calculate execution duration and attach metadata
    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    result["response_time_ms"] = elapsed_ms

    return jsonify(result), 200


# Define 404 error handler
@app.errorhandler(404)
def not_found(_e):
    return jsonify({"error": "Not found. Use POST /predict or GET /health."}), 404


# Define 500 error handler
@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": f"Internal server error: {str(e)}"}), 500


# Execute application server entry point
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
