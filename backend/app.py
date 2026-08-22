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
import verdict_store
from domain_lists.blacklist import (
    BLACKLIST,
    remove_from_blacklist,
    reload_blacklist,
    get_blacklist_domains,
    count_blacklist_by_source,
)
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
    """Returns API and loaded model status. Also used by the cloud
    platform's load balancer to confirm this instance is ready to
    receive traffic before routing requests to it."""
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

    # Persist to verdict_log for analytics/evaluation. Errors are
    # never allowed to affect the response returned to the caller
    if not result.get("error"):
        try:
            verdict_store.log_verdict(url, result, elapsed_ms)
        except Exception as e:
            print(f"[app] WARNING: verdict logging failed: {e}")

    return jsonify(result), 200


# ---- Admin endpoints: manage the runtime-learned blacklist ----

@app.route("/blacklist", methods=["GET"])
def list_blacklist():
    """Returns blacklist domains, optionally filtered by source, plus a

    per-source breakdown count.

    Query params:
      source - optional, e.g. "ml_auto_learned" or "phishtank". Restricts
               both the returned sample and its size to that source.
      limit  - optional, default 50, max rows returned in `domains`.

    `by_source` always reflects the FULL table regardless of the source
    filter, so the dashboard can show e.g. "47 self-learned / 11,842 total"
    even while only listing the 47 self-learned ones.
    """
    source = request.args.get("source")
    limit = request.args.get("limit", default=50, type=int)
    limit = max(1, min(limit, 500))

    domains = get_blacklist_domains(source=source, limit=limit)
    by_source = count_blacklist_by_source()

    return jsonify({
        "total_domains": len(BLACKLIST),
        "by_source": by_source,
        "source_filter": source,
        "domains": domains,
    }), 200


@app.route("/blacklist/<domain>", methods=["DELETE"])
def delete_blacklist_domain(domain):
    """Removes a domain from both the in-memory BLACKLIST set and the
    database in one step, so the removal takes effect immediately
    without restarting the server.
    """
    removed = remove_from_blacklist(domain)
    return jsonify({
        "domain": domain.lower().strip(),
        "removed": removed,
    }), (200 if removed else 404)


@app.route("/blacklist/reload", methods=["POST"])
def reload_blacklist_route():
    """Forces a full reload of the in-memory BLACKLIST set from the database.

    Use this after making direct database edits (e.g. via SQLTools/sqlite3 CLI)
    to sync the running server without a restart.

    NOTE: on a multi-instance cloud deployment, this only reloads the instance
    that handled this specific request - the load balancer may route it to any
    one of them. Call this once per instance (or hit it repeatedly) if running
    more than one instance, until a shared cache (e.g. Redis) replaces the
    in-memory set.
    """
    total = reload_blacklist()
    return jsonify({
        "status": "reloaded",
        "total_domains": total,
    }), 200


# ---- User override endpoints ----

@app.route("/override", methods=["POST"])
def record_override():
    """Records that a user dismissed a warning and proceeded to a URL anyway.

    Called by the extension's "proceed anyway" button. Body: {"url": "...",
    "tab_id": "..."}  (tab_id optional)
    """
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Request body must be JSON with a 'url' field."}), 400

    url = _normalise_input_url(data.get("url", ""))
    if not url:
        return jsonify({"error": "empty url"}), 400

    tab_id = data.get("tab_id")
    override_id = verdict_store.record_override(url, tab_id)

    return jsonify({
        "status": "recorded",
        "override_id": override_id,
        "url": url,
        "tab_id": tab_id,
    }), 201


@app.route("/override/check", methods=["GET"])
def check_override():
    """Returns whether this URL has already been overridden recently, so the
    extension can skip re-warning on a page the user already chose to proceed
    through this session.

    Query params: url (required), tab_id (optional)
    """
    raw_url = request.args.get("url", "")
    url = _normalise_input_url(raw_url)
    if not url:
        return jsonify({"error": "missing 'url' query param"}), 400

    tab_id = request.args.get("tab_id")
    already_overridden = verdict_store.check_override(url, tab_id)

    return jsonify({
        "url": url,
        "tab_id": tab_id,
        "already_overridden": already_overridden,
        "suppression_window_hours": verdict_store.OVERRIDE_SUPPRESSION_HOURS,
    }), 200


@app.route("/overrides", methods=["GET"])
def list_overrides():
    """Returns a raw, newest-first feed of individual override events, each

    annotated with the verdict/layer/confidence the user bypassed.

    This is distinct from /stats' `frequently_overridden_domains`, which is
    aggregated by domain (2+ overrides only). This endpoint returns every
    override event, including one-offs, which is what a live demo table
    wants to show as it happens.

    Query params: limit - optional, default 50, max 500.
    """
    limit = request.args.get("limit", default=50, type=int)
    limit = max(1, min(limit, 500))

    overrides = verdict_store.get_all_overrides(limit=limit)
    return jsonify({
        "count": len(overrides),
        "overrides": overrides,
    }), 200


# ---- Verdict log endpoint ----

@app.route("/verdicts", methods=["GET"])
def list_verdicts():
    """Returns a paginated, newest-first feed of verdict_log rows, optionally

    filtered to a single detection layer.

    Unlike /stats' `recent` (hardcoded to the last 20, unfiltered), this
    supports a larger page size and a layer filter, e.g.
    /verdicts?layer=ml_model&limit=100 to show only what the ML layer has
    caught during a demo.

    Query params:
      limit - optional, default 50, max 500.
      layer - optional, restricts to one detection_layer value
              (e.g. "blacklist", "whitelist", "lookalike_typosquatting",
              "ml_model").
    """
    limit = request.args.get("limit", default=50, type=int)
    limit = max(1, min(limit, 500))
    layer = request.args.get("layer")

    verdicts = verdict_store.get_recent_verdicts(limit=limit, layer=layer)
    return jsonify({
        "count": len(verdicts),
        "layer_filter": layer,
        "verdicts": verdicts,
    }), 200


# ---- Stats / evaluation endpoint ----

@app.route("/stats", methods=["GET"])
def stats():
    """Aggregated verdict_log + user_overrides stats for the admin dashboard and
    project evaluation chapter: per-layer trigger counts, verdict split,

    average latency, and domains that keep getting overridden (candidate false
    positives).
    """
    verdict_stats = verdict_store.get_verdict_stats()
    overridden = verdict_store.get_most_overridden_domains()

    return jsonify({
        **verdict_stats,
        "frequently_overridden_domains": overridden,
    }), 200


# Define 404 error handler
@app.errorhandler(404)
def not_found(_e):
    return jsonify({"error": "Not found. Use POST /predict or GET /health."}), 404


# Define 500 error handler
@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": f"Internal server error: {str(e)}"}), 500


# Execute application server entry point.
# In production, Gunicorn reads $PORT and starts the app
# directly - this __main__ block only runs during local development,
# but it reads PORT from the environment too so local behaviour matches
# how the app will be started in the cloud.
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)