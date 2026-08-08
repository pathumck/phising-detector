"""
Flask Backend API
Exposes the detection cascade (hybrid_checker.check_url)
"""

import os
import sys
import time


from flask import Flask, request, jsonify
from flask_cors import CORS


# Configure module search path for local backend imports
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Initialize Flask application instance
app = Flask(__name__)

# Configure Cross-Origin Resource Sharing
CORS(app, resources={r"/*": {"origins": "*"}})

