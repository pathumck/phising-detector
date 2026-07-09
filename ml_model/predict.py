"""
predict.py
==========
Interactive command-line tool to classify a given URL as legitimate or phishing
using a trained machine learning model.
"""

import joblib
from feature_extractor import extract_features, FEATURE_NAMES

# Load the trained classification model and feature scaler
model  = joblib.load("models/phishing_model.pkl")
scaler = joblib.load("models/scaler.pkl")

# Load configuration metadata to determine scaling requirements
with open("models/model_metadata.json") as f:
    import json
    meta = json.load(f)

uses_scaler   = meta["uses_scaler"]
selected_name = meta["selected_model"]

# Display interface header
print("=" * 55)
print(f"   Phishing URL Predictor  {selected_name}")
print("=" * 55)
print("Type a URL and press Enter. Type 'quit' to exit.\n")

# Start interactive prediction loop
while True:
    url = input("URL> ").strip()
    if url.lower() in ("quit", "exit", "q"):
        break
    if not url:
        continue

    # Extract numerical features from the raw URL string
    features = extract_features(url)

    # Standardize features if required by the loaded model architecture
    if uses_scaler:
        import numpy as np
        features_input = scaler.transform([features])
    else:
        features_input = [features]

    # Run inference and calculate classification metrics
    proba     = model.predict_proba(features_input)[0][1]
    verdict   = "PHISHING" if proba > 0.5 else "LEGITIMATE"
    confidence = proba if verdict == "PHISHING" else 1 - proba

    # Display prediction verdict and confidence scores
    print(f"\n   URL:        {url}")
    print(f"   Verdict:    {verdict}")
    print(f"   Confidence: {confidence*100:.1f}%")
    print(f"   Raw phishing probability: {proba:.4f}")
    
    # List all extracted features that have non-zero values for this URL
    print(f"\n   Top contributing features:")
    for name, val in zip(FEATURE_NAMES, features):
        if val != 0:
            print(f"    {name:<25} = {val}")
    print()