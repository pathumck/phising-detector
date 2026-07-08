"""
Generates a comprehensive evaluation report on the held-out
test set. Covers:
  - Threshold analysis at 0.3, 0.4, 0.5, 0.6, 0.7
  - Full confusion matrix with plain English explanation
  - Per-class precision and recall breakdown
  - What the errors actually look like (sample FP and FN URLs)
"""

import json
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
    classification_report
)
from feature_extractor import FEATURE_NAMES


# Load saved models and data
print("Loading models and data...")

xgb       = joblib.load("models/xgb_model.pkl")
lr        = joblib.load("models/lr_model.pkl")
scaler    = joblib.load("models/scaler.pkl")

with open("models/model_metadata.json") as f:
    meta = json.load(f)

X = pd.read_csv("dataset/features_X.csv")
y = pd.read_csv("dataset/labels_y.csv").squeeze()

# Recreate the exact same test split used in training
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Load clean URLs so we can show example FP/FN URLs
clean_df = pd.read_csv("dataset/clean_urls.csv")
_, urls_test = train_test_split(
    clean_df, test_size=0.2, random_state=42, stratify=y
)
urls_test = urls_test.reset_index(drop=True)

X_test_scaled = scaler.transform(X_test)
X_test = X_test.reset_index(drop=True)

# Get probabilities from both models
xgb_proba = xgb.predict_proba(X_test)[:, 1]
lr_proba  = lr.predict_proba(X_test_scaled)[:, 1]

print("Done.\n")