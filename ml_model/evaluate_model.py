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


# SECTION 1 - Confusion Matrix Deep Dive
print("=" * 60)
print("SECTION 1  CONFUSION MATRIX EXPLAINED (XGBoost, t=0.5)")
print("=" * 60)

xgb_pred = (xgb_proba >= 0.5).astype(int)
tn, fp, fn, tp = confusion_matrix(y_test, xgb_pred).ravel()
total = tn + fp + fn + tp

print(f"""
Predicted          LEGITIMATE      PHISHING
Actual LEGITIMATE  TN={tn:>7,}    FP={fp:>7,}
Actual PHISHING    FN={fn:>7,}    TP={tp:>7,}

What each cell means for your users:
  TN = {tn:,} ({tn/total*100:.1f}%)
       True Negatives  legitimate sites correctly allowed through.
       User browses normally with no interruption. 

  FP = {fp:,} ({fp/total*100:.1f}%)
       False Positives  legitimate sites wrongly blocked.
       User sees the warning page on a safe site. Annoying but
       not dangerous  they can click "continue anyway". 

  FN = {fn:,} ({fn/total*100:.1f}%)
       False Negatives  phishing sites that slipped through.
       User visits a phishing site with NO warning shown.
       This is the dangerous failure mode. 

  TP = {tp:,} ({tp/total*100:.1f}%)
       True Positives  phishing sites correctly blocked.
       User sees the full-screen warning. System working. 

Phishing catch rate:  {tp/(tp+fn)*100:.2f}%  ({tp:,} of {tp+fn:,} blocked)
False alarm rate:     {fp/(fp+tn)*100:.2f}%  ({fp:,} of {fp+tn:,} legitimate sites)
""")
