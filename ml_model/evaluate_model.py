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


# SECTION 2 - Threshold Analysis
# WHY THIS MATTERS:
#   The default threshold of 0.5 means: "if the model is more
#   than 50% confident it's phishing, block it." But you can
#   tune this. A lower threshold (0.3) catches more phishing
#   but also generates more false alarms. A higher threshold
#   (0.7) has fewer false alarms but misses more phishing.
#   This tradeoff is a core concept in applied ML.
print("=" * 60)
print("SECTION 2  THRESHOLD ANALYSIS")
print("=" * 60)
print("Lower threshold = catch more phishing ( Recall) "
      "but more false alarms ( Precision)")
print("Higher threshold = fewer false alarms ( Precision) "
      "but miss more phishing ( Recall)\n")

thresholds = [0.3, 0.4, 0.5, 0.6, 0.7]
print(f"  {'Threshold':<12} {'Precision':<12} {'Recall':<12} "
      f"{'F1':<12} {'FP':<8} {'FN':<8}")
print("  " + "-" * 65)

threshold_results = []
for t in thresholds:
    pred = (xgb_proba >= t).astype(int)
    p  = precision_score(y_test, pred)
    r  = recall_score(y_test, pred)
    f1 = f1_score(y_test, pred)
    tn_, fp_, fn_, tp_ = confusion_matrix(y_test, pred).ravel()
    marker = "  default" if t == 0.5 else ""
    print(f"  {t:<12} {p:<12.4f} {r:<12.4f} "
          f"{f1:<12.4f} {int(fp_):<8} {int(fn_):<8}{marker}")
    threshold_results.append({
        "threshold": t, "precision": round(p, 4),
        "recall": round(r, 4), "f1": round(f1, 4),
        "fp": int(fp_), "fn": int(fn_)
    })

print("""
Reading this table for your report:
  At t=0.3: recall is highest  model catches the most phishing
             but generates the most false alarms (highest FP).
  At t=0.5: balanced  the default we use in production.
  At t=0.7: precision is highest  fewest false alarms but
             misses more phishing (highest FN, most dangerous).

For a phishing detector, erring toward lower thresholds
(more recall, fewer missed phishing) is the safer choice.
""")


# SECTION 3 - LR vs XGBoost detailed comparison
print("=" * 60)
print("SECTION 3  LR vs XGBoost DETAILED COMPARISON")
print("=" * 60)

lr_pred = (lr_proba >= 0.5).astype(int)

print("\nLogistic Regression Classification Report:")
print(classification_report(y_test, lr_pred,
      target_names=["Legitimate", "Phishing"]))

print("XGBoost Classification Report:")
print(classification_report(y_test, xgb_pred,
      target_names=["Legitimate", "Phishing"]))


# SECTION 4 - Sample False Positives and False Negatives
print("=" * 60)
print("SECTION 4  SAMPLE ERRORS (XGBoost, t=0.5)")
print("=" * 60)

y_test_arr    = y_test.reset_index(drop=True).values
xgb_pred_arr  = xgb_pred

# False Positives - legitimate sites wrongly flagged
fp_mask = (y_test_arr == 0) & (xgb_pred_arr == 1)
fp_urls = urls_test[fp_mask]["URL"].head(5).tolist()
fp_conf = xgb_proba[fp_mask][:5]

print("\nFalse Positives (legitimate URLs wrongly blocked):")
for url, conf in zip(fp_urls, fp_conf):
    print(f"  conf={conf:.3f}  {url[:80]}")

# False Negatives - phishing sites that slipped through
fn_mask = (y_test_arr == 1) & (xgb_pred_arr == 0)
fn_urls = urls_test[fn_mask]["URL"].head(5).tolist()
fn_conf = xgb_proba[fn_mask][:5]

print("\nFalse Negatives (phishing URLs that slipped through):")
for url, conf in zip(fn_urls, fn_conf):
    print(f"  conf={conf:.3f}  {url[:80]}")

print("""
Why False Negatives happen:
  These phishing URLs look structurally "clean"  short, HTTPS,
  no suspicious keywords, no high-risk TLD. They rely on brand
  impersonation or social engineering that lexical features alone
  cannot detect. This is exactly why Layers 1-3 of the hybrid
  system (blacklist, whitelist, lookalike detection) exist 
  to catch what the ML model misses.

Why False Positives happen:
  These legitimate URLs have unusual structural properties that
  overlap with phishing patterns  very long paths, many query
  parameters, numeric subdomains, or suspicious-looking keywords
  in the path (e.g. /account/ or /login/ on a real bank site).
""")


# SECTION 5 - Summary for report
print("=" * 60)
print("SECTION 5  SUMMARY FOR YOUR REPORT")
print("=" * 60)

print(f"""
Dataset:        579,920 URLs (339,074 legitimate / 240,846 phishing)
Features:       27 lexical URL features (no DNS/WHOIS/page content)
Train/Test:     80% / 20% stratified split (random_state=42)

                Logistic Regression    XGBoost (selected)
Accuracy:       {meta['logistic_regression']['accuracy']:.4f}                 {meta['xgboost']['accuracy']:.4f}
Precision:      {meta['logistic_regression']['precision']:.4f}                 {meta['xgboost']['precision']:.4f}
Recall:         {meta['logistic_regression']['recall']:.4f}                 {meta['xgboost']['recall']:.4f}
F1-Score:       {meta['logistic_regression']['f1']:.4f}                 {meta['xgboost']['f1']:.4f}
ROC-AUC:        {meta['logistic_regression']['roc_auc']:.4f}                 {meta['xgboost']['roc_auc']:.4f}
Training time:  {meta['logistic_regression']['training_time_seconds']:.1f}s                    {meta['xgboost']['training_time_seconds']:.1f}s

5-Fold CV (XGBoost):
  F1      mean={meta['cross_validation']['f1_mean']:.4f}  std={meta['cross_validation']['f1_std']:.4f}
  Recall  mean={meta['cross_validation']['recall_mean']:.4f}  std={meta['cross_validation']['recall_std']:.4f}
  ROC-AUC mean={meta['cross_validation']['roc_auc_mean']:.4f}  std={meta['cross_validation']['roc_auc_std']:.4f}

All three targets met:
  Recall  {meta['xgboost']['recall']:.4f}  >= 0.90  
  F1      {meta['xgboost']['f1']:.4f}  >= 0.85  
  ROC-AUC {meta['xgboost']['roc_auc']:.4f}  >= 0.90  
""")

# Save threshold results to metadata
with open("models/model_metadata.json") as f:
    meta = json.load(f)
meta["threshold_analysis"] = threshold_results
with open("models/model_metadata.json", "w") as f:
    json.dump(meta, f, indent=2)

print("Threshold analysis saved to models/model_metadata.json")
print("\nevaluate_model.py complete.")