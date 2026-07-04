"""
Trains two models on the extracted feature dataset:
  Model 1 - Logistic Regression (interpretable academic baseline)
  Model 2 - XGBoost (production model)

Compares both on the held-out test set using F1-score.
Saves the best model as phishing_model.pkl for use by the
Flask API. Also saves both individual models, the scaler,
and a metadata JSON with all metrics for your report.
"""

import json
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix
)
from xgboost import XGBClassifier


# Step 1 - Load feature matrix and labels
print("=" * 60)
print("LOADING DATA")
print("=" * 60)

X = pd.read_csv("dataset/features_X.csv")
y = pd.read_csv("dataset/labels_y.csv").squeeze()  # DataFrame -> Series

print(f"Feature matrix: {X.shape[0]:,} rows x {X.shape[1]} features")
print(f"Label vector:   {len(y):,} values")
print(f"Features: {X.columns.tolist()}")
print(f"\nLabel distribution:")
print(f"  0 = Legitimate: {(y==0).sum():,} ({(y==0).mean()*100:.2f}%)")
print(f"  1 = Phishing:   {(y==1).sum():,} ({(y==1).mean()*100:.2f}%)")


# Step 2 - Stratified train/test split
print("\n" + "=" * 60)
print("TRAIN / TEST SPLIT")
print("=" * 60)

from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y          # preserve class ratio in both splits
)

print(f"Training set: {X_train.shape[0]:,} rows")
print(f"Test set:     {X_test.shape[0]:,} rows")
print(f"Train phishing ratio: {y_train.mean()*100:.2f}%")
print(f"Test  phishing ratio: {y_test.mean()*100:.2f}%")


# Step 3 - Fit StandardScaler on TRAINING DATA ONLY
print("\n" + "=" * 60)
print("FITTING STANDARD SCALER (training data only)")
print("=" * 60)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)   # fit + transform training
X_test_scaled  = scaler.transform(X_test)        # transform only - no fit

print("Scaler fitted on training data.")
print("Test data transformed using training statistics only.")
print(f"Feature means (first 5): "
      f"{scaler.mean_[:5].round(3)}")
print(f"Feature stds  (first 5): "
      f"{scaler.scale_[:5].round(3)}")

# Helper - compute all metrics from true and predicted labels
def evaluate(name, y_true, y_pred, y_proba):
    """Return a dict of all evaluation metrics for one model."""
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    return {
        "model":     name,
        "accuracy":  round(accuracy_score(y_true, y_pred),  4),
        "precision": round(precision_score(y_true, y_pred), 4),
        "recall":    round(recall_score(y_true, y_pred),    4),
        "f1":        round(f1_score(y_true, y_pred),        4),
        "roc_auc":   round(roc_auc_score(y_true, y_proba),  4),
        "tn": int(tn), "fp": int(fp),
        "fn": int(fn), "tp": int(tp),
    }


# Step 4 - Train Model 1: Logistic Regression
print("\n" + "=" * 60)
print("TRAINING MODEL 1 - LOGISTIC REGRESSION")
print("=" * 60)

lr = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    C=1.0,
    solver="lbfgs",
    random_state=42
)

t0 = time.time()
lr.fit(X_train_scaled, y_train)
lr_time = time.time() - t0
print(f"Training complete in {lr_time:.1f}s")

lr_pred  = lr.predict(X_test_scaled)
lr_proba = lr.predict_proba(X_test_scaled)[:, 1]
lr_metrics = evaluate("LogisticRegression", y_test, lr_pred, lr_proba)

print(f"  Accuracy:  {lr_metrics['accuracy']:.4f}")
print(f"  Precision: {lr_metrics['precision']:.4f}")
print(f"  Recall:    {lr_metrics['recall']:.4f}  [priority metric]")
print(f"  F1-Score:  {lr_metrics['f1']:.4f}  [selection metric]")
print(f"  ROC-AUC:   {lr_metrics['roc_auc']:.4f}")
print(f"  Confusion Matrix:")
print(f"    TN={lr_metrics['tn']:,}  FP={lr_metrics['fp']:,}")
print(f"    FN={lr_metrics['fn']:,}  TP={lr_metrics['tp']:,}")

# Feature coefficients for reporting
print(f"\nTop 10 most influential features (by abs coefficient):")
coef_df = pd.DataFrame({
    "feature": X.columns,
    "coefficient": lr.coef_[0]
}).reindex(lr.coef_[0].argsort()[::-1])
# Sort by absolute value
coef_df["abs_coef"] = coef_df["coefficient"].abs()
coef_df = coef_df.sort_values("abs_coef", ascending=False)
for _, row in coef_df.head(10).iterrows():
    direction = "PHISHING" if row["coefficient"] > 0 else "LEGITIMATE"
    print(f"  {row['feature']:<25} {row['coefficient']:+.4f}  {direction}")
