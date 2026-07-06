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
import os


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


# Step 5 - Train Model 2: XGBoost
print("\n" + "=" * 60)
print("TRAINING MODEL 2 - XGBOOST")
print("=" * 60)

# Calculate class imbalance ratio for scale_pos_weight
neg_count = (y_train == 0).sum()   # legitimate
pos_count = (y_train == 1).sum()   # phishing
scale_pos_weight = neg_count / pos_count
print(f"scale_pos_weight = {neg_count:,} / {pos_count:,} = {scale_pos_weight:.4f}")

xgb = XGBClassifier(
    n_estimators=200,
    learning_rate=0.1,
    max_depth=6,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=scale_pos_weight,
    random_state=42,
    verbosity=0,
    eval_metric="logloss"
)

t0 = time.time()
xgb.fit(X_train, y_train)   # raw features - no scaling for XGBoost
xgb_time = time.time() - t0
print(f"Training complete in {xgb_time:.1f}s")

xgb_pred  = xgb.predict(X_test)
xgb_proba = xgb.predict_proba(X_test)[:, 1]
xgb_metrics = evaluate("XGBoost", y_test, xgb_pred, xgb_proba)

print(f"  Accuracy:  {xgb_metrics['accuracy']:.4f}")
print(f"  Precision: {xgb_metrics['precision']:.4f}")
print(f"  Recall:    {xgb_metrics['recall']:.4f}  [priority metric]")
print(f"  F1-Score:  {xgb_metrics['f1']:.4f}  [selection metric]")
print(f"  ROC-AUC:   {xgb_metrics['roc_auc']:.4f}")
print(f"  Confusion Matrix:")
print(f"    TN={xgb_metrics['tn']:,}  FP={xgb_metrics['fp']:,}")
print(f"    FN={xgb_metrics['fn']:,}  TP={xgb_metrics['tp']:,}")

print(f"\nTop 10 most important features (by XGBoost gain):")
importance_df = pd.DataFrame({
    "feature":    X.columns,
    "importance": xgb.feature_importances_
}).sort_values("importance", ascending=False)
for _, row in importance_df.head(10).iterrows():
    print(f"  {row['feature']:<25} {row['importance']:.4f}")


# Step 6 - Side-by-side comparison and model selection
print("\n" + "=" * 60)
print("MODEL COMPARISON")
print("=" * 60)

headers = ["Metric", "Logistic Regression", "XGBoost", "Winner"]
print(f"  {headers[0]:<12} {headers[1]:<22} {headers[2]:<12} {headers[3]}")
print("  " + "-" * 55)

metrics_to_compare = [
    ("Accuracy",  "accuracy"),
    ("Precision", "precision"),
    ("Recall",    "recall"),
    ("F1-Score",  "f1"),
    ("ROC-AUC",   "roc_auc"),
]

for label, key in metrics_to_compare:
    lr_val  = lr_metrics[key]
    xgb_val = xgb_metrics[key]
    winner  = "XGBoost" if xgb_val >= lr_val else "LR"
    print(f"  {label:<12} {lr_val:<22.4f} {xgb_val:<12.4f} {winner}")

# Select winner by F1-score (per spec)
if xgb_metrics["f1"] >= lr_metrics["f1"]:
    best_model      = xgb
    best_model_name = "XGBoost"
    best_metrics    = xgb_metrics
    best_uses_scaler = False
    print(f"\n  SELECTED: XGBoost (F1={xgb_metrics['f1']:.4f})")
else:
    best_model      = lr
    best_model_name = "LogisticRegression"
    best_metrics    = lr_metrics
    best_uses_scaler = True
    print(f"\n  SELECTED: Logistic Regression (F1={lr_metrics['f1']:.4f})")


# Step 7 - 5-fold cross-validation on the selected model
print("\n" + "=" * 60)
print(f"5-FOLD CROSS-VALIDATION - {best_model_name}")
print("=" * 60)
print("Running... (this may take 1-3 minutes)")

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

if best_uses_scaler:
    # Select scaled or raw feature matrix based on requirements of the chosen model
    X_cv = pd.DataFrame(
        scaler.transform(X), columns=X.columns
    )
else:
    X_cv = X

cv_f1 = cross_val_score(
    best_model, X_cv, y,
    cv=cv, scoring="f1", n_jobs=-1
)
cv_recall = cross_val_score(
    best_model, X_cv, y,
    cv=cv, scoring="recall", n_jobs=-1
)
cv_auc = cross_val_score(
    best_model, X_cv, y,
    cv=cv, scoring="roc_auc", n_jobs=-1
)

print(f"\n  F1      per fold: {[round(v,4) for v in cv_f1]}")
print(f"  F1      mean: {cv_f1.mean():.4f}  std: {cv_f1.std():.4f}")
print(f"\n  Recall  per fold: {[round(v,4) for v in cv_recall]}")
print(f"  Recall  mean: {cv_recall.mean():.4f}  std: {cv_recall.std():.4f}")
print(f"\n  ROC-AUC per fold: {[round(v,4) for v in cv_auc]}")
print(f"  ROC-AUC mean: {cv_auc.mean():.4f}  std: {cv_auc.std():.4f}")


# Step 8 - Save all models and metadata
print("\n" + "=" * 60)
print("SAVING MODELS")
print("=" * 60)

# Create models directory
os.makedirs("models", exist_ok=True)

# Save individual models
joblib.dump(lr,  "models/lr_model.pkl")
joblib.dump(xgb, "models/xgb_model.pkl")
joblib.dump(scaler, "models/scaler.pkl")
print("  Saved: models/lr_model.pkl")
print("  Saved: models/xgb_model.pkl")
print("  Saved: models/scaler.pkl")

# Save the best model as the production model
joblib.dump(best_model, "models/phishing_model.pkl")
print(f"  Saved: models/phishing_model.pkl  ({best_model_name})")

# Save metadata - report will reference these numbers
metadata = {
    "selected_model":      best_model_name,
    "uses_scaler":         best_uses_scaler,
    "feature_names":       list(X.columns),
    "num_features":        len(X.columns),
    "train_size":          len(X_train),
    "test_size":           len(X_test),
    "label_convention":    {"0": "legitimate", "1": "phishing"},
    "logistic_regression": {
        **lr_metrics,
        "training_time_seconds": round(lr_time, 2),
        "parameters": {
            "max_iter": 1000,
            "class_weight": "balanced",
            "C": 1.0,
            "solver": "lbfgs",
            "random_state": 42
        }
    },
    "xgboost": {
        **xgb_metrics,
        "training_time_seconds": round(xgb_time, 2),
        "scale_pos_weight": round(scale_pos_weight, 4),
        "parameters": {
            "n_estimators": 200,
            "learning_rate": 0.1,
            "max_depth": 6,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "random_state": 42
        }
    },
    "cross_validation": {
        "folds": 5,
        "model": best_model_name,
        "f1_scores":      [round(v, 4) for v in cv_f1],
        "f1_mean":        round(cv_f1.mean(), 4),
        "f1_std":         round(cv_f1.std(), 4),
        "recall_mean":    round(cv_recall.mean(), 4),
        "recall_std":     round(cv_recall.std(), 4),
        "roc_auc_mean":   round(cv_auc.mean(), 4),
        "roc_auc_std":    round(cv_auc.std(), 4),
    }
}

with open("models/model_metadata.json", "w") as f:
    json.dump(metadata, f, indent=2)
print("  Saved: models/model_metadata.json")

print("\n" + "=" * 60)
print("TRAINING COMPLETE")
print("=" * 60)
print(f"  Best model:  {best_model_name}")
print(f"  F1-Score:    {best_metrics['f1']:.4f}")
print(f"  Recall:      {best_metrics['recall']:.4f}  (target >= 0.90)")
print(f"  ROC-AUC:     {best_metrics['roc_auc']:.4f}  (target >= 0.90)")
print(f"\n  Recall: {'MEETS TARGET' if best_metrics['recall'] >= 0.90 else 'BELOW TARGET - see evaluate_model.py for threshold tuning'}")
print(f"  ROC-AUC: {'MEETS TARGET' if best_metrics['roc_auc'] >= 0.90 else 'BELOW TARGET'}")
print("\nRun evaluate_model.py next for the full evaluation report.")