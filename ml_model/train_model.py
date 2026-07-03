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