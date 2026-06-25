import pandas as pd

print("Loading raw dataset...")
df = pd.read_csv("dataset/phishing_url_features.csv")
print(f"Raw shape: {df.shape[0]:,} rows x {df.shape[1]} columns")

# ================================================================
# DATA CLEANING AND PREPARATION
# ================================================================

# Step 1: Retain only the URL and label columns.
#
# The original dataset contains numerous pre-engineered lexical,
# DNS, and WHOIS features. These are intentionally removed because:
#
# 1. The project extracts features directly from raw URLs using
#    feature_extractor.py during both training and prediction.
#
# 2. DNS and WHOIS features require external network lookups,
#    which increase latency and are impractical for real-time
#    predictions in the Flask API.
#
# Only the raw URL and its corresponding label are required.
original_cols = df.shape[1]
df = df[["url", "label"]].copy()
print(f"Kept 2 columns, discarded {original_cols - 2} feature columns")

# Step 2: Remove rows with missing URLs or labels.
before = len(df)
df = df.dropna(subset=["url", "label"])
dropped = before - len(df)

if dropped > 0:
    print(f"Dropped {dropped:,} incomplete rows")
else:
    print("No missing values detected")

# Step 3: Remove leading and trailing whitespace from URLs.
# This prevents duplicate URLs caused by formatting issues.
df["url"] = df["url"].astype(str).str.strip()

# Step 4: Validate label values.
#
# Dataset convention:
#   0 = Legitimate URL
#   1 = Phishing URL
#
# Any unexpected labels are removed.
df["label"] = df["label"].astype(int)
unexpected = df[~df["label"].isin([0, 1])]

if len(unexpected) > 0:
    print(f"WARNING: {len(unexpected)} invalid labels found")
    df = df[df["label"].isin([0, 1])]

# Step 5: Remove duplicate URLs.
#
# Duplicate URLs can leak information between training and test
# sets, resulting in artificially inflated evaluation metrics.
before = len(df)
df = df.drop_duplicates(subset=["url"], keep="first")
removed = before - len(df)
print(f"Removed {removed:,} duplicate URLs")

# Step 6: Rename columns to match the project's naming convention.
df = df.rename(columns={
    "url": "URL",
    "label": "Label"
})

# Step 7: Reset the index after all cleaning operations.
df = df.reset_index(drop=True)

# ================================================================
# FINAL DATASET SUMMARY
# ================================================================

print(f"\nFinal clean dataset: {len(df):,} rows")

print("\nLabel distribution:")
counts = df["Label"].value_counts().sort_index()
pct = df["Label"].value_counts(normalize=True).sort_index() * 100

print(f"  0 = Legitimate: {counts[0]:,} ({pct[0]:.2f}%)")
print(f"  1 = Phishing:   {counts[1]:,} ({pct[1]:.2f}%)")

# Save the cleaned dataset for subsequent training stages.
df.to_csv("dataset/clean_urls.csv", index=False)

print("\nSaved to dataset/clean_urls.csv")
print("Columns in output:", df.columns.tolist())