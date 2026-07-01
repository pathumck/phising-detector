"""
Runs feature_extractor.py across every URL in clean_urls.csv
and saves the results as:
  dataset/features_X.csv  - 27 numeric features, one row per URL
  dataset/labels_y.csv    - matching labels (1=phishing, 0=legitimate)
"""

import pandas as pd
import time
from feature_extractor import extract_features, FEATURE_NAMES

# Load the cleaned dataset produced by preprocess.py
print("Loading clean_urls.csv ...")
df = pd.read_csv("dataset/clean_urls.csv")
print(f"Loaded {len(df):,} URLs")
print(f"Label distribution:")
print(f"  0 = Legitimate: {(df['Label']==0).sum():,}")
print(f"  1 = Phishing:   {(df['Label']==1).sum():,}")

urls   = df["URL"].tolist()
labels = df["Label"].tolist()

# Extract features - batch processing with progress reporting
print(f"\nExtracting {len(FEATURE_NAMES)} features from {len(urls):,} URLs ...")
print("Progress will update every 50,000 URLs.\n")

features_list = []
errors        = 0
start_time    = time.time()

for i, url in enumerate(urls):

    # Progress update every 50,000 URLs
    if i > 0 and i % 50_000 == 0:
        elapsed  = time.time() - start_time
        rate     = i / elapsed
        remaining = (len(urls) - i) / rate
        print(f"  [{i:>7,} / {len(urls):,}]  "
              f"elapsed: {elapsed:.0f}s  "
              f"rate: {rate:.0f} URLs/s  "
              f"remaining: ~{remaining:.0f}s")

    try:
        features = extract_features(url)
        features_list.append(features)
    except Exception as e:
        # If a URL is so malformed it crashes the extractor,
        # fill with zeros rather than losing the whole batch.
        # This should never happen - urlparse is very resilient -
        # but it is good defensive programming practice.
        features_list.append([0] * len(FEATURE_NAMES))
        errors += 1
        if errors <= 5:  # only print the first 5 errors
            print(f"  WARNING: Error on URL [{i}]: {url[:60]} — {e}")

elapsed_total = time.time() - start_time
print(f"\nExtraction complete in {elapsed_total:.1f}s "
      f"({len(urls)/elapsed_total:.0f} URLs/second)")

if errors > 0:
    print(f"WARNING: {errors} URLs produced errors and were filled with zeros")
else:
    print("No extraction errors — all URLs processed cleanly")

# Build DataFrames and save
print("\nBuilding feature DataFrame ...")
features_df = pd.DataFrame(features_list, columns=FEATURE_NAMES)
labels_df   = pd.Series(labels, name="Label")

# Sanity check - row counts must match perfectly
assert len(features_df) == len(labels_df), \
    f"MISMATCH: features={len(features_df)}, labels={len(labels_df)}"
assert list(features_df.columns) == FEATURE_NAMES, \
    "Column order mismatch — FEATURE_NAMES changed after extraction"

print(f"Feature matrix shape: {features_df.shape}")
print(f"Label vector length:  {len(labels_df):,}")

# Show a quick statistical summary of the feature matrix
print("\nFeature summary (first 10 features):")
print(features_df.iloc[:, :10].describe().round(3))

# Save
features_df.to_csv("dataset/features_X.csv", index=False)
labels_df.to_csv("dataset/labels_y.csv", index=False)

print("\nSaved:")
print("  dataset/features_X.csv")
print("  dataset/labels_y.csv")
print("\nPhase 4 Step 1 complete. Run train_model.py next.")