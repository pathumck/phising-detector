import pandas as pd

# Load the raw dataset - all 75 columns (url + label + 73 pre-built features)
df = pd.read_csv("dataset/phishing_url_features.csv")

print("=" * 60)
print("DATASET SHAPE")
print("=" * 60)
print(f"Rows:    {df.shape[0]:,}")
print(f"Columns: {df.shape[1]}")

print("\n" + "=" * 60)
print("ALL COLUMN NAMES")
print("=" * 60)
for i, col in enumerate(df.columns.tolist()):
    print(f"  [{i:02d}] {col}")

print("\n" + "=" * 60)
print("DATA TYPES - url and label only")
print("=" * 60)
print(df[["url", "label"]].dtypes)

print("\n" + "=" * 60)
print("MISSING VALUES - url and label only")
print("=" * 60)
print(df[["url", "label"]].isnull().sum())

print("\n" + "=" * 60)
print("LABEL DISTRIBUTION")
print("=" * 60)
counts = df["label"].value_counts().sort_index()
print(f"  0 = Legitimate: {counts[0]:,}")
print(f"  1 = Phishing:   {counts[1]:,}")
print()
pct = df["label"].value_counts(normalize=True).sort_index() * 100
print(f"  Legitimate: {pct[0]:.2f}%")
print(f"  Phishing:   {pct[1]:.2f}%")
print()
print("NOTE: label convention already matches our project.")
print("  1 = phishing, 0 = legitimate. No flipping needed.")

print("\n" + "=" * 60)
print("DUPLICATE CHECK")
print("=" * 60)
print(f"  Fully duplicate rows:     {df.duplicated().sum():,}")
print(f"  Duplicate URLs only:      {df.duplicated(subset=['url']).sum():,}")

print("\n" + "=" * 60)
print("SAMPLE PHISHING URLs  (label == 1)")
print("=" * 60)
for url in df[df["label"] == 1]["url"].head(5):
    print(f"  {url}")

print("\n" + "=" * 60)
print("SAMPLE LEGITIMATE URLs  (label == 0)")
print("=" * 60)
for url in df[df["label"] == 0]["url"].head(5):
    print(f"  {url}")

print("\n" + "=" * 60)
print("URL LENGTH STATS")
print("=" * 60)
print(df["url_length"].describe().round(2))