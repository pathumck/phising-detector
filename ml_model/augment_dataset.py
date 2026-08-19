import csv
import random
import pandas as pd

# Set random seed for reproducible sampling
SEED = 42
random.seed(SEED)

print("Loading existing clean dataset...")
existing_path = "dataset/clean_urls.csv"
existing = pd.read_csv(existing_path)

print(f"Existing Total: {len(existing):,} URLs")
num_phishing = (existing["Label"] == 1).sum()
num_legit = (existing["Label"] == 0).sum()
print(f"  Phishing (1)  : {num_phishing:,}")
print(f"  Legitimate (0): {num_legit:,}")


# Source 1 - Tranco Top Domains (Handled Robustly)
print("\nLoading Tranco list for legitimate URL augmentation...")

tranco_domains = []
tranco_file = "domain_lists/tranco_top1m.csv"

with open(tranco_file, "r", encoding="utf-8") as f:
    reader = csv.reader(f)
    for idx, row in enumerate(reader, start=1):
        if not row:
            continue
        
        # Support both 1-column (domain) and 2-column (rank, domain) formats
        if len(row) == 1:
            rank = idx
            domain = row[0].strip().lower()
        else:
            try:
                rank = int(row[0])
                domain = row[1].strip().lower()
            except ValueError:
                continue  # Skip header row if present

        # Target rank range: 10,001 to 500,000
        if 10_001 <= rank <= 500_000 and domain:
            tranco_domains.append(domain)

print(f"Tranco domains available in rank range: {len(tranco_domains):,}")

# Cap sampling to prevent destroying class ratios (max 1.5x of existing phishing count)
target_legit_count = min(80_000, int(num_phishing * 1.5))
sampled_domains = random.sample(tranco_domains, min(target_legit_count, len(tranco_domains)))

# Realistic paths to inject structural diversity into augmented data
COMMON_PATHS = [
    "", "", "", "/", "/index.html", "/home", "/about-us", 
    "/contact", "/products", "/services", "/blog", "/faq",
    "/en/", "/login", "/terms", "/privacy"
]

augmented_rows = []
for domain in sampled_domains:
    # 1. Scheme selection (95% https, 5% http to reflect real distribution)
    scheme = "https" if random.random() < 0.95 else "http"
    
    # 2. Subdomain selection
    prefix = "www." if random.random() > 0.4 else ""
    
    # 3. Path injection for structural variety
    path = random.choice(COMMON_PATHS)
    
    url = f"{scheme}://{prefix}{domain}{path}"
    augmented_rows.append({"URL": url, "Label": 0})

augmented_df = pd.DataFrame(augmented_rows)
print(f"Generated {len(augmented_df):,} realistic legitimate URLs")

# Source 2 - Targeted Regional & Institutional Multi-Word Patterns
manual_legitimate = [
    # Sri Lankan educational and enterprise domains
    "https://studyworldlanka.com/",
    "https://universityofjaffna.ac.lk/",
    "https://sliit.lk/",
    "https://cmb.ac.lk/",
    "https://moe.gov.lk/",
    "https://sltelecom.lk/",
    # Multi-word developer & technical resources
    "https://stackoverflow.com/questions/",
    "https://digitalocean.com/community/",
    "https://freecodecamp.org/learn/",
    "https://w3schools.com/python/",
    "https://geeksforgeeks.org/python-programming-language/",
    "https://tutorialspoint.com/python/",
    "https://javatpoint.com/python-tutorial",
    "https://programiz.com/python-programming",
    "https://realpython.com/tutorials/",
    "https://learnpython.org/",
    "https://codecademy.com/learn/learn-python-3",
]

manual_df = pd.DataFrame([{"URL": url, "Label": 0} for url in manual_legitimate])


# Merging, Cleaning & Deduplication
final_df = pd.concat([existing, augmented_df, manual_df], ignore_index=True)

# Standardize URLs prior to deduplication
final_df["URL"] = final_df["URL"].str.strip()

before_count = len(final_df)
final_df = final_df.drop_duplicates(subset=["URL"], keep="first")
print(f"Removed {before_count - len(final_df):,} exact duplicate URLs")

# Shuffle dataset cleanly
final_df = final_df.sample(frac=1, random_state=SEED).reset_index(drop=True)


# Dataset Summary & Export
total_final = len(final_df)
legit_final = (final_df["Label"] == 0).sum()
phish_final = (final_df["Label"] == 1).sum()

print(f"\n--- Final Dataset Summary ---")
print(f"Total Dataset Size : {total_final:,} URLs")
print(f"Legitimate (0)     : {legit_final:,} ({legit_final / total_final * 100:.2f}%)")
print(f"Phishing (1)       : {phish_final:,} ({phish_final / total_final * 100:.2f}%)")

output_path = "dataset/clean_urls_augmented.csv"
final_df.to_csv(output_path, index=False)
print(f"\nSuccessfully saved augmented dataset to: {output_path}")