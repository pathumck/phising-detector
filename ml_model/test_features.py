from feature_extractor import extract_features, FEATURE_NAMES

# Test URLs
test_cases = [
    {
        "label": "OBVIOUS PHISHING",
        "url": "http://paypal-secure-login.tk/account/verify?user=victim&token=abc123"
    },
    {
        "label": "CLEAN LEGITIMATE",
        "url": "https://www.google.com/search?q=python+tutorial"
    },
    {
        "label": "IP ADDRESS PHISHING",
        "url": "http://192.168.1.105/login/bank/account"
    },
    {
        "label": "AT SYMBOL TRICK",
        "url": "http://paypal.com@evil-phishing-site.com/steal"
    },
    {
        "label": "URL SHORTENER",
        "url": "http://bit.ly/3xK9mP2"
    },
    {
        "label": "HIGH ENTROPY RANDOM",
        "url": "http://xK9mP2qR7vL4j.xyz/a8f3b1c9d2e5/q7r2?tk=9x2m"
    },
]


# Print the table header.
print(f"{'Feature':<25} ", end="")
for case in test_cases:
    print(f"{case['label'][:18]:<20}", end="")
print()

# Print a separator line.
print("-" * (25 + 20 * len(test_cases)))

# Extract and print the value of this feature for every test URL.
for i, name in enumerate(FEATURE_NAMES):
    print(f"{name:<25} ", end="")
    for case in test_cases:
        val = extract_features(case["url"])[i]
        print(f"{str(val):<20}", end="")
    print()

# Print the complete feature vector for the phishing URL.
print("\n--- FULL VECTOR FOR OBVIOUS PHISHING URL ---")
phishing_url = test_cases[0]["url"]
features = extract_features(phishing_url)
print(f"URL: {phishing_url}")
print(f"Feature count: {len(features)}")
for name, val in zip(FEATURE_NAMES, features):
    print(f"  {name:<25} = {val}")