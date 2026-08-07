"""
Layer verification test suite for the hybrid detection system.
Runs test cases to check layer logic, calculates confusion matrix metrics,
and identifies mismatches between expected and actual verdicts.
"""

from collections import Counter

from hybrid_checker import check_url
from domain_lists.blacklist import BLACKLIST

# Mock entries for testing open-redirect and blacklist detection
BLACKLIST.add("confirmed-phishing-test.com")
BLACKLIST.add("phish-login-portal.tk")


# Test Dataset: (label, url, expected_is_phishing)
test_cases = [
    # Layer 1 - Blacklist
    ("L1 Blacklist",
     "http://confirmed-phishing-test.com/steal/credentials",
     True),

    # Layer 2 - Whitelist
    ("L2 Whitelist",
     "https://www.google.com/search?q=python+tutorial",
     False),
    ("L2 Whitelist subdomain",
     "https://mail.google.com/inbox",
     False),
    ("L2 Whitelist",
     "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
     False),
    ("L2 Whitelist",
     "https://en.wikipedia.org/wiki/Phishing",
     False),
    ("L2 Whitelist gov.au",
     "https://www.exportfinance.gov.au/",
     False),
    ("L2 Whitelist LinkedIn",
     "https://www.linkedin.com/company/google",
     False),

    # Layer 2 - Subdomain impersonation on whitelisted parent
    ("L2 Subdomain Impersonation Through Whitelisted Parent",
     "https://exportfinance.av.com/apply",
     True),

    # Layer 3A - TLD Swap
    ("L3A TLD Swap",
     "http://paypal.net/login/account/verify",
     True),
    ("L3A TLD Swap",
     "http://netflix.xyz/signin/account",
     True),
    ("L3A TLD Swap",
     "http://amazon.tk/deals/today",
     True),

    # Layer 3A - Subdomain Impersonation
    ("L3A Subdomain impersonation",
     "http://google.evil-attacker.com/login",
     True),
    ("L3A Subdomain impersonation",
     "http://paypal.free-money.tk/claim",
     True),

    # Layer 3B - Typosquatting
    ("L3B Typo dist=1",
     "http://paypa1.com/secure/login",
     True),
    ("L3B Typo dist=1",
     "http://amazn.com/deals",
     True),
    ("L3B Typo dist=1",
     "http://gooogle.com/search",
     True),
    ("L3B Typo dist=2",
     "http://micosoft.com/login",
     True),

    # Layer 3B - Digit-Substitution
    ("L3B Digit-Sub Google (g00gle)",
     "http://g00gle.com/account/signin",
     True),
    ("L3B Digit-Sub Amazon (amaz0n)",
     "http://amaz0n.com/orders/track",
     True),

    # Layer 3C - Homograph (contains Cyrillic characters)
    ("L3C Homograph Cyrillic",
     "http://pаypal.com/login",
     True),
    ("L3C Homograph Cyrillic Amazon",
     "http://аmazon.com/orders",
     True),

    # Layer 4 - ML Model
    ("L4 ML Phishing",
     "http://xk9mp2qr.tk/login/steal/your/credentials",
     True),
    ("L4 ML Legitimate",
     "https://www.localcafeshop.lk/menu",
     False),
    ("L4 ML Legitimate",
     "https://myuniversity.edu.lk/student/results",
     False),

    # Advanced Parser & Edge Cases
    ("L3A Userinfo Spoofing",
     "https://paypal.com:login-verify@attacker-server.net/auth",
     True),
    ("L3A Userinfo Spoofing Classic @",
     "https://www.microsoft.com@evil-attacker-login.net/verify",
     True),
    ("L2 Whitelist Trailing Dot",
     "https://www.google.com./search?q=test",
     False),
    ("L3B Encoded Hostname",
     "http://%70%61%79%70%61%6c.com/account/login",
     False),

    # Regional Domain Coverage
    ("L2 Whitelist Sri Lanka Gov Portal",
     "https://www.gov.lk/",
     False),
    ("L2 Whitelist Sri Lanka University",
     "https://www.cmb.ac.lk/",
     False),
    ("L4/L2 Commercial Bank of Ceylon",
     "https://www.combank.lk/personal-banking",
     False),
    ("L4/L2 Sampath Bank",
     "https://www.sampath.lk/",
     False),
    ("L4/L2 Dialog Axiata (telecom)",
     "https://www.dialog.lk/",
     False),
    ("L3-gap Sampath Bank Subdomain Impersonation",
     "https://sampath.secure-login-verify.tk/account",
     True),
    ("L3-gap Bank of Ceylon Typosquat",
     "http://b0c-online.tk/secure/update",
     True),

    # Adversarial Cases
    ("ADV IP Obfuscation (octal-padded)",
     "http://0301.0250.0.1/login/verify",
     True),
    ("ADV IP Obfuscation (IPv6 literal)",
     "http://[2001:db8::1]/secure/update",
     True),
    ("ADV Combined Homograph + Digit-Sub",
     "http://pаypa1.com/login",
     True),
    ("ADV Hyphenated Compound-Label Brand Embedding",
     "http://sampath.paypal-secure-update.tk/verify",
     True),
    ("ADV Path-Based Brand Impersonation",
     "http://free-file-hosting-xyz123.com/paypal/secure/account/verify/login.html",
     True),
    ("ADV Deep Subdomain Chain",
     "http://a.b.c.d.e.f.g.h.paypal.secure-office365-verify.tk/login",
     True),
    ("ADV Mixed Case Subdomain Impersonation",
     "http://PayPal.COM.security-verify.TK/Login",
     True),
    ("ADV Encoded Space Before Dot",
     "http://paypal.com%20.evil-attacker.net/login",
     True),
]


def run_test_suite():
    print("=" * 75)
    print("  HYBRID DETECTION SYSTEM - FULL LAYER TEST")
    print("=" * 75)

    errors = 0
    executed_layers = []
    mismatches = []

    tp = fp = tn = fn = 0

    for label, url, expected_phishing in test_cases:
        result = check_url(url)

        verdict = result.get("verdict", "UNKNOWN").upper()
        layer = result.get("detection_layer", "unknown")
        conf = result.get("confidence", 0.0)
        is_phish = result.get("is_phishing", False)
        explanation = result.get("explanation", "No explanation.")

        executed_layers.append(layer)
        icon = "[PHISH]" if is_phish else "[SAFE]"

        correct = (is_phish == expected_phishing)
        mark = "MATCH" if correct else "MISMATCH"

        if is_phish and expected_phishing:
            tp += 1
        elif is_phish and not expected_phishing:
            fp += 1
        elif not is_phish and not expected_phishing:
            tn += 1
        else:
            fn += 1

        if not correct:
            mismatches.append((label, url, expected_phishing, is_phish, layer))

        print(f"\n  {icon}  [{label}]  {mark}")
        print(f"      URL:         {url[:68]}")
        print(f"      Expected:    {'PHISHING' if expected_phishing else 'SAFE'}")
        print(f"      Verdict:     {verdict:<10} | Confidence: {conf:.2f} | Layer: {layer}")
        print(f"      Explanation: {explanation[:68]}")

        if result.get("error"):
            print(f"      ERROR: {result['error']}")
            errors += 1

    print("\n" + "=" * 75)
    print("  LAYER DISTRIBUTION:")
    counts = Counter(executed_layers)
    for layer, count in sorted(counts.items()):
        print(f"    {layer:<40}  {count} URL(s)")

    print("\n" + "=" * 75)
    print("  MISMATCHES (expected vs actual):")
    if mismatches:
        for label, url, expected, actual, layer in mismatches:
            exp_str = "PHISHING" if expected else "SAFE"
            act_str = "PHISHING" if actual else "SAFE"
            print(f"    [{label}]")
            print(f"        URL:      {url[:68]}")
            print(f"        Expected: {exp_str}  |  Got: {act_str}  |  Layer: {layer}")
    else:
        print("    None - every case matched its expected label.")

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)

    print("\n" + "=" * 75)
    print("  CONFUSION MATRIX")
    print("=" * 75)
    print(f"    {'':>18}{'Predicted Phishing':>22}{'Predicted Safe':>18}")
    print(f"    {'Actually Phishing':<18}{tp:>22}{fn:>18}")
    print(f"    {'Actually Safe':<18}{fp:>22}{tn:>18}")

    print("\n  METRICS")
    print(f"    Accuracy    : {accuracy*100:6.2f}%")
    print(f"    Precision   : {precision*100:6.2f}%")
    print(f"    Recall(TPR) : {recall*100:6.2f}%")
    print(f"    Specificity : {specificity*100:6.2f}%")
    print(f"    FPR         : {fpr*100:6.2f}%")
    print(f"    FNR         : {fnr*100:6.2f}%")
    print(f"    F1 Score    : {f1*100:6.2f}%")

    print("\n" + "-" * 75)
    print(f"  Total Executed Cases : {len(test_cases)}")
    print(f"  Correct              : {tp + tn}")
    print(f"  Mismatches           : {len(mismatches)}")
    print(f"  Errors               : {errors}")
    print("=" * 75)
    print()


if __name__ == "__main__":
    run_test_suite()