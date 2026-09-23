import pandas as pd
import re
import math
from urllib.parse import urlparse

def shannon_entropy(text):
    if len(text) == 0:
        return 0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs)

def extract_features(url):
    features = {}
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        parsed = urlparse("http://invalid.com")

    domain = parsed.netloc
    path = parsed.path

    features["url_length"] = len(url)
    features["domain_length"] = len(domain)
    features["path_length"] = len(path)
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_digits"] = sum(c.isdigit() for c in url)
    features["num_at_symbols"] = url.count("@")
    features["num_question_marks"] = url.count("?")
    features["num_equal_signs"] = url.count("=")
    features["num_underscores"] = url.count("_")
    features["num_slashes"] = url.count("/")
    features["digit_ratio"] = features["num_digits"] / len(url) if len(url) > 0 else 0
    features["hyphen_ratio"] = features["num_hyphens"] / len(url) if len(url) > 0 else 0
    features["has_ip_address"] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) else 0
    features["has_https"] = 1 if url.startswith("https") else 0
    features["subdomain_count"] = max(domain.count(".") - 1, 0)

    suspicious_words = ["login", "verify", "secure", "account", "update",
                         "confirm", "banking", "signin", "password", "suspend"]
    features["suspicious_keyword_count"] = sum(word in url.lower() for word in suspicious_words)
    features["url_entropy"] = shannon_entropy(url)
    features["domain_entropy"] = shannon_entropy(domain)

    return features

df = pd.read_csv("combined_dataset.csv")
print(f"Extracting features for {len(df)} URLs...")

feature_rows = df["url"].apply(extract_features)
features_df = pd.DataFrame(list(feature_rows))

final_df = pd.concat([df[["url"]], features_df, df[["label"]]], axis=1)
final_df.to_csv("dataset_with_features.csv", index=False)

print("Done! Saved dataset_with_features.csv")
print(final_df.head())
print(final_df.columns)
print(final_df.shape)