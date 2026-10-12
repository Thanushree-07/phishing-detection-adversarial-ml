
import os
import random
import json
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
DATA_PATH = os.path.join("data", "combined_dataset.csv")
MODEL_DIR = os.path.join("text_model", "saved_model")
RESULTS_DIR = os.path.join("text_model", "results")
ORIGINAL_MODEL = os.path.join(
    MODEL_DIR, "tfidf_phishing_model.joblib"
)
HARDENED_MODEL = os.path.join(
    MODEL_DIR, "tfidf_hardened_model.joblib"
)
ADV_TRAINED_MODEL = os.path.join(
    MODEL_DIR, "tfidf_adversarially_trained_model.joblib"
)
RANDOM_STATE = 42
THRESHOLD = 0.5

os.makedirs(RESULTS_DIR, exist_ok=True)
random.seed(RANDOM_STATE)


# --------------------------------------------------
# ADVERSARIAL URL TRANSFORMATIONS
# --------------------------------------------------

def digit_substitution(url):
    """Replace selected letters with visually similar digits."""
    replacements = {
        "o": "0",
        "i": "1",
        "e": "3",
        "a": "4",
        "s": "5"
    }

    chars = list(url.lower())
    positions = [
        i for i, char in enumerate(chars)
        if char in replacements
    ]

    if not positions:
        return url

    # Change one eligible character, if possible.
    position = random.choice(positions)
    chars[position] = replacements[chars[position]]
    return "".join(chars)


def typo_attack(url):
    """Delete one character from the domain name."""
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(url if "://" in url else "http://" + url)
    domain = parts.hostname or ""

    if len(domain) < 5:
        return url

    # Avoid changing the first or last domain character.
    position = random.randint(1, len(domain) - 2)
    changed_domain = domain[:position] + domain[position + 1:]

    # Preserve port and credentials only if present.
    netloc = parts.netloc
    if domain in netloc:
        netloc = netloc.replace(domain, changed_domain, 1)

    return urlunsplit((
        parts.scheme,
        netloc,
        parts.path,
        parts.query,
        parts.fragment
    ))


def homoglyph_attack(url):
    """Replace ASCII 'o' with a visually similar Unicode character."""
    if "o" in url.lower():
        position = next(
            i for i, char in enumerate(url.lower())
            if char == "o"
        )
        chars = list(url)
        chars[position] = "ο"  # Greek small letter omicron
        return "".join(chars)

    return url


ATTACKS = {
    "digit_substitution": digit_substitution,
    "typo": typo_attack,
    "homoglyph": homoglyph_attack
}


# --------------------------------------------------
# LOAD DATA AND MODELS
# --------------------------------------------------

print("Loading dataset and trained models...")

df = pd.read_csv(DATA_PATH)
df = df.dropna(subset=["url", "label"])
df["url"] = df["url"].astype(str)
df = df.drop_duplicates(subset=["url"])

# Match the original model's stratified split.
_, test_df = train_test_split(
    df,
    test_size=0.2,
    random_state=RANDOM_STATE,
    stratify=df["label"]
)

# Evaluate phishing URLs only.
phishing_df = test_df[test_df["label"] == 1].copy()

if phishing_df.empty:
    raise ValueError("No phishing URLs found in the test set.")
original_model = joblib.load(ORIGINAL_MODEL)
hardened_model = joblib.load(HARDENED_MODEL)
adversarially_trained_model = joblib.load(ADV_TRAINED_MODEL)

models = {
    "original": original_model,
    "previous_hardened": hardened_model,
    "adversarially_trained": adversarially_trained_model,
}

print("Test phishing URLs:", len(phishing_df))


# --------------------------------------------------
# EVALUATION
# --------------------------------------------------

def phishing_probability(model, urls):
    """Return phishing probabilities (class label 1)."""
    probabilities = model.predict_proba(urls)
    classes = list(model.classes_)
    phishing_index = classes.index(1)
    return probabilities[:, phishing_index]


records = []

for attack_name, attack_function in ATTACKS.items():
    print("\nEvaluating:", attack_name)

    originals = phishing_df["url"].tolist()
    modified = [attack_function(url) for url in originals]

    for model_name, model in models.items():
        probabilities = phishing_probability(model, modified)
        predictions = (probabilities >= THRESHOLD).astype(int)

        # An evasion occurs when a phishing URL is classified as benign.
        successful_evasions = int((predictions == 0).sum())
        total = len(predictions)

        asr = successful_evasions / total if total else 0.0

        print(
            f"{model_name}: "
            f"evasion={successful_evasions}/{total}, "
            f"ASR={asr:.4f}"
        )

        for original, altered, probability, prediction in zip(
            originals, modified, probabilities, predictions
        ):
            records.append({
                "model": model_name,
                "attack": attack_name,
                "original_url": original,
                "modified_url": altered,
                "phishing_probability": float(probability),
                "predicted_label": int(prediction),
                "successful_evasion": int(prediction == 0)
            })


# --------------------------------------------------
# SAVE RESULTS
# --------------------------------------------------

results_df = pd.DataFrame(records)

csv_path = os.path.join(
    RESULTS_DIR, "adversarial_evaluation.csv"
)
summary_path = os.path.join(
    RESULTS_DIR, "adversarial_summary.csv"
)

results_df.to_csv(csv_path, index=False)

summary = (
    results_df.groupby(["model", "attack"])
    .agg(
        total=("successful_evasion", "size"),
        successful_evasions=("successful_evasion", "sum")
    )
    .reset_index()
)

summary["attack_success_rate"] = (
    summary["successful_evasions"] / summary["total"]
)
summary["detection_rate"] = 1 - summary["attack_success_rate"]

summary.to_csv(summary_path, index=False)

print("\nEvaluation complete.")
print("\nSummary:")
print(summary.to_string(index=False))
print("\nSaved detailed results to:", csv_path)
print("Saved summary to:", summary_path)
