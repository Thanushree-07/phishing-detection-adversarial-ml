
import random
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
import re

import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    average_precision_score,
    roc_auc_score,
    confusion_matrix,
)

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

RANDOM_STATE = 42
TEST_SIZE = 0.20

DATA_PATH = Path("data/combined_dataset.csv")
MODEL_DIR = Path("text_model/saved_model")
MODEL_PATH = MODEL_DIR / "tfidf_adversarially_trained_model.joblib"
RESULTS_DIR = Path("text_model/results")

random.seed(RANDOM_STATE)


# --------------------------------------------------
# ADVERSARIAL TRANSFORMATIONS
# --------------------------------------------------

def digit_substitution(url):
    replacements = {
        "o": "0",
        "i": "1",
        "e": "3",
        "a": "4",
        "s": "5",
    }

    chars = list(url.lower())
    positions = [
        i for i, char in enumerate(chars)
        if char in replacements
    ]

    if not positions:
        return url

    position = random.choice(positions)
    chars[position] = replacements[chars[position]]
    return "".join(chars)


def typo_attack(url):
    candidate = url if "://" in url else "http://" + url
    parts = urlsplit(candidate)
    hostname = parts.hostname

    if not hostname or len(hostname) < 5:
        return url

    position = random.randint(1, len(hostname) - 2)
    changed_domain = (
        hostname[:position] + hostname[position + 1:]
    )

    netloc = re.sub(
        re.escape(hostname),
        changed_domain,
        parts.netloc,
        count=1,
        flags=re.IGNORECASE,
    )

    result = urlunsplit((
        parts.scheme,
        netloc,
        parts.path,
        parts.query,
        parts.fragment,
    ))

    return result


def homoglyph_attack(url):
    for i, char in enumerate(url):
        if char.lower() == "o":
            chars = list(url)
            chars[i] = "ο"  # Greek small letter omicron
            return "".join(chars)

    return url


ATTACKS = {
    "digit_substitution": digit_substitution,
    "typo": typo_attack,
    "homoglyph": homoglyph_attack,
}


# --------------------------------------------------
# LOAD AND CLEAN DATA
# --------------------------------------------------

def load_dataset():
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATA_PATH}"
        )

    df = pd.read_csv(DATA_PATH)

    if not {"url", "label"}.issubset(df.columns):
        raise ValueError("Dataset must contain url and label columns.")

    df = df[["url", "label"]].dropna().copy()
    df["url"] = df["url"].astype(str)
    df["label"] = df["label"].astype(int)
    df = df.drop_duplicates(subset=["url"])

    if not set(df["label"].unique()).issubset({0, 1}):
        raise ValueError("Labels must be 0 (legitimate) or 1 (phishing).")

    print("Dataset shape:", df.shape)
    print("Label distribution:")
    print(df["label"].value_counts())

    return df


# --------------------------------------------------
# BUILD THE SAME MODEL ARCHITECTURE
# --------------------------------------------------

def build_model():
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            lowercase=True,
            min_df=2,
            max_features=100000,
        )),
        ("classifier", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=RANDOM_STATE,
        )),
    ])


# --------------------------------------------------
# AUGMENT TRAINING DATA ONLY
# --------------------------------------------------

def augment_training_data(X_train, y_train):
    training_urls = list(X_train)
    training_labels = list(y_train)

    # Do not assign a phishing label to a URL already
    # labelled legitimate in the training set.
    existing_labels = dict(zip(training_urls, training_labels))
    seen = set(training_urls)

    generated_count = 0

    phishing_urls = [
        url for url, label in zip(training_urls, training_labels)
        if label == 1
    ]

    for url in phishing_urls:
        for attack_name, attack_function in ATTACKS.items():
            modified_url = attack_function(url)

            # Skip transformations that made no change.
            if modified_url == url:
                continue

            # Avoid duplicate samples and contradictory labels
            # within the training set.
            if modified_url in seen:
                continue

            if existing_labels.get(modified_url) == 0:
                continue

            seen.add(modified_url)
            training_urls.append(modified_url)
            training_labels.append(1)
            generated_count += 1

    print("\nOriginal training samples:", len(X_train))
    print("Generated adversarial samples:", generated_count)
    print("Augmented training samples:", len(training_urls))

    return pd.Series(training_urls), pd.Series(training_labels)


# --------------------------------------------------
# EVALUATION
# --------------------------------------------------

def evaluate_clean(model, X_test, y_test):
    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": accuracy_score(y_test, predictions),
        "precision": precision_score(
            y_test, predictions, zero_division=0
        ),
        "recall": recall_score(
            y_test, predictions, zero_division=0
        ),
        "f1": f1_score(y_test, predictions, zero_division=0),
        "roc_auc": roc_auc_score(y_test, probabilities),
        "pr_auc": average_precision_score(y_test, probabilities),
    }

    print("\n========== CLEAN TEST RESULTS ==========")
    for name, value in metrics.items():
        print(f"{name}: {value:.4f}")

    print("\nConfusion matrix:")
    print(confusion_matrix(y_test, predictions))

    return metrics


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main():
    df = load_dataset()

    X_train, X_test, y_train, y_test = train_test_split(
        df["url"],
        df["label"],
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=df["label"],
    )

    # Generate variants from training data only.
    X_augmented, y_augmented = augment_training_data(
        X_train, y_train
    )

    model = build_model()

    print("\nTraining adversarially augmented model...")
    model.fit(X_augmented, y_augmented)
    print("Training completed.")

    # The test set is not used to generate training examples.
    clean_metrics = evaluate_clean(model, X_test, y_test)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, MODEL_PATH)

    print("\nNew model saved to:", MODEL_PATH)

    metrics_path = RESULTS_DIR / "adversarial_training_clean_metrics.csv"
    pd.DataFrame([clean_metrics]).to_csv(metrics_path, index=False)

    print("Clean metrics saved to:", metrics_path)
    print("\nOriginal model files were not overwritten.")


if __name__ == "__main__":
    main()
