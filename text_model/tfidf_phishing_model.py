import os
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
    roc_auc_score,
    average_precision_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# CONFIGURATION
# ============================================================

DATA_PATH = "../data/combined_dataset.csv"
MODEL_DIR = "saved_model"
MODEL_PATH = os.path.join(MODEL_DIR, "tfidf_phishing_model.joblib")

RANDOM_STATE = 42
TEST_SIZE = 0.20


# ============================================================
# 1. LOAD DATASET
# ============================================================

def load_dataset():

    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(
            f"Dataset not found at: {DATA_PATH}"
        )

    df = pd.read_csv(DATA_PATH)

    print("\n========== DATASET ==========")
    print("Shape:", df.shape)
    print("Columns:", list(df.columns))
    print("\nFirst 5 rows:")
    print(df.head())

    return df


# ============================================================
# 2. CLEAN DATASET
# ============================================================

def clean_dataset(df):

    required_columns = ["url", "label"]

    for column in required_columns:
        if column not in df.columns:
            raise ValueError(
                f"Required column '{column}' is missing."
            )

    # Keep only required columns
    df = df[required_columns].copy()

    # Remove missing values
    df = df.dropna()

    # Convert URL to string
    df["url"] = df["url"].astype(str)

    # Convert label to integer
    df["label"] = df["label"].astype(int)

    # Remove duplicate URLs
    before = len(df)
    df = df.drop_duplicates(subset=["url"])
    after = len(df)

    print("\n========== DATA CLEANING ==========")
    print("Duplicates removed:", before - after)
    print("Missing values:", df.isnull().sum().sum())

    print("\nLabel distribution:")
    print(df["label"].value_counts())

    print("\nFinal dataset shape:", df.shape)

    return df


# ============================================================
# 3. TRAIN-TEST SPLIT
# ============================================================

def split_data(df):

    X = df["url"]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y
    )

    print("\n========== DATA SPLIT ==========")
    print("Training samples:", len(X_train))
    print("Testing samples:", len(X_test))

    print("\nTraining label distribution:")
    print(y_train.value_counts())

    print("\nTesting label distribution:")
    print(y_test.value_counts())

    return X_train, X_test, y_train, y_test


# ============================================================
# 4. BUILD TF-IDF MODEL
# ============================================================

def build_model():

    tfidf = TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        lowercase=True,
        min_df=2,
        max_features=100000
    )

    classifier = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=RANDOM_STATE
    )

    model = Pipeline([
        ("tfidf", tfidf),
        ("classifier", classifier)
    ])

    return model


# ============================================================
# 5. TRAIN MODEL
# ============================================================

def train_model(model, X_train, y_train):

    print("\n========== TRAINING ==========")

    model.fit(X_train, y_train)

    print("Training completed.")

    return model


# ============================================================
# 6. EVALUATE MODEL
# ============================================================

def evaluate_model(model, X_test, y_test):

    print("\n========== MODEL EVALUATION ==========")

    # Predictions
    y_pred = model.predict(X_test)

    # Probability of phishing class
    y_prob = model.predict_proba(X_test)[:, 1]

    # Metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    roc_auc = roc_auc_score(y_test, y_prob)
    pr_auc = average_precision_score(y_test, y_prob)

    print(f"\nAccuracy  : {accuracy:.4f}")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1 Score  : {f1:.4f}")
    print(f"ROC-AUC   : {roc_auc:.4f}")
    print(f"PR-AUC    : {pr_auc:.4f}")

    print("\n========== CLASSIFICATION REPORT ==========")
    print(
        classification_report(
            y_test,
            y_pred,
            target_names=["Legitimate", "Phishing"],
            zero_division=0
        )
    )

    print("========== CONFUSION MATRIX ==========")
    print(confusion_matrix(y_test, y_pred))

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc
    }


# ============================================================
# 7. SAVE MODEL
# ============================================================

def save_model(model):

    os.makedirs(MODEL_DIR, exist_ok=True)

    joblib.dump(model, MODEL_PATH)

    print("\n========== MODEL SAVED ==========")
    print("Model saved at:", MODEL_PATH)


# ============================================================
# 8. TEST A SINGLE URL
# ============================================================

def predict_url(model, url):

    prediction = model.predict([url])[0]
    probability = model.predict_proba([url])[0][1]

    if prediction == 1:
        result = "PHISHING"
    else:
        result = "LEGITIMATE"

    print("\n========== URL PREDICTION ==========")
    print("URL:", url)
    print("Prediction:", result)
    print(f"Phishing Probability: {probability:.4f}")


# ============================================================
# MAIN
# ============================================================

def main():

    # Step 1: Load dataset
    df = load_dataset()

    # Step 2: Clean dataset
    df = clean_dataset(df)

    # Step 3: Split dataset
    X_train, X_test, y_train, y_test = split_data(df)

    # Step 4: Build TF-IDF + Logistic Regression
    model = build_model()

    # Step 5: Train
    model = train_model(
        model,
        X_train,
        y_train
    )

    # Step 6: Evaluate
    evaluate_model(
        model,
        X_test,
        y_test
    )

    # Step 7: Save
    save_model(model)

    # Step 8: Example prediction
    predict_url(
        model,
        "http://triplinkintl.com"
    )


if __name__ == "__main__":
    main()