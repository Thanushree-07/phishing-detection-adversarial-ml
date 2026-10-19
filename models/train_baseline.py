import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import (
    classification_report, roc_auc_score, average_precision_score,
    confusion_matrix
)
import joblib

# ---- Load data ----
df = pd.read_csv("dataset_with_features.csv")
print(f"Loaded {len(df)} rows, {df.shape[1]} columns")

# ---- Split features (X) from label (y) ----
X = df.drop(columns=["url", "label"])
y = df["label"]

print(f"\nFeature columns used ({len(X.columns)}):")
print(list(X.columns))

# ---- Train/test split ----
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\nTrain size: {len(X_train)}, Test size: {len(X_test)}")

# ==========================================================
# MODEL 1: Logistic Regression (interpretable baseline)
# Scaled, since LR needs feature scaling to converge reliably
# on data with widely different feature ranges.
# ==========================================================
print("\n" + "=" * 60)
print("MODEL 1: Logistic Regression")
print("=" * 60)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

log_reg = LogisticRegression(max_iter=2000)
log_reg.fit(X_train_scaled, y_train)

lr_preds = log_reg.predict(X_test_scaled)
lr_probs = log_reg.predict_proba(X_test_scaled)[:, 1]

print("\nClassification Report:")
print(classification_report(y_test, lr_preds, target_names=["legitimate", "phishing"]))

print(f"ROC-AUC:  {roc_auc_score(y_test, lr_probs):.4f}")
print(f"PR-AUC:   {average_precision_score(y_test, lr_probs):.4f}")

print("\nConfusion Matrix:")
print("             predicted_legit  predicted_phish")
cm = confusion_matrix(y_test, lr_preds)
print(f"actual_legit      {cm[0][0]:>6}          {cm[0][1]:>6}")
print(f"actual_phish      {cm[1][0]:>6}          {cm[1][1]:>6}")

print("\nTop features driving predictions (by weight):")
coefs = pd.Series(log_reg.coef_[0], index=X.columns).sort_values(key=abs, ascending=False)
print(coefs.head(10))

# ==========================================================
# MODEL 2: Gradient-Boosted Trees
# No scaling needed - tree-based models are scale-invariant.
# ==========================================================
print("\n" + "=" * 60)
print("MODEL 2: Gradient-Boosted Trees")
print("=" * 60)

gbt = GradientBoostingClassifier(random_state=42)
gbt.fit(X_train, y_train)

gbt_preds = gbt.predict(X_test)
gbt_probs = gbt.predict_proba(X_test)[:, 1]

print("\nClassification Report:")
print(classification_report(y_test, gbt_preds, target_names=["legitimate", "phishing"]))

print(f"ROC-AUC:  {roc_auc_score(y_test, gbt_probs):.4f}")
print(f"PR-AUC:   {average_precision_score(y_test, gbt_probs):.4f}")

print("\nConfusion Matrix:")
print("             predicted_legit  predicted_phish")
cm = confusion_matrix(y_test, gbt_preds)
print(f"actual_legit      {cm[0][0]:>6}          {cm[0][1]:>6}")
print(f"actual_phish      {cm[1][0]:>6}          {cm[1][1]:>6}")

print("\nTop features driving predictions (by importance):")
importances = pd.Series(gbt.feature_importances_, index=X.columns).sort_values(ascending=False)
print(importances.head(10))

# ==========================================================
# Save models + the scaler (needed at inference time for LR)
# ==========================================================
joblib.dump(log_reg, "baseline_logreg.pkl")
joblib.dump(gbt, "baseline_gbt.pkl")
joblib.dump(scaler, "baseline_scaler.pkl")
print("\nSaved models: baseline_logreg.pkl, baseline_gbt.pkl, baseline_scaler.pkl")