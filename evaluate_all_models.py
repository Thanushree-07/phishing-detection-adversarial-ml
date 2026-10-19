"""
evaluate_all_models.py  --  ONE consistent experiment for the research article.

Run from the PROJECT ROOT (the folder that contains data/, backend/, models/):
    python evaluate_all_models.py

It trains the three classical models on the SAME 80/20 stratified split (seed 42),
and writes every table/figure number used in Sections 6-8 of the article.
Outputs go to ./article_results/
"""
import os, sys, time, random, platform
import numpy as np, pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import sklearn
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             roc_auc_score, average_precision_score, confusion_matrix, roc_curve)

sys.path.insert(0, "backend")
from features import features_as_row, FEATURE_ORDER
from evasion import digit_substitution, typo_attack, homoglyph_attack, keyword_stuffing_attack

OUT = "article_results"; os.makedirs(OUT, exist_ok=True)
SEED = 42
print("ENVIRONMENT:", platform.platform(), "| Python", platform.python_version(),
      "| scikit-learn", sklearn.__version__, "| pandas", pd.__version__, "| numpy", np.__version__)

# ---------------- data and split (identical for every model) ----------------
df = pd.read_csv("data/dataset_with_features.csv")
print("Rows:", len(df), "| duplicates:", df.url.duplicated().sum(), "| nulls:", int(df.isna().sum().sum()))
print(df.label.value_counts().rename({0: "legitimate", 1: "phishing"}))
tr, te = train_test_split(df, test_size=0.2, random_state=SEED, stratify=df.label)
Xtr, Xte = tr[FEATURE_ORDER], te[FEATURE_ORDER]
ytr, yte = tr.label.values, te.label.values
print("Train:", len(tr), "| Test:", len(te))

# ---------------- models ----------------
models = {}
t0 = time.time(); sc = StandardScaler().fit(Xtr)
lr = LogisticRegression(max_iter=2000).fit(sc.transform(Xtr), ytr)
models["LR (19 features)"] = dict(fit=time.time() - t0, feat=True,
    proba=lambda X, u: lr.predict_proba(sc.transform(X))[:, 1])

t0 = time.time(); gbt = GradientBoostingClassifier(random_state=SEED).fit(Xtr, ytr)
models["GBT (19 features)"] = dict(fit=time.time() - t0, feat=True,
    proba=lambda X, u: gbt.predict_proba(X)[:, 1])

t0 = time.time()
tfidf = Pipeline([("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), lowercase=True,
                                            min_df=2, max_features=100000)),
                  ("clf", LogisticRegression(max_iter=1000, random_state=SEED))]).fit(tr.url.tolist(), ytr)
models["TF-IDF + LR (char 3-5)"] = dict(fit=time.time() - t0, feat=False,
    proba=lambda X, u: tfidf.predict_proba(list(u))[:, 1])

def feats(urls):
    return pd.DataFrame([features_as_row(u)[0] for u in urls], columns=FEATURE_ORDER)

# ---------------- clean performance ----------------
rows, probs = [], {}
for name, m in models.items():
    p = m["proba"](Xte, te.url.values); probs[name] = p
    pred = (p >= 0.5).astype(int); tn, fp, fn, tp = confusion_matrix(yte, pred).ravel()
    sample = te.url.values[:300]; t0 = time.time()
    for u in sample:                                   # per-URL latency (feature extraction included)
        m["proba"](feats([u]) if m["feat"] else None, [u])
    ms = (time.time() - t0) / len(sample) * 1000
    rows.append(dict(Model=name, Accuracy=accuracy_score(yte, pred), Precision=precision_score(yte, pred),
                     Recall=recall_score(yte, pred), F1=f1_score(yte, pred), ROC_AUC=roc_auc_score(yte, p),
                     PR_AUC=average_precision_score(yte, p), TN=tn, FP=fp, FN=fn, TP=tp,
                     FPR=fp / (fp + tn), Train_seconds=m["fit"], Latency_ms_per_URL=ms))
res = pd.DataFrame(rows); res.to_csv(f"{OUT}/model_comparison.csv", index=False)
print("\n=== TABLE 3: clean test performance ==="); print(res.round(4).to_string(index=False))

# ---------------- robustness (attacks applied to the TEST set only) ----------------
random.seed(SEED)
phish = te[te.label == 1].url.tolist(); legit = te[te.label == 0].url.tolist()
attacks = {"digit_substitution": digit_substitution, "typo": typo_attack, "homoglyph": homoglyph_attack}
rob = []
for name, m in models.items():
    base = (m["proba"](feats(phish) if m["feat"] else None, phish) >= .5).mean()
    rob.append(dict(Model=name, Test="clean phishing (recall)", Rate=base))
    for an, fn in attacks.items():
        random.seed(SEED); adv = [fn(u) for u in phish]
        rob.append(dict(Model=name, Test=f"{an} (detection rate)",
                        Rate=(m["proba"](feats(adv) if m["feat"] else None, adv) >= .5).mean()))
    fpr0 = (m["proba"](feats(legit) if m["feat"] else None, legit) >= .5).mean()
    fa = [keyword_stuffing_attack(u) for u in legit]
    rob.append(dict(Model=name, Test="clean legitimate (false-positive rate)", Rate=fpr0))
    rob.append(dict(Model=name, Test="keyword_stuffing on legitimate (false-positive rate)",
                    Rate=(m["proba"](feats(fa) if m["feat"] else None, fa) >= .5).mean()))
rob = pd.DataFrame(rob); rob.to_csv(f"{OUT}/robustness.csv", index=False)
print("\n=== TABLE 4: robustness ==="); print(rob.pivot(index="Test", columns="Model", values="Rate").round(4).to_string())

# ---------------- figures ----------------
fig, ax = plt.subplots(figsize=(5.5, 4.5))
for name, p in probs.items():
    fpr, tpr, _ = roc_curve(yte, p); ax.plot(fpr, tpr, label=f"{name} (AUC={roc_auc_score(yte, p):.3f})")
ax.plot([0, 1], [0, 1], "k--", lw=.8); ax.set_xlabel("False positive rate"); ax.set_ylabel("True positive rate")
ax.set_title("ROC curves on the held-out test set"); ax.legend(loc="lower right", fontsize=8); fig.tight_layout()
fig.savefig(f"{OUT}/fig_roc.png", dpi=200); plt.close(fig)

fig, axes = plt.subplots(1, 3, figsize=(12, 3.8))
for ax, (name, p) in zip(axes, probs.items()):
    cm = confusion_matrix(yte, (p >= .5).astype(int)); ax.imshow(cm, cmap="Blues")
    for (i, j), v in np.ndenumerate(cm): ax.text(j, i, v, ha="center", va="center", fontsize=12)
    ax.set_xticks([0, 1], ["legit", "phish"]); ax.set_yticks([0, 1], ["legit", "phish"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(name, fontsize=10)
fig.tight_layout(); fig.savefig(f"{OUT}/fig_confusion.png", dpi=200); plt.close(fig)

imp = pd.Series(gbt.feature_importances_, index=FEATURE_ORDER).sort_values()
fig, ax = plt.subplots(figsize=(6, 5)); imp.plot(kind="barh", ax=ax, color="#3b6ea5")
ax.set_title("GBT feature importance"); ax.set_xlabel("Importance"); fig.tight_layout()
fig.savefig(f"{OUT}/fig_feature_importance.png", dpi=200); plt.close(fig)
imp.sort_values(ascending=False).to_csv(f"{OUT}/gbt_feature_importance.csv", header=["importance"])

names = tfidf.named_steps["tfidf"].get_feature_names_out(); w = tfidf.named_steps["clf"].coef_[0]; o = np.argsort(w)
pd.DataFrame({"toward_phishing": names[o[-15:]][::-1], "toward_legitimate": names[o[:15]]}).to_csv(f"{OUT}/tfidf_top_ngrams.csv", index=False)
print("\nTop char n-grams -> phishing:", list(names[o[-10:]][::-1])); print("Top char n-grams -> legitimate:", list(names[o[:10]]))
print("\nDone. Files written to", OUT)