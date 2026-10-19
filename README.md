# Adversarially Robust Phishing URL Detection

A machine-learning project for detecting phishing URLs and evaluating model robustness against adversarial URL manipulation techniques.

## Overview

Phishing attacks use deceptive URLs to trick users into visiting malicious websites. This project compares machine-learning approaches for distinguishing phishing URLs from legitimate ones and investigates how URL modifications affect detection performance.

The study compares lexical feature-based classification with character-level text classification and evaluates robustness against digit substitution, homoglyph substitution, keyword stuffing, and typographical changes.

## Key Features

- Phishing and legitimate URL classification
- Extraction of 19 handcrafted lexical features
- Character-level TF-IDF using 3–5 character n-grams
- Comparison of Logistic Regression and Gradient-Boosted Trees
- Adversarial URL robustness evaluation
- Confusion matrix and classification metric analysis
- Training time and inference latency measurement
- Saved models and experimental result files

## Tech Stack

- **Language:** Python 3.13.9
- **Machine Learning:** scikit-learn
- **Data Processing:** pandas, NumPy
- **Visualisation:** Matplotlib
- **Application:** Frontend and backend components

## Models Compared

| Model | Feature Representation |
|---|---|
| Logistic Regression | 19 lexical features |
| Gradient-Boosted Trees | 19 lexical features |
| Character TF-IDF + Logistic Regression | Character n-grams (3–5) |

## Dataset

The dataset contains 11,729 URLs collected from public sources.

| Property | Count |
|---|---:|
| Total URLs | 11,729 |
| Phishing URLs | 6,014 |
| Legitimate URLs | 5,715 |
| Duplicate URLs after cleaning | 0 |
| Missing values after cleaning | 0 |
| Training samples | 9,383 |
| Testing samples | 2,346 |

An 80:20 stratified train-test split was used with random seed `42`.

## Experimental Results

The following results were obtained on the clean test set.

| Model | Accuracy | Precision | Recall | F1-score | ROC-AUC | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 76.94% | 82.39% | 69.99% | 75.69% | 0.8551 | 0.8778 |
| Gradient-Boosted Trees | 84.61% | 87.19% | 82.04% | 84.54% | 0.9261 | 0.9356 |
| Character TF-IDF + Logistic Regression | **90.96%** | **91.33%** | **91.02%** | **91.17%** | **0.9709** | **0.9755** |

Character-level TF-IDF with Logistic Regression achieved the highest performance across the reported clean-test metrics.

## Adversarial Robustness Evaluation

The models were tested against four URL manipulation techniques.

| Test | Gradient-Boosted Trees | Logistic Regression | Character TF-IDF + LR |
|---|---:|---:|---:|
| Digit substitution detection | 90.77% | 76.89% | 91.27% |
| Homoglyph detection | 79.47% | 66.83% | 57.94% |
| Typographical-change detection | 81.55% | 68.74% | 91.11% |
| Keyword stuffing on legitimate URLs (FPR) | 98.51% | 99.91% | 99.13% |

The experiments reveal that strong performance on clean URLs does not guarantee robustness against all manipulations. Homoglyph substitution reduced the detection rate of the character-level model, while keyword stuffing caused high false-positive rates across all three classifiers.

## Project Structure

```text
phishing-detection-adversarial-ml/
├── app/
├── backend/
├── frontend/
├── data/
├── models/
│   └── train_baseline.py
├── text_model/
│   ├── results/
│   ├── saved_model/
│   └── tfidf_phishing_model.py
├── article_results/
├── results/
├── evaluate_all_models.py
├── RUN_APP.md
└── README.md
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Thanushree-07/phishing-detection-adversarial-ml.git
cd phishing-detection-adversarial-ml
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

If a root `requirements.txt` is available:

```bash
python -m pip install -r requirements.txt
```

Otherwise, install the dependencies documented for the relevant project component.

### 4. Run the evaluation

Inspect the script configuration and ensure the required dataset files and saved models are available.

```bash
python evaluate_all_models.py
```

Refer to [`RUN_APP.md`](RUN_APP.md) for application-specific instructions.

## Limitations

- Evaluation uses a single stratified hold-out split.
- Robustness results cover only the tested URL manipulations.
- Keyword stuffing causes high false-positive rates on the tested legitimate URLs.
- Performance may differ on newer or independently collected phishing datasets.
- LLM-based classification and prompt-injection results are not included in the reported ML comparison.

## Future Work

- Evaluate on newer and independent URL datasets.
- Improve detection against homoglyph substitution and keyword stuffing.
- Investigate adversarial training and robust feature engineering.
- Evaluate LLM-based classification and prompt-injection defences.
- Test the application in realistic deployment environments.

## Responsible Use

This project is intended for academic research and defensive cybersecurity. Do not visit suspicious URLs merely to test them. Follow the original dataset licences and source-provider terms when using or redistributing URL data.

## Author

**Thanushree M.**

[GitHub Repository](https://github.com/Thanushree-07/phishing-detection-adversarial-ml)
