# Machine Learning Phishing URL Detection Engine (Phase 8 Complete)

**Module:** Website Security Extension — ML Phishing Classifier
**Status:** Phase 8 Complete & Validated (V2 40-Feature Schema, Ablation, Held-Out Test Evaluated)
**Date:** November 2026
**License / Attribution:** Based on [URL-Phish Dataset, Mendeley Data, Version 2](https://data.mendeley.com/datasets/65z9twcx3r/2)

---

## 1. Executive Overview

This module implements an offline, lexical machine-learning model that classifies URLs into:
- **`0` = Legitimate / Benign**
- **`1` = Phishing / Malicious**

### Scope Boundary Notice
**This module is strictly for dataset preparation, offline feature extraction, model training, ablation experimentation, held-out evaluation, and documentation.**
In accordance with project security requirements, the ML model remains isolated in `ml/` and is **not called from or integrated into the production FastAPI backend or Chrome Extension popup in this phase**.

---

## 2. Phase 8 V2 Achievements vs Phase 7 Baseline

| Metric | Phase 7 Baseline (V1) | Phase 8 Extended (V2) | Gain / Difference |
| :--- | :---: | :---: | :--- |
| **Feature Count** | 22 lexical features | **40 features** (+18 extended) | +81.8% feature depth |
| **Selected Model** | HistGradientBoosting (400 KB) | HistGradientBoosting (**525 KB**) | Compact, fast (<7 ms) |
| **Operating Threshold** | $\tau = 0.80$ | **$\tau = 0.95$** (tuned on val) | Optimized for low FPR |
| **Held-Out Test ROC-AUC** | 0.9901 | **0.9955** | **+0.0054 (Strictly superior)** |
| **Held-Out Test PR-AUC** | 0.9716 | **0.9868** | **+0.0152 (+1.52% gain)** |
| **Held-Out Test Precision**| 95.00% | **98.60%** | **+3.60% absolute gain** |
| **Held-Out Test FPR** | 0.0140 (215 false alarms) | **0.0036 (55 false alarms)** | **74.4% fewer false alarms** |
| **Recall at Matched $\tau=0.80$**| 86.31% | **93.98%** | **+7.67% gain (363 more attacks detected)** |
| **Brier Score Calibration**| 0.0327 | **0.0211** | **Substantially better calibrated** |
| **Full Report** | `ml/reports/model_evaluation_report.md` | `docs/PHASE_8_FINAL_REPORT.md` | Comprehensive documentation |

---

## 3. Directory Layout

```
ml/
├── data/
│   ├── raw/
│   │   └── Dataset.csv              # Original 116,600-row dataset (gitignored)
│   └── processed/
│       ├── train.csv                # V1 train set (78,028 rows, 63,601 unseen domains)
│       ├── val.csv                  # V1 val set (18,528 rows, 13,629 unseen domains)
│       ├── test.csv                 # V1 test set (20,044 rows, 13,630 unseen domains)
│       ├── train_v2.csv             # V2 train set (40 numerical features + metadata)
│       ├── val_v2.csv               # V2 val set (40 numerical features + metadata)
│       └── test_v2.csv              # V2 test set (computed post-tuning, zero leakage)
├── models/
│   ├── phishing_detector_v1.joblib  # V1 HistGradientBoosting model (409 KB)
│   ├── model_metadata.json          # V1 model metadata & schema
│   └── experiments/
│       ├── best_model_v2.joblib     # V2 HistGradientBoosting model (525 KB, 40 feats)
│       ├── best_model_v2_metadata.json # V2 metadata, tuned threshold & validation stats
│       ├── ablation_results.json    # A1-A5 feature ablation experimental metrics
│       ├── dataset_audit.json       # Formal dataset quality & distribution audit
│       ├── hybrid_evaluation_results.json # Multi-strategy offline evaluation metrics
│       ├── hybrid_comparison.png    # Strategy comparison visualization
│       └── phase8_summary.json      # Machine-readable Phase 8 final summary
├── reports/
│   ├── data_validation_report.md    # Dataset audit report
│   ├── model_evaluation_report.md   # Phase 7 evaluation report
│   ├── confusion_matrix.png         # Diagnostic visual artifacts
│   ├── roc_pr_curve.png
│   ├── feature_importance.png
│   └── calibration_curve.png
├── src/
│   ├── __init__.py
│   ├── validate_dataset.py          # Dataset schema and integrity validator
│   ├── url_features.py              # V1 offline lexical feature extractor (22 features)
│   ├── url_features_v2.py           # V2 extended feature extractor (40 features)
│   ├── prepare_test_v2.py           # Held-out test set V2 feature computation
│   ├── train.py                     # V1 training script
│   ├── experiments.py               # Phase 8 ablation, audit & tuning framework
│   ├── evaluate.py                  # Evaluation on held-out test data
│   ├── hybrid_evaluation.py         # Multi-strategy hybrid framework & proxy simulation
│   └── predict.py                   # Isolated CLI & Python prediction interface
├── tests/
│   ├── test_validate_dataset.py     # Dataset validation unit tests
│   ├── test_url_features.py         # V1 feature extraction tests
│   ├── test_url_features_v2.py      # V2 extended feature extraction tests (54 tests)
│   ├── test_model_pipeline.py       # Pipeline, domain split & artifact tests
│   ├── test_hybrid_evaluation.py    # Hybrid framework & proxy score tests (19 tests)
│   └── test_phase8_validation.py    # Final Phase 8 validation & contract tests (13 tests)
├── requirements-ml.txt              # ML library dependencies
└── README.md                        # This documentation
```

---

## 4. Feature Schemas

### V1 Baseline Schema (22 Features)
`url_len`, `dom_len`, `is_ip`, `tld_len`, `subdom_cnt`, `letter_cnt`, `digit_cnt`, `special_cnt`, `eq_cnt`, `qm_cnt`, `amp_cnt`, `dot_cnt`, `dash_cnt`, `under_cnt`, `letter_ratio`, `digit_ratio`, `spec_ratio`, `is_https`, `slash_cnt`, `entropy`, `path_len`, `query_len`.

### V2 Extended Schema (40 Features = 22 V1 + 18 New)
- **URL Encoding & Structure:** `pct_encoded_ratio`, `double_encoded`, `at_symbol`, `has_fragment`, `path_segment_count`, `max_path_segment_len`, `query_param_count`, `max_query_val_len`.
- **Hostname Structure:** `hostname_len`, `longest_label_len`, `hostname_digit_ratio`, `hostname_entropy`, `hyphen_in_dom`, `subdomain_len`, `punycode_present`, `label_count`.
- **Credential-Target Lexical Signals:** `login_word_in_host`, `login_word_in_path`.

---

## 5. Exact PowerShell Commands

All commands run inside the virtual environment `.\backend\venv\Scripts\python.exe`.

### 1. Compute V2 Features on Test Set
```powershell
.\backend\venv\Scripts\python.exe ml/src/prepare_test_v2.py
```

### 2. Run Experiments & Ablation
```powershell
.\backend\venv\Scripts\python.exe ml/src/experiments.py
```

### 3. Run Hybrid Evaluation Framework
```powershell
.\backend\venv\Scripts\python.exe ml/src/hybrid_evaluation.py
```

### 4. Run Local Offline URL Prediction
```powershell
# Benign sample
.\backend\venv\Scripts\python.exe ml/src/predict.py "https://www.google.com"

# Phishing sample
.\backend\venv\Scripts\python.exe ml/src/predict.py "https://pay.pagcorefeiraosetembro.site/2wq7Gr7zmL8gBAN?utm_source=organic"
```

### 5. Run Test Suites
```powershell
# Run ML unit tests (101 tests)
.\backend\venv\Scripts\python.exe -m pytest -q ml/tests

# Run complete test suite (258 tests)
.\backend\venv\Scripts\python.exe -m pytest -q backend/tests ml/tests
```

---

## 6. Hybrid Architecture Status & Documentation

For the complete technical report, empirical ablation details, error analysis, and Phase 9 integration roadmap, see:
**[`docs/PHASE_8_FINAL_REPORT.md`](../docs/PHASE_8_FINAL_REPORT.md)**
