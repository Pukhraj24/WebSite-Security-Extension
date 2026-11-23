# Machine Learning Model Evaluation Report (Phase 7)

**Model:** `HistGradientBoosting` (HistGradientBoostingClassifier)
**Dataset:** URL-Phish, Mendeley Data, Version 2
**Evaluation Protocol:** Strictly held-out test split, grouped by registrable domain (`dom`) with zero domain leakage
**Date:** 2026-10-27 18:38:32 UTC
**Target:** Binary Phishing Classification (`0 = Legitimate`, `1 = Phishing`)

---

## 1. Split Distribution & Zero-Leakage Guarantee

| Split | Records | Percentage | Registrable Domains | Phishing Prevalence | Domain Overlap with Test |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Train** | 78,028 | 66.9% | 63,601 | 10.6% | **0 (Zero)** |
| **Validation** | 18,528 | 15.9% | 13,629 | 19.4% | **0 (Zero)** |
| **Test (Held-Out)** | 20,044 | 17.2% | 13,630 | 23.6% | **0 (Zero)** |
| **Total** | 116,600 | 100.0% | 90,860 | 14.2% | N/A |

> [!IMPORTANT]
> **Data Leakage Safeguard:** All URLs belonging to the same registrable domain (e.g. `example.com`) were strictly assigned to the same partition. The test set comprises **13,630 completely unseen domains** that the model never encountered during training or threshold tuning.

---

## 2. Test Set Evaluation Metrics

### Comprehensive Performance Table

| Metric | Result (Default Threshold $\tau = 0.50$) | Result (Tuned Threshold $\tau = 0.80$) | Description / Impact on Product |
| :--- | :--- | :--- | :--- |
| **Accuracy** | 0.9570 | **0.9569** (95.69%) | Overall fraction of correct predictions across all classes. |
| **ROC-AUC** | **0.9901** | **0.9901** | Threshold-independent discrimination power across full range. |
| **PR-AUC (Avg Precision)** | **0.9716** | **0.9716** | Area under Precision-Recall curve (primary metric for imbalanced classes). |
| **Phishing Precision** | 0.8938 | **0.9500** (95.00%) | Fraction of flagged URLs that are genuine phishing threats. |
| **Phishing Recall** | 0.9284 | **0.8631** (86.31%) | Fraction of actual phishing attacks successfully detected. |
| **Phishing F1-Score** | 0.9108 | **0.9045** | Harmonic mean of phishing precision and recall. |
| **Macro-F1** | 0.9412 | **0.9383** | Unweighted average F1 across both benign and phishing classes. |
| **False Positive Rate (FPR)** | 0.0341 (3.41%) | **0.0140** (1.40%) | Benign sites falsely blocked (must remain low to avoid alert fatigue). |
| **Brier Score Calibration** | **0.0327** | **0.0327** | Mean squared difference between predicted probability and label. |

---

## 3. Detailed Confusion Matrix (Held-Out Test Set @ $\tau = 0.80$)

```
                      PREDICTED BENIGN (0)    PREDICTED PHISHING (1)
ACTUAL BENIGN (0)          15,095 (TN)              215 (FP)
ACTUAL PHISHING (1)          648 (FN)             4,086 (TP)
```

- **True Negatives (TN):** 15,095 legitimate websites correctly left unblocked.
- **False Positives (FP):** 215 legitimate websites mistakenly flagged (1.40% FPR).
- **False Negatives (FN):** 648 phishing attacks that bypassed detection.
- **True Positives (TP):** 4,086 phishing attacks successfully detected and blocked.

### Impact of False Positives on Browser Security Extension
In a consumer Chrome extension, **False Positives are far more damaging than in back-office threat hunting**. A false positive blocks users from legitimate banking, work, or e-commerce destinations, rapidly eroding trust and causing users to disable the extension. By tuning the threshold from $\tau = 0.50$ to $\tau = 0.80$, the False Positive Rate was lowered while maintaining a high **95.0% Precision** and **86.3% Recall** on previously unseen domains.

---

## 4. Per-Class Breakdown

| Class | Precision | Recall | F1-Score | Support |
| :--- | :--- | :--- | :--- | :--- |
| **0 (Legitimate / Benign)** | 0.9588 | 0.9860 | 0.9722 | 15,310 |
| **1 (Phishing / Malicious)** | 0.9500 | 0.8631 | 0.9045 | 4,734 |
| **Macro Average** | 0.9544 | 0.9245 | 0.9383 | 20,044 |
| **Weighted Average** | 0.9568 | 0.9569 | 0.9562 | 20,044 |

---

## 5. Permutation Feature Importances (Top 15)

| Rank | Feature Name | Mean Importance Decrease | Standard Deviation | Interpretation |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `dom_len` | 0.05700 | ±0.00268 |
| 2 | `path_len` | 0.04705 | ±0.00168 |
| 3 | `tld_len` | 0.01185 | ±0.00214 |
| 4 | `subdom_cnt` | 0.00610 | ±0.00077 |
| 5 | `dot_cnt` | 0.00545 | ±0.00099 |
| 6 | `dash_cnt` | 0.00530 | ±0.00127 |
| 7 | `entropy` | 0.00505 | ±0.00168 |
| 8 | `special_cnt` | 0.00460 | ±0.00083 |
| 9 | `slash_cnt` | 0.00200 | ±0.00088 |
| 10 | `letter_cnt` | 0.00155 | ±0.00107 |
| 11 | `query_len` | 0.00055 | ±0.00029 |
| 12 | `url_len` | 0.00035 | ±0.00070 |
| 13 | `eq_cnt` | 0.00035 | ±0.00034 |
| 14 | `under_cnt` | 0.00005 | ±0.00010 |
| 15 | `is_ip` | 0.00000 | ±0.00000 |

---

## 6. Generated Visual Artifacts

1. **Confusion Matrix Plot:** `ml/reports/confusion_matrix.png`
2. **ROC & Precision-Recall Curves:** `ml/reports/roc_pr_curve.png`
3. **Feature Importance Ranking:** `ml/reports/feature_importance.png`
4. **Reliability Diagram (Calibration):** `ml/reports/calibration_curve.png`

---

## 7. Model Calibration & Probability Meaning

- **Brier Score:** `0.0327` indicates well-calibrated probabilities on unseen domains.
- **Interpretation:** The raw `predict_proba()` output represents a monotonically increasing heuristic likelihood of phishing, but should **not** be presented to end users as an uncalibrated mathematical truth. The tuned threshold $\tau = 0.80$ serves as the operational high-confidence boundary.

---

## 8. Feasibility of Future Hybrid Integration (Rules + ML)

The evaluation proves that the ML model achieves **86.3% recall on zero-day domains** where rule-based heuristics alone might not trigger. However, the model should **augment rather than replace** the rule engine:
1. Hard security defects (expired certificates, unencrypted transport downgrade, SSRF link-local destinations) must remain deterministic rules.
2. The ML model acts as a secondary heuristic signal: when rule scores are low (e.g. 0–19), a high ML phishing score ($P \ge 0.80$) can elevate the assessment from Low to High/Critical, warning the user against sophisticated phishing pages hosted on valid HTTPS infrastructure.
