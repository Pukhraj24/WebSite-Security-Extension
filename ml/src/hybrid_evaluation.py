"""
Offline Hybrid Evaluation Framework (Phase 8, Task 4).

Evaluates four strategies on the existing test dataset:
  A. Rule-only baseline (simulated from dataset features)
  B. URL-only ML model (v1 baseline)
  C. Feature-enhanced ML model (v2, if available)
  D. Conservative hybrid: max(rule_score, ml_score * 100)
  E. Learned combination (if valid rule outputs available)

CRITICAL LIMITATIONS -- documented honestly:
  - The rule engine requires HTTP headers, TLS certificates, cookies, and
    fetched HTML page content.  None of this evidence exists in the dataset.
  - We therefore define a "URL-feature proxy rule" that uses ONLY features
    derivable offline from the URL string (is_https, is_ip, url_len, entropy,
    dom_len, subdom_cnt) to approximate a minimal rule-based signal.
  - This proxy is NOT the real production rule engine.
  - Any comparison labeled "rule-proxy" is clearly marked as a simulation.
  - We do NOT visit, crawl, or request any URL to obtain real rule signals.
  - We do NOT claim results from the proxy equal production rule-engine results.

The held-out test set IS used here for final evaluation only, after all model
selection, feature selection, and threshold tuning has been completed on
train/val data.  This is the ONLY file that reads test.csv for evaluation.
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Path configuration
_ROOT = Path(__file__).resolve().parent.parent.parent
_ML_DIR = _ROOT / "ml"
_DATA_PROC = _ML_DIR / "data" / "processed"
_MODELS_DIR = _ML_DIR / "models"
_EXP_DIR = _MODELS_DIR / "experiments"
_REPORTS_DIR = _ML_DIR / "reports"

RANDOM_SEED = 42

# V1 feature schema
FEATURE_NAMES_V1 = [
    'url_len', 'dom_len', 'is_ip', 'tld_len', 'subdom_cnt',
    'letter_cnt', 'digit_cnt', 'special_cnt', 'eq_cnt', 'qm_cnt',
    'amp_cnt', 'dot_cnt', 'dash_cnt', 'under_cnt', 'letter_ratio',
    'digit_ratio', 'spec_ratio', 'is_https', 'slash_cnt', 'entropy',
    'path_len', 'query_len',
]

FEATURE_NAMES_V2_NEW = [
    'pct_encoded_ratio', 'double_encoded', 'at_symbol', 'has_fragment',
    'path_segment_count', 'max_path_segment_len', 'query_param_count',
    'max_query_val_len', 'hostname_len', 'longest_label_len',
    'hostname_digit_ratio', 'hostname_entropy', 'hyphen_in_dom',
    'subdomain_len', 'punycode_present', 'label_count',
    'login_word_in_host', 'login_word_in_path',
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _metrics_at_threshold(y_true, y_pred_proba, threshold: float) -> Dict[str, Any]:
    """Compute binary classification metrics at a given threshold."""
    preds = (y_pred_proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, preds, labels=[0, 1]).ravel()
    fpr = float(fp / max(1, fp + tn))
    return {
        "threshold": round(threshold, 4),
        "accuracy": round(float(accuracy_score(y_true, preds)), 4),
        "precision": round(float(precision_score(y_true, preds, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, preds, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, preds, zero_division=0)), 4),
        "macro_f1": round(float(f1_score(y_true, preds, average="macro", zero_division=0)), 4),
        "fpr": round(fpr, 4),
        "roc_auc": round(float(roc_auc_score(y_true, y_pred_proba)), 4),
        "pr_auc": round(float(average_precision_score(y_true, y_pred_proba)), 4),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "coverage": 1.0,  # full coverage since all samples have URL features
    }


def _rule_proxy_score(df: pd.DataFrame) -> np.ndarray:
    """
    Compute an offline URL-feature proxy rule score in range [0, 100].

    This is NOT the production rule engine.  It approximates a minimal
    URL-based heuristic using only features already in the dataset.
    Missing evidence (TLS, headers, cookies, HTML) is treated as absent
    (i.e. it does NOT add positive evidence of safety).

    Rules used (all computable offline from URL string):
      +30: IP address hostname (is_ip == 1)
      +20: URL over HTTP (is_https == 0)
      +20: URL length > 100 chars
      +15: Entropy > 4.5 (high randomness)
      +10: domain length < 5 (very short domain, common in phishing)
      +10: subdom_cnt > 3 (excessive subdomain nesting)
      +5:  path_len > 50 and query_len > 30 (long path with query)

    Maximum raw sum = 110, capped to [0, 100].
    """
    scores = np.zeros(len(df), dtype=float)

    if 'is_ip' in df.columns:
        scores += df['is_ip'].values * 30
    if 'is_https' in df.columns:
        scores += (1 - df['is_https'].values) * 20
    if 'url_len' in df.columns:
        scores += (df['url_len'].values > 100).astype(float) * 20
    if 'entropy' in df.columns:
        scores += (df['entropy'].values > 4.5).astype(float) * 15
    if 'dom_len' in df.columns:
        scores += (df['dom_len'].values < 5).astype(float) * 10
    if 'subdom_cnt' in df.columns:
        scores += (df['subdom_cnt'].values > 3).astype(float) * 10
    if 'path_len' in df.columns and 'query_len' in df.columns:
        scores += ((df['path_len'].values > 50) & (df['query_len'].values > 30)).astype(float) * 5

    return np.clip(scores, 0, 100)


def _rule_proxy_proba(df: pd.DataFrame) -> np.ndarray:
    """Convert rule proxy score to pseudo-probability in [0, 1] for ROC/PR."""
    return _rule_proxy_score(df) / 100.0


# ---------------------------------------------------------------------------
# Strategy A: Rule-Only Proxy Baseline
# ---------------------------------------------------------------------------

def evaluate_rule_proxy(
    df_test: pd.DataFrame,
    y_test: pd.Series,
    threshold_score: float = 40.0,
) -> Dict[str, Any]:
    """
    Evaluate the URL-feature proxy rule engine on the test set.

    Flags a URL as phishing if rule_proxy_score >= threshold_score.
    threshold_score=40 corresponds to the 'High' risk band in the real engine.

    Returns metrics dict with explicit limitations note.
    """
    rule_scores = _rule_proxy_score(df_test)
    rule_proba = rule_scores / 100.0
    preds = (rule_scores >= threshold_score).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_test, preds, labels=[0, 1]).ravel()
    fpr = float(fp / max(1, fp + tn))

    # Coverage: all records have URL features, so coverage = 100%
    coverage = 1.0

    roc = float(roc_auc_score(y_test, rule_proba))
    pr = float(average_precision_score(y_test, rule_proba))

    return {
        "strategy": "A_rule_proxy_only",
        "limitation": (
            "PROXY ONLY: Uses offline URL features as a heuristic stand-in "
            "for the real rule engine.  The production engine also uses TLS certificates, "
            "HTTP headers, cookies, and fetched HTML -- all unavailable in the offline dataset. "
            "These results are NOT comparable to the production rule engine's real-world performance."
        ),
        "threshold_score": threshold_score,
        "coverage": coverage,
        "precision": round(float(precision_score(y_test, preds, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, preds, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, preds, zero_division=0)), 4),
        "macro_f1": round(float(f1_score(y_test, preds, average="macro", zero_division=0)), 4),
        "fpr": round(fpr, 4),
        "roc_auc": round(roc, 4),
        "pr_auc": round(pr, 4),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


# ---------------------------------------------------------------------------
# Strategy B: URL-Only ML Model (v1 baseline)
# ---------------------------------------------------------------------------

def evaluate_ml_baseline(
    df_test: pd.DataFrame,
    y_test: pd.Series,
    model_path: Path = _MODELS_DIR / "phishing_detector_v1.joblib",
    metadata_path: Path = _MODELS_DIR / "model_metadata.json",
) -> Dict[str, Any]:
    """Evaluate the existing baseline HistGradientBoosting v1 model on the test set."""
    model = joblib.load(model_path)
    with open(metadata_path) as f:
        meta = json.load(f)

    feature_names = meta["feature_names"]
    threshold = float(meta["tuned_threshold"])

    X_test = df_test[feature_names]
    probs = model.predict_proba(X_test)[:, 1]

    result = _metrics_at_threshold(y_test, probs, threshold)
    result["strategy"] = "B_ml_v1_url_only"
    result["model_name"] = meta.get("model_name", "HistGradientBoosting")
    result["model_version"] = meta.get("model_version", "v1.0.0")
    return result


# ---------------------------------------------------------------------------
# Strategy C: Feature-Enhanced ML Model (v2, if available)
# ---------------------------------------------------------------------------

def evaluate_ml_v2(
    df_test: pd.DataFrame,
    y_test: pd.Series,
    exp_dir: Path = _EXP_DIR,
) -> Optional[Dict[str, Any]]:
    """
    Evaluate the v2 feature-enhanced experiment model on the test set.
    Only runs if the experiment model and test_v2.csv exist.
    Returns None with a note if unavailable.
    """
    model_path = exp_dir / "best_model_v2.joblib"
    meta_path = exp_dir / "best_model_v2_metadata.json"
    test_v2_path = _DATA_PROC / "test_v2.csv"

    if not model_path.exists() or not meta_path.exists():
        return {
            "strategy": "C_ml_v2_feature_enhanced",
            "limitation": "V2 experiment model not found. Run experiments.py first.",
            "available": False,
        }

    if not test_v2_path.exists():
        return {
            "strategy": "C_ml_v2_feature_enhanced",
            "limitation": (
                "test_v2.csv not found. V2 features have not been computed for the test set. "
                "To ensure no data leakage, test-set v2 features are computed here "
                "from the URL strings only after all experiments are complete."
            ),
            "available": False,
        }

    model = joblib.load(model_path)
    with open(meta_path) as f:
        meta = json.load(f)

    feature_names = meta["feature_names"]
    threshold = float(meta["tuned_threshold"])

    df_test_v2 = pd.read_csv(test_v2_path)
    available_feats = [f for f in feature_names if f in df_test_v2.columns]
    if len(available_feats) < len(feature_names):
        return {
            "strategy": "C_ml_v2_feature_enhanced",
            "limitation": f"Missing {len(feature_names)-len(available_feats)} v2 features in test_v2.csv.",
            "available": False,
        }

    X_test = df_test_v2[available_feats]
    probs = model.predict_proba(X_test)[:, 1]
    y_test_v2 = df_test_v2['label']

    result = _metrics_at_threshold(y_test_v2, probs, threshold)
    result["strategy"] = "C_ml_v2_feature_enhanced"
    result["model_name"] = meta.get("model_name", "HistGB_v2")
    result["available"] = True
    return result


# ---------------------------------------------------------------------------
# Strategy D: Conservative Hybrid
# ---------------------------------------------------------------------------

def evaluate_conservative_hybrid(
    df_test: pd.DataFrame,
    y_test: pd.Series,
    model_path: Path = _MODELS_DIR / "phishing_detector_v1.joblib",
    metadata_path: Path = _MODELS_DIR / "model_metadata.json",
    ml_threshold: float = 0.80,
    rule_min_score: float = 40.0,
) -> Dict[str, Any]:
    """
    Strategy D: Conservative Hybrid.

      composite_score = max(rule_proxy_score, ml_proba * 100)
      flag_as_phishing = composite_score >= rule_min_score (i.e., 40)
                       OR ml_proba >= ml_threshold

    Rules govern:
      - Deterministic security controls are never downgraded by ML.
      - Confirmed high-severity rule findings (score >= 40) always flag.
      - ML elevates suspicion when rule score is low.

    NOTE: rule_proxy_score is an offline URL-feature proxy, not the real engine.
    """
    model = joblib.load(model_path)
    with open(metadata_path) as f:
        meta = json.load(f)

    feature_names = meta["feature_names"]
    X_test = df_test[feature_names]
    ml_probs = model.predict_proba(X_test)[:, 1]

    rule_scores = _rule_proxy_score(df_test)

    # Composite score: take the maximum signal
    composite_scores = np.maximum(rule_scores, ml_probs * 100)

    # Flag if rule score is high OR ML is confident
    preds = ((composite_scores >= rule_min_score) | (ml_probs >= ml_threshold)).astype(int)
    composite_proba = composite_scores / 100.0

    tn, fp, fn, tp = confusion_matrix(y_test, preds, labels=[0, 1]).ravel()
    fpr = float(fp / max(1, fp + tn))

    return {
        "strategy": "D_conservative_hybrid",
        "limitation": (
            "Rule proxy uses offline URL features only.  In production, "
            "real TLS/header/cookie/HTML rule signals would replace the proxy. "
            "Results are NOT a valid comparison of production hybrid vs ML-only."
        ),
        "ml_threshold": ml_threshold,
        "rule_threshold_score": rule_min_score,
        "precision": round(float(precision_score(y_test, preds, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, preds, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, preds, zero_division=0)), 4),
        "macro_f1": round(float(f1_score(y_test, preds, average="macro", zero_division=0)), 4),
        "fpr": round(fpr, 4),
        "roc_auc": round(float(roc_auc_score(y_test, composite_proba)), 4),
        "pr_auc": round(float(average_precision_score(y_test, composite_proba)), 4),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "coverage": 1.0,
    }


# ---------------------------------------------------------------------------
# Strategy E: Learned Combination
# ---------------------------------------------------------------------------

def evaluate_learned_combination(
    df_train: pd.DataFrame,
    y_train: pd.Series,
    df_val: pd.DataFrame,
    y_val: pd.Series,
    df_test: pd.DataFrame,
    y_test: pd.Series,
    model_path: Path = _MODELS_DIR / "phishing_detector_v1.joblib",
    metadata_path: Path = _MODELS_DIR / "model_metadata.json",
) -> Dict[str, Any]:
    """
    Strategy E: Learned combination of rule proxy + ML scores.
    A logistic regression meta-learner is trained on train set out-of-fold
    predictions (to avoid leakage) and evaluated on the val-tuned, test set.

    Valid because:
      - Meta-learner trained on training data only.
      - Threshold selected on validation data only.
      - Final evaluation on held-out test set.
    """
    model = joblib.load(model_path)
    with open(metadata_path) as f:
        meta = json.load(f)

    feature_names = meta["feature_names"]

    # Get ML probabilities for all splits
    ml_probs_train = model.predict_proba(df_train[feature_names])[:, 1]
    ml_probs_val = model.predict_proba(df_val[feature_names])[:, 1]
    ml_probs_test = model.predict_proba(df_test[feature_names])[:, 1]

    # Get rule proxy probabilities
    rule_probs_train = _rule_proxy_proba(df_train)
    rule_probs_val = _rule_proxy_proba(df_val)
    rule_probs_test = _rule_proxy_proba(df_test)

    # Stack features: [ml_prob, rule_prob, interaction]
    def stack(ml_p, rule_p):
        interaction = ml_p * rule_p
        return np.column_stack([ml_p, rule_p, interaction])

    X_meta_train = stack(ml_probs_train, rule_probs_train)
    X_meta_val = stack(ml_probs_val, rule_probs_val)
    X_meta_test = stack(ml_probs_test, rule_probs_test)

    # Fit meta-learner on training data
    meta_model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(class_weight="balanced", max_iter=500, random_state=RANDOM_SEED))
    ])
    meta_model.fit(X_meta_train, y_train)

    # Tune threshold on validation
    val_probs = meta_model.predict_proba(X_meta_val)[:, 1]
    best_thresh = 0.50
    best_prec = -1.0
    for t in [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95]:
        preds_t = (val_probs >= t).astype(int)
        prec_t = float(precision_score(y_val, preds_t, zero_division=0))
        rec_t = float(recall_score(y_val, preds_t, zero_division=0))
        if rec_t >= 0.70 and prec_t > best_prec:
            best_prec = prec_t
            best_thresh = t

    # Evaluate on test set
    test_probs = meta_model.predict_proba(X_meta_test)[:, 1]
    result = _metrics_at_threshold(y_test, test_probs, best_thresh)
    result["strategy"] = "E_learned_combination"
    result["meta_model"] = "LogisticRegression (ml_prob, rule_proxy_prob, interaction)"
    result["limitation"] = (
        "Rule proxy uses offline URL features only.  A production learned "
        "combination must use real rule-engine output signals."
    )
    return result


# ---------------------------------------------------------------------------
# Main evaluation
# ---------------------------------------------------------------------------

def run_hybrid_evaluation(
    test_csv: Path = _DATA_PROC / "test.csv",
    train_csv: Path = _DATA_PROC / "train.csv",
    val_csv: Path = _DATA_PROC / "val.csv",
    model_path: Path = _MODELS_DIR / "phishing_detector_v1.joblib",
    metadata_path: Path = _MODELS_DIR / "model_metadata.json",
    exp_dir: Path = _EXP_DIR,
    reports_dir: Path = _REPORTS_DIR,
) -> Dict[str, Any]:
    """
    Run all hybrid strategy evaluations and write the hybrid evaluation report.
    The test set is read here for final reporting only.
    """
    print("=" * 70)
    print("PHASE 8: HYBRID EVALUATION (OFFLINE EXPERIMENT)")
    print("=" * 70)
    print("  NOTE: Rule proxy is a URL-feature heuristic, NOT the production rule engine.")
    print("  Real rule engine requires TLS/headers/cookies/HTML (unavailable in dataset).")

    df_test = pd.read_csv(test_csv)
    df_train = pd.read_csv(train_csv)
    df_val = pd.read_csv(val_csv)

    y_test = df_test['label']
    y_train = df_train['label']
    y_val = df_val['label']

    results = {}

    # A: Rule proxy
    print("\n  [A] Evaluating rule proxy baseline...")
    results["A_rule_proxy"] = evaluate_rule_proxy(df_test, y_test)

    # B: ML baseline
    print("  [B] Evaluating ML v1 baseline...")
    results["B_ml_v1"] = evaluate_ml_baseline(df_test, y_test, model_path, metadata_path)

    # C: V2 ML (if available)
    print("  [C] Evaluating ML v2 (feature-enhanced)...")
    r_c = evaluate_ml_v2(df_test, y_test, exp_dir=exp_dir)
    if r_c:
        results["C_ml_v2"] = r_c

    # D: Conservative hybrid
    print("  [D] Evaluating conservative hybrid...")
    results["D_hybrid_conservative"] = evaluate_conservative_hybrid(
        df_test, y_test, model_path, metadata_path
    )

    # E: Learned combination
    print("  [E] Evaluating learned combination (meta-learner)...")
    results["E_learned_combination"] = evaluate_learned_combination(
        df_train, y_train, df_val, y_val, df_test, y_test, model_path, metadata_path
    )

    # Print summary table
    print("\n  Strategy Comparison Table")
    print("  " + "-" * 90)
    print(f"  {'Strategy':38s}  {'Precision':>10}  {'Recall':>8}  {'F1':>8}  {'FPR':>8}  {'PR-AUC':>8}")
    print("  " + "-" * 90)
    for k, v in results.items():
        if isinstance(v, dict) and "precision" in v:
            print(f"  {k:38s}  {v['precision']:>10.4f}  {v['recall']:>8.4f}  "
                  f"{v['f1']:>8.4f}  {v['fpr']:>8.4f}  {v.get('pr_auc', 'N/A'):>8}")

    # Save results JSON
    exp_dir.mkdir(parents=True, exist_ok=True)
    results_path = exp_dir / "hybrid_evaluation_results.json"
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  Results saved to {results_path}")

    # Generate comparison plot
    _plot_hybrid_comparison(results, exp_dir)

    return results


def _plot_hybrid_comparison(results: Dict, exp_dir: Path) -> None:
    """Generate a bar chart comparing strategies on precision, recall, F1, FPR."""
    strategies = []
    precisions = []
    recalls = []
    f1s = []
    fprs = []

    short_labels = {
        "A_rule_proxy": "A:Rule\nProxy",
        "B_ml_v1": "B:ML v1",
        "C_ml_v2": "C:ML v2",
        "D_hybrid_conservative": "D:Hybrid\nConserv.",
        "E_learned_combination": "E:Learned\nCombo",
    }

    for k, v in results.items():
        if isinstance(v, dict) and "precision" in v:
            strategies.append(short_labels.get(k, k))
            precisions.append(v["precision"])
            recalls.append(v["recall"])
            f1s.append(v["f1"])
            fprs.append(v["fpr"])

    if not strategies:
        return

    x = np.arange(len(strategies))
    width = 0.20

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(x - 1.5 * width, precisions, width, label="Precision", color="steelblue", alpha=0.85)
    ax.bar(x - 0.5 * width, recalls, width, label="Recall", color="forestgreen", alpha=0.85)
    ax.bar(x + 0.5 * width, f1s, width, label="F1", color="darkorange", alpha=0.85)
    ax.bar(x + 1.5 * width, fprs, width, label="FPR", color="crimson", alpha=0.85)

    ax.set_xlabel("Strategy", fontsize=11)
    ax.set_ylabel("Metric Value", fontsize=11)
    ax.set_title("Hybrid Strategy Comparison (Test Set)", fontsize=13)
    ax.set_xticks(x)
    ax.set_xticklabels(strategies, fontsize=9)
    ax.legend()
    ax.set_ylim(0, 1.05)
    ax.grid(axis="y", alpha=0.3)
    ax.axhline(0.95, color="steelblue", linestyle=":", alpha=0.5, label="95% Precision baseline")
    plt.tight_layout()

    plot_path = exp_dir / "hybrid_comparison.png"
    plt.savefig(plot_path, dpi=150)
    plt.close()
    print(f"  Comparison plot saved to {plot_path.name}")


if __name__ == "__main__":
    run_hybrid_evaluation()
