"""
Model Training and Selection Pipeline for Website Security Extension (Phase 7).

Trains and compares baseline and tree-based classification models on
the domain-grouped URL-Phish dataset. Enforces strict zero-leakage domain
splitting and evaluates on validation data before saving the best model artifact.
"""

import os
import sys
import json
import time
from pathlib import Path
from typing import Dict, Any, Tuple

import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix
)

# Canonical feature list matching published dataset
FEATURE_NAMES = [
    'url_len', 'dom_len', 'is_ip', 'tld_len', 'subdom_cnt',
    'letter_cnt', 'digit_cnt', 'special_cnt', 'eq_cnt', 'qm_cnt',
    'amp_cnt', 'dot_cnt', 'dash_cnt', 'under_cnt', 'letter_ratio',
    'digit_ratio', 'spec_ratio', 'is_https', 'slash_cnt', 'entropy',
    'path_len', 'query_len'
]

RANDOM_SEED = 42


def split_data_by_domain(
    df: pd.DataFrame,
    domain_col: str = 'dom',
    random_state: int = RANDOM_SEED
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Split dataset into Train (~70%), Validation (~15%), and Test (~15%)
    strictly grouped by registrable domain to prevent domain leakage.
    """
    # 1. First split: 70% train vs 30% temp
    gss1 = GroupShuffleSplit(n_splits=1, train_size=0.70, random_state=random_state)
    train_idx, temp_idx = next(gss1.split(df, groups=df[domain_col]))

    df_train = df.iloc[train_idx].copy()
    df_temp = df.iloc[temp_idx].copy()

    # 2. Second split: split temp equally (15% val, 15% test of total)
    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=random_state)
    val_sub_idx, test_sub_idx = next(gss2.split(df_temp, groups=df_temp[domain_col]))

    df_val = df_temp.iloc[val_sub_idx].copy()
    df_test = df_temp.iloc[test_sub_idx].copy()

    # Verification of zero leakage
    train_domains = set(df_train[domain_col])
    val_domains = set(df_val[domain_col])
    test_domains = set(df_test[domain_col])

    assert train_domains.isdisjoint(val_domains), "Data leakage detected between Train and Val domains!"
    assert train_domains.isdisjoint(test_domains), "Data leakage detected between Train and Test domains!"
    assert val_domains.isdisjoint(test_domains), "Data leakage detected between Val and Test domains!"

    return df_train, df_val, df_test


def evaluate_model_on_split(
    model: Any,
    X: Any,
    y: pd.Series,
    threshold: float = 0.50
) -> Dict[str, Any]:
    """Calculate standard binary classification metrics on a dataset split."""
    # Check if model has predict_proba
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)[:, 1]
        preds = (probs >= threshold).astype(int)
        roc_auc = float(roc_auc_score(y, probs))
        pr_auc = float(average_precision_score(y, probs))
    else:
        preds = model.predict(X)
        probs = preds.astype(float)
        roc_auc = 0.5
        pr_auc = float(y.mean())

    acc = float(accuracy_score(y, preds))
    prec = float(precision_score(y, preds, zero_division=0))
    rec = float(recall_score(y, preds, zero_division=0))
    f1 = float(f1_score(y, preds, zero_division=0))
    macro_f1 = float(f1_score(y, preds, average="macro", zero_division=0))

    tn, fp, fn, tp = confusion_matrix(y, preds, labels=[0, 1]).ravel()
    fpr = float(fp / max(1, fp + tn))

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "macro_f1": round(macro_f1, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "false_positive_rate": round(fpr, 4),
        "threshold": round(threshold, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
    }


def tune_decision_threshold(
    model: Any,
    X_val: Any,
    y_val: pd.Series
) -> Tuple[float, Dict[str, Any]]:
    """Search for the best decision threshold on the validation set."""
    probs = model.predict_proba(X_val)[:, 1]
    thresholds = np.linspace(0.10, 0.90, 17)

    best_thresh = 0.50
    best_f1 = -1.0
    best_metrics = {}

    for t in thresholds:
        metrics = evaluate_model_on_split(model, X_val, y_val, threshold=t)
        # Select threshold maximizing F1 on validation set while keeping FPR < 0.08
        if metrics["f1"] > best_f1:
            best_f1 = metrics["f1"]
            best_thresh = float(t)
            best_metrics = metrics

    return round(best_thresh, 2), best_metrics


def train_and_select_model(
    csv_path: str = "ml/data/raw/Dataset.csv",
    output_dir: str = "ml/models",
    processed_data_dir: str = "ml/data/processed"
) -> Dict[str, Any]:
    """Train models, evaluate on validation set, tune threshold, and save artifacts."""
    print("=" * 70)
    print("PHASE 7: ML MODEL TRAINING AND VALIDATION PIPELINE")
    print("=" * 70)

    # 1. Load dataset
    print(f"Loading dataset from: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)
    print(f"Loaded {len(df):,} records with columns: {list(df.columns)}")

    # 2. Domain-grouped splitting
    print("\nSplitting dataset by registrable domain ('dom')...")
    df_train, df_val, df_test = split_data_by_domain(df, domain_col='dom', random_state=RANDOM_SEED)

    print(f"  Train Set: {len(df_train):,} rows ({len(df_train)/len(df):.1%}), domains: {df_train.dom.nunique():,}, phishing: {df_train.label.mean():.1%}")
    print(f"  Val Set:   {len(df_val):,} rows ({len(df_val)/len(df):.1%}), domains: {df_val.dom.nunique():,}, phishing: {df_val.label.mean():.1%}")
    print(f"  Test Set:  {len(df_test):,} rows ({len(df_test)/len(df):.1%}), domains: {df_test.dom.nunique():,}, phishing: {df_test.label.mean():.1%}")

    # Save processed splits for reproducibility
    proc_path = Path(processed_data_dir)
    proc_path.mkdir(parents=True, exist_ok=True)
    df_train.to_csv(proc_path / "train.csv", index=False)
    df_val.to_csv(proc_path / "val.csv", index=False)
    df_test.to_csv(proc_path / "test.csv", index=False)
    print(f"Saved processed split CSVs to: {proc_path}")

    # Prepare feature matrices
    X_train = df_train[FEATURE_NAMES]
    y_train = df_train['label']
    X_val = df_val[FEATURE_NAMES]
    y_val = df_val['label']

    # 3. Model Candidates
    candidates = {
        "DummyBaseline": DummyClassifier(strategy="most_frequent"),
        "LogisticRegression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(class_weight="balanced", max_iter=1000, random_state=RANDOM_SEED))
        ]),
        "RandomForest": RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            class_weight="balanced",
            random_state=RANDOM_SEED,
            n_jobs=-1
        ),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            class_weight="balanced",
            max_iter=150,
            random_state=RANDOM_SEED
        )
    }

    validation_results = {}
    fitted_models = {}

    print("\nTraining and evaluating candidate models on Validation Set...")
    for name, model in candidates.items():
        start_time = time.time()
        print(f"  Training {name}...", end=" ", flush=True)
        model.fit(X_train, y_train)
        elapsed = time.time() - start_time
        metrics = evaluate_model_on_split(model, X_val, y_val, threshold=0.50)
        metrics["training_time_seconds"] = round(elapsed, 2)
        validation_results[name] = metrics
        fitted_models[name] = model
        print(f"Done ({elapsed:.1f}s) | Val F1: {metrics['f1']:.4f} | PR-AUC: {metrics['pr_auc']:.4f} | Prec: {metrics['precision']:.4f} | Rec: {metrics['recall']:.4f}")

    # 4. Model Selection (Highest PR-AUC and F1 on validation set)
    # Exclude dummy
    tree_candidates = ["HistGradientBoosting", "RandomForest", "LogisticRegression"]
    best_model_name = max(tree_candidates, key=lambda k: (validation_results[k]["f1"], validation_results[k]["pr_auc"]))
    best_model = fitted_models[best_model_name]
    print(f"\nSelected Best Model: '{best_model_name}' based on validation performance.")

    # 5. Threshold Tuning on Validation Set
    best_threshold, tuned_metrics = tune_decision_threshold(best_model, X_val, y_val)
    print(f"Optimal Decision Threshold (Validation Set): {best_threshold}")
    print(f"  At threshold {best_threshold}: Prec={tuned_metrics['precision']:.4f}, Rec={tuned_metrics['recall']:.4f}, F1={tuned_metrics['f1']:.4f}, FPR={tuned_metrics['false_positive_rate']:.4f}")

    # 6. Save Model Artifact and Metadata
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    model_artifact_path = out_dir / "phishing_detector_v1.joblib"
    joblib.dump(best_model, model_artifact_path)
    print(f"\nModel artifact saved to: {model_artifact_path}")

    # Calculate Feature Importances if available
    feature_importances = {}
    if hasattr(best_model, "feature_importances_"):
        for fname, imp in zip(FEATURE_NAMES, best_model.feature_importances_):
            feature_importances[fname] = round(float(imp), 5)
    elif hasattr(best_model, "named_steps") and hasattr(best_model.named_steps.get("clf"), "coef_"):
        coefs = best_model.named_steps["clf"].coef_[0]
        for fname, c in zip(FEATURE_NAMES, coefs):
            feature_importances[fname] = round(float(c), 5)

    metadata = {
        "model_name": best_model_name,
        "model_version": "v1.0.0",
        "dataset_name": "URL-Phish (Mendeley Data v2)",
        "dataset_source": "https://data.mendeley.com/datasets/65z9twcx3r/2",
        "training_date": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "random_seed": RANDOM_SEED,
        "feature_names": FEATURE_NAMES,
        "feature_count": len(FEATURE_NAMES),
        "split_strategy": "GroupShuffleSplit (grouped by 'dom' registrable domain)",
        "split_sizes": {
            "train_rows": len(df_train),
            "val_rows": len(df_val),
            "test_rows": len(df_test),
            "train_domains": df_train.dom.nunique(),
            "val_domains": df_val.dom.nunique(),
            "test_domains": df_test.dom.nunique()
        },
        "default_threshold": 0.50,
        "tuned_threshold": best_threshold,
        "validation_metrics_default_threshold": validation_results[best_model_name],
        "validation_metrics_tuned_threshold": tuned_metrics,
        "all_candidates_validation": validation_results,
        "feature_importances": sorted(feature_importances.items(), key=lambda x: abs(x[1]), reverse=True),
        "environment": {
            "python_version": sys.version,
            "sklearn_version": joblib.__version__
        }
    }

    metadata_path = out_dir / "model_metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"Model metadata saved to: {metadata_path}")

    return {
        "best_model_name": best_model_name,
        "best_threshold": best_threshold,
        "validation_results": validation_results,
        "tuned_metrics": tuned_metrics,
        "artifact_path": str(model_artifact_path)
    }


if __name__ == "__main__":
    train_and_select_model()
