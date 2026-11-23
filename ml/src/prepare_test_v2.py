"""
Test-Set V2 Feature Computation Script.

Computes v2 features for the held-out test set AFTER all model selection,
feature selection, and threshold tuning is complete.

This script must only be run AFTER experiments.py has completed, to ensure
no test-set information influenced any upstream decisions.
"""

from pathlib import Path
import sys

_ML_DIR = Path(__file__).resolve().parent.parent

def compute_test_v2_features():
    """Compute v2 features for the test split and save as test_v2.csv."""
    sys.path.insert(0, str(_ML_DIR / "src"))
    from url_features_v2 import extract_url_features_v2, FEATURE_NAMES_V2_NEW

    import pandas as pd

    test_csv = _ML_DIR / "data" / "processed" / "test.csv"
    test_v2_csv = _ML_DIR / "data" / "processed" / "test_v2.csv"

    if test_v2_csv.exists():
        print(f"test_v2.csv already exists at {test_v2_csv}. Delete it to recompute.")
        return

    if not test_csv.exists():
        print(f"test.csv not found at {test_csv}.")
        return

    print(f"Loading test set from {test_csv} ...")
    df = pd.read_csv(test_csv)
    print(f"Computing v2 features for {len(df):,} test rows (ZERO network requests) ...")

    records = []
    for i, url in enumerate(df['url']):
        try:
            feats = extract_url_features_v2(str(url), schema_version="v2_extended")
            records.append({k: feats.get(k, 0.0) for k in FEATURE_NAMES_V2_NEW})
        except Exception:
            records.append({k: 0.0 for k in FEATURE_NAMES_V2_NEW})
        if (i + 1) % 5000 == 0:
            print(f"  Processed {i + 1:,} / {len(df):,} rows...")

    v2_df = pd.DataFrame(records)
    df_out = pd.concat([df.reset_index(drop=True), v2_df], axis=1)
    df_out.to_csv(test_v2_csv, index=False)
    print(f"Saved {len(df_out):,} rows to {test_v2_csv}")
    print("NOTE: This file should only be used for final evaluation, not for model selection.")


if __name__ == "__main__":
    compute_test_v2_features()
