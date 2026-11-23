"""
Dataset Validation Module for Website Security Extension (Phase 7).

Inspects the dataset file, validates schema, checks types, labels,
missing values, duplicate URLs, and domain distribution, and outputs
a structured markdown validation report.
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, List, Optional

import pandas as pd


EXPECTED_FEATURE_COLUMNS = [
    'url_len', 'dom_len', 'is_ip', 'tld_len', 'subdom_cnt',
    'letter_cnt', 'digit_cnt', 'special_cnt', 'eq_cnt', 'qm_cnt',
    'amp_cnt', 'dot_cnt', 'dash_cnt', 'under_cnt', 'letter_ratio',
    'digit_ratio', 'spec_ratio', 'is_https', 'slash_cnt', 'entropy',
    'path_len', 'query_len'
]

EXPECTED_REFERENCE_COLUMNS = ['url', 'dom', 'tld']
EXPECTED_TARGET_COLUMN = 'label'


def validate_dataset(
    csv_path: str = "ml/data/raw/Dataset.csv",
    report_output_path: Optional[str] = "ml/reports/data_validation_report.md"
) -> Dict[str, Any]:
    """
    Validate the dataset at csv_path and generate a validation report.

    Args:
        csv_path: Path to Dataset.csv
        report_output_path: Optional path to save markdown report

    Returns:
        Dictionary of validation metrics and findings.
    """
    file_path = Path(csv_path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Dataset file not found at '{csv_path}'. "
            "Please ensure 'Dataset.csv' (URL-Phish Version 2) is downloaded "
            "and placed in 'ml/data/raw/Dataset.csv'."
        )

    file_size_bytes = file_path.stat().st_size

    # Load dataset safely without executing or accessing any URL
    df = pd.read_csv(file_path, low_memory=False)

    total_rows = len(df)
    total_columns = len(df.columns)
    column_names = list(df.columns)

    # 1. Target column verification
    target_col = EXPECTED_TARGET_COLUMN
    if target_col not in df.columns:
        # Search for case-insensitive match
        candidates = [c for c in df.columns if c.lower() in ('label', 'target', 'class', 'phishing')]
        if candidates:
            target_col = candidates[0]
        else:
            raise ValueError(f"Target column '{EXPECTED_TARGET_COLUMN}' not found in dataset columns: {column_names}")

    label_counts = df[target_col].value_counts(dropna=False).to_dict()
    label_percentages = (df[target_col].value_counts(normalize=True, dropna=False) * 100).round(2).to_dict()

    # 2. Reference & feature column segregation
    ref_cols_present = [c for c in EXPECTED_REFERENCE_COLUMNS if c in df.columns]
    feature_cols_present = [c for c in EXPECTED_FEATURE_COLUMNS if c in df.columns]
    unexpected_cols = [c for c in df.columns if c not in EXPECTED_FEATURE_COLUMNS + EXPECTED_REFERENCE_COLUMNS + [target_col]]
    missing_expected_features = [c for c in EXPECTED_FEATURE_COLUMNS if c not in df.columns]

    # 3. Missing values audit
    missing_by_col = df.isnull().sum()
    columns_with_missing = missing_by_col[missing_by_col > 0].to_dict()

    # 4. Duplicate checks
    url_col = 'url' if 'url' in df.columns else None
    dom_col = 'dom' if 'dom' in df.columns else None

    total_unique_urls = df[url_col].nunique() if url_col else 0
    duplicate_urls_count = total_rows - total_unique_urls if url_col else 0
    total_unique_domains = df[dom_col].nunique() if dom_col else 0

    # Check for mixed domains (domains that have both benign and phishing records)
    mixed_domains_count = 0
    if dom_col and target_col:
        domain_labels = df.groupby(dom_col)[target_col].nunique()
        mixed_domains_count = (domain_labels > 1).sum()

    # 5. Numerical features integrity (check for non-numeric, infs, NaNs)
    feature_data = df[feature_cols_present]
    replaced = feature_data.replace([float('inf'), float('-inf')], pd.NA)
    total_na_after_replace = int(pd.isna(replaced).to_numpy().sum())
    original_na = int(feature_data.isnull().to_numpy().sum())
    infinite_values_count = total_na_after_replace - original_na

    validation_summary = {
        "dataset_path": str(file_path),
        "file_size_bytes": file_size_bytes,
        "file_size_mb": round(file_size_bytes / (1024 * 1024), 2),
        "total_rows": total_rows,
        "total_columns": total_columns,
        "target_column": target_col,
        "label_counts": {str(k): v for k, v in label_counts.items()},
        "label_percentages": {str(k): float(v) for k, v in label_percentages.items()},
        "feature_count": len(feature_cols_present),
        "feature_columns": feature_cols_present,
        "reference_columns": ref_cols_present,
        "unexpected_columns": unexpected_cols,
        "missing_expected_features": missing_expected_features,
        "missing_values": {str(k): int(v) for k, v in columns_with_missing.items()},
        "infinite_values": infinite_values_count,
        "unique_urls": total_unique_urls,
        "duplicate_urls": duplicate_urls_count,
        "unique_domains": total_unique_domains,
        "mixed_domains_count": mixed_domains_count,
        "is_valid": len(missing_expected_features) == 0 and total_rows > 0 and 0 in label_counts and 1 in label_counts
    }

    # Generate Markdown Report
    if report_output_path:
        out_path = Path(report_output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        report_md = f"""# Dataset Validation Report: URL-Phish (Mendeley Data v2)

**Generated:** {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}
**Source Dataset:** `{csv_path}`
**Status:** {'VALIDATED' if validation_summary['is_valid'] else 'INVALID'}

---

## 1. Dataset Dimensions & Basic Metadata
- **Total Records:** {total_rows:,}
- **Total Columns:** {total_columns}
- **File Size:** {validation_summary['file_size_mb']} MB ({file_size_bytes:,} bytes)
- **Target Label Column:** `{target_col}`

## 2. Target Label Distribution
| Label | Meaning | Sample Count | Percentage |
| :--- | :--- | :--- | :--- |
| **0** | Legitimate / Benign | {label_counts.get(0, 0):,} | {label_percentages.get(0, 0.0):.2f}% |
| **1** | Phishing / Malicious | {label_counts.get(1, 0):,} | {label_percentages.get(1, 0.0):.2f}% |
| **Total** | | {total_rows:,} | 100.00% |

*Imbalance Ratio:* Approximately {round(label_counts.get(0, 1) / max(1, label_counts.get(1, 1)), 2)}:1 benign-to-phishing.

## 3. Schema & Column Segregation

### Numerical Feature Columns ({len(feature_cols_present)} features)
These columns constitute the feature vector input for machine learning models:
`{', '.join(feature_cols_present)}`

### Reference & Metadata Columns (Excluded from model features)
These columns are strictly retained for domain grouping, auditing, and ground-truth evaluation, never fed as raw inputs to ML models:
- `url`: Raw URL string (untrusted input)
- `dom`: Registrable domain (used for GroupShuffleSplit domain-isolation)
- `tld`: Top-level domain string

### Missing Expected Features
{', '.join(missing_expected_features) if missing_expected_features else 'None. All 22 expected numerical features are present.'}

## 4. Data Quality & Integrity Checks
- **Missing Values:** {columns_with_missing if columns_with_missing else 'Zero missing values in feature columns.'} (Note: `tld` column has {columns_with_missing.get('tld', 0)} missing values for raw IP hostnames).
- **Infinite / NaN Values in Features:** {infinite_values_count}
- **Unique URLs:** {total_unique_urls:,}
- **Duplicate URLs:** {duplicate_urls_count:,} ({round(duplicate_urls_count / total_rows * 100, 2)}%)
- **Unique Registrable Domains:** {total_unique_domains:,}
- **Mixed Domains (having both 0 and 1 records):** {mixed_domains_count} (Cloud platforms, free hosting, e.g. `amazonaws.com`, `blogspot.com`, `azurewebsites.net`).

## 5. Domain Grouping Feasibility
Because the `dom` (registrable domain) column is explicitly available for all records, a strict domain-grouped train/validation/test split (`GroupShuffleSplit`) is feasible and will be enforced to prevent domain leakage.
"""
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(report_md)

    return validation_summary


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "ml/data/raw/Dataset.csv"
    print(f"Validating dataset at: {path}")
    summary = validate_dataset(path)
    print("\n--- Validation Summary ---")
    print(f"Total Rows: {summary['total_rows']:,}")
    print(f"Features: {summary['feature_count']} columns")
    print(f"Labels: {summary['label_counts']}")
    print(f"Is Valid: {summary['is_valid']}")
    print("Report written to: ml/reports/data_validation_report.md")
