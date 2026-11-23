"""
Unit tests for Dataset Validation module (ml/src/validate_dataset.py).
"""

import os
import tempfile
from pathlib import Path
import pytest
import pandas as pd

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from validate_dataset import validate_dataset, EXPECTED_FEATURE_COLUMNS


def test_validate_real_dataset_if_present():
    """Verify that the real Dataset.csv validates successfully if present."""
    raw_path = Path("ml/data/raw/Dataset.csv")
    if not raw_path.exists():
        pytest.skip("Dataset.csv not found; skipping full dataset test.")

    summary = validate_dataset(str(raw_path), report_output_path="ml/reports/data_validation_report.md")
    assert summary["is_valid"] is True
    assert summary["total_rows"] == 116600
    assert summary["feature_count"] == 22
    assert "0" in summary["label_counts"]
    assert "1" in summary["label_counts"]
    assert summary["label_counts"]["0"] == 100000
    assert summary["label_counts"]["1"] == 16600
    assert Path("ml/reports/data_validation_report.md").exists()


def test_validate_dataset_missing_file_raises():
    """Verify that a non-existent path raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError) as exc_info:
        validate_dataset("non_existent_directory/missing.csv")
    assert "Dataset file not found" in str(exc_info.value)


def test_validate_dataset_missing_target_column():
    """Verify ValueError when target column is missing from CSV."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, newline="") as f:
        f.write("url,feature_a,feature_b\nhttp://example.com,1,2\n")
        tmp_name = f.name

    try:
        with pytest.raises(ValueError) as exc_info:
            validate_dataset(tmp_name, report_output_path=None)
        assert "Target column 'label' not found" in str(exc_info.value)
    finally:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)


def test_validate_dataset_detects_missing_expected_features():
    """Verify that missing expected features are flagged in summary."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, newline="") as f:
        f.write("url,dom,tld,label,url_len\nhttp://example.com,example.com,com,0,18\n")
        tmp_name = f.name

    try:
        summary = validate_dataset(tmp_name, report_output_path=None)
        assert summary["is_valid"] is False
        assert len(summary["missing_expected_features"]) > 0
        assert "entropy" in summary["missing_expected_features"]
        assert "is_ip" in summary["missing_expected_features"]
    finally:
        if os.path.exists(tmp_name):
            os.remove(tmp_name)
