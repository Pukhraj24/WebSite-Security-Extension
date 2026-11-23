"""
Unit tests for Model Training, Splitting, and Prediction Pipeline (ml/tests/test_model_pipeline.py).
"""

from pathlib import Path
from unittest.mock import patch
import pytest
import pandas as pd
import numpy as np

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from train import split_data_by_domain
from predict import predict_url, load_model_and_metadata


def test_domain_group_split_zero_leakage():
    """Verify that split_data_by_domain guarantees zero domain overlap."""
    # Synthetic dataset with repeated domains
    data = {
        "url": [f"http://domain{i}.com/page{j}" for i in range(20) for j in range(5)],
        "dom": [f"domain{i}.com" for i in range(20) for j in range(5)],
        "label": [i % 2 for i in range(20) for j in range(5)]
    }
    df = pd.DataFrame(data)

    df_train, df_val, df_test = split_data_by_domain(df, domain_col="dom", random_state=42)

    train_doms = set(df_train["dom"])
    val_doms = set(df_val["dom"])
    test_doms = set(df_test["dom"])

    # Assert mutually disjoint domain sets
    assert train_doms.isdisjoint(val_doms)
    assert train_doms.isdisjoint(test_doms)
    assert val_doms.isdisjoint(test_doms)
    assert len(train_doms) + len(val_doms) + len(test_doms) == 20


def test_model_artifact_load_and_predict():
    """Verify that the trained model artifact loads and produces structured predictions."""
    model, metadata = load_model_and_metadata()
    assert model is not None
    assert metadata["model_version"] == "v1.0.0"
    assert len(metadata["feature_names"]) == 22

    res = predict_url("https://www.google.com")
    assert res["valid"] is True
    assert res["is_phishing"] is False
    assert res["predicted_class"] == 0
    assert 0.0 <= res["phishing_probability"] <= 1.0
    assert res["decision_threshold"] == metadata["tuned_threshold"]
    assert "url_len" in res["extracted_features"]


def test_predict_detects_phishing_sample():
    """Verify that high-entropy suspicious URL receives high phishing probability."""
    phish_url = "https://pay.pagcorefeiraosetembro.site/2wq7Gr7zmL8gBAN?utm_source=organic&utm_campaign=xyz"
    res = predict_url(phish_url)
    assert res["valid"] is True
    assert res["phishing_probability"] > 0.80
    assert res["is_phishing"] is True
    assert res["predicted_class"] == 1


def test_predict_rejects_empty_and_oversized_url():
    """Verify safe rejection of empty or excessively long inputs."""
    empty_res = predict_url("")
    assert empty_res["valid"] is False
    assert "empty" in empty_res["error"].lower()

    huge_url = "https://example.com/" + ("a" * 2050)
    huge_res = predict_url(huge_url)
    assert huge_res["valid"] is False
    assert "exceeds maximum" in huge_res["error"].lower()


def test_predict_offline_zero_network_guarantee():
    """Verify that prediction performs zero network requests."""
    def forbidden_call(*args, **kwargs):
        raise AssertionError("Network connection attempted during prediction!")

    with patch("socket.socket", side_effect=forbidden_call):
        with patch("socket.getaddrinfo", side_effect=forbidden_call):
            res = predict_url("https://bank.example.com/login?token=abc")
            assert res["valid"] is True
            assert isinstance(res["phishing_probability"], float)
