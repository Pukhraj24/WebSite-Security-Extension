"""
Unit tests for URL Lexical Feature Extraction (ml/src/url_features.py).
"""

import socket
from pathlib import Path
from unittest.mock import patch
import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from url_features import (
    extract_url_features,
    extract_features_vector,
    calculate_shannon_entropy,
    is_ip_address,
    FEATURE_NAMES_V1
)


def test_feature_names_and_order_consistency():
    """Verify exact 22 feature names and order matching published Dataset.csv."""
    assert len(FEATURE_NAMES_V1) == 22
    assert FEATURE_NAMES_V1 == [
        'url_len', 'dom_len', 'is_ip', 'tld_len', 'subdom_cnt',
        'letter_cnt', 'digit_cnt', 'special_cnt', 'eq_cnt', 'qm_cnt',
        'amp_cnt', 'dot_cnt', 'dash_cnt', 'under_cnt', 'letter_ratio',
        'digit_ratio', 'spec_ratio', 'is_https', 'slash_cnt', 'entropy',
        'path_len', 'query_len'
    ]


def test_feature_extraction_standard_url():
    """Verify feature values on a known standard HTTPS URL."""
    url = "https://www.rmit.edu.au/"
    feats = extract_url_features(url)

    assert feats["url_len"] == 24
    assert feats["dom_len"] == 11   # rmit.edu.au
    assert feats["tld_len"] == 6    # edu.au
    assert feats["subdom_cnt"] == 1 # www
    assert feats["is_ip"] == 0
    assert feats["is_https"] == 1
    assert feats["slash_cnt"] == 3
    assert feats["dot_cnt"] == 3
    assert feats["letter_cnt"] == 17
    assert feats["digit_cnt"] == 0
    assert feats["special_cnt"] == 7
    assert round(feats["letter_ratio"], 4) == round(17 / 24, 4)
    assert round(feats["entropy"], 4) == round(3.7091, 4)


def test_feature_extraction_ipv4_and_ipv6():
    """Verify IP literal detection on IPv4 and IPv6 URLs."""
    v4_url = "http://192.168.1.1:8080/admin"
    v4_feats = extract_url_features(v4_url)
    assert v4_feats["is_ip"] == 1
    assert v4_feats["is_https"] == 0
    assert v4_feats["subdom_cnt"] == 0

    v6_url = "http://[2001:db8::1]:8080/status"
    v6_feats = extract_url_features(v6_url)
    assert v6_feats["is_ip"] == 1
    assert v6_feats["is_https"] == 0


def test_feature_extraction_punycode():
    """Verify handling of Punycode / IDN domains."""
    url = "https://xn--pple-43d.com/login"
    feats = extract_url_features(url)
    assert feats["is_ip"] == 0
    assert feats["is_https"] == 1
    assert feats["dom_len"] > 0
    assert feats["tld_len"] == 3  # com


def test_feature_extraction_malformed_and_empty():
    """Verify safe degradation on empty, malformed, or unusual inputs."""
    empty_feats = extract_url_features("")
    assert len(empty_feats) == 22
    assert all(v == 0.0 for v in empty_feats.values())

    none_feats = extract_url_features(None)
    assert len(none_feats) == 22

    malformed_url = "http:///bad_host:99999/path?q=1"
    m_feats = extract_url_features(malformed_url)
    assert m_feats["url_len"] == len(malformed_url)
    assert m_feats["qm_cnt"] == 1


def test_offline_zero_network_guarantee():
    """
    CRITICAL: Verify that feature extraction makes ZERO network or socket calls.
    Patches socket.socket and socket.getaddrinfo to raise if called.
    """
    def forbidden_socket(*args, **kwargs):
        raise AssertionError("Network socket creation was attempted during feature extraction!")

    def forbidden_dns(*args, **kwargs):
        raise AssertionError("DNS resolution was attempted during feature extraction!")

    with patch("socket.socket", side_effect=forbidden_socket):
        with patch("socket.getaddrinfo", side_effect=forbidden_dns):
            vector = extract_features_vector("https://www.suspicious-phishing-test-url.com/path?arg=1&key=val")
            assert len(vector) == 22
            assert all(isinstance(v, (int, float)) for v in vector)
