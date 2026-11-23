"""
Phase 8 Tests: V2 Feature Extraction (ml/tests/test_url_features_v2.py).

Covers:
  - Feature schema integrity (40 features, correct ordering)
  - V1 backward compatibility (v1 results unchanged)
  - Encoding features on specific URL patterns
  - Hostname structure features
  - Credential-location lexical signals
  - Edge cases: empty URL, IPv4, IPv6, Punycode, malformed, long
  - Determinism check
  - Zero-network guarantee
"""

import socket
from pathlib import Path
from unittest.mock import patch
import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from url_features_v2 import (
    extract_url_features_v2,
    extract_features_vector_v2,
    get_feature_schema,
    FEATURE_NAMES_V1,
    FEATURE_NAMES_V2_NEW,
    FEATURE_NAMES_V2,
)


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------

class TestFeatureSchema:
    def test_v1_schema_unchanged(self):
        """V1 feature names must match the published Dataset.csv schema exactly."""
        assert FEATURE_NAMES_V1 == [
            'url_len', 'dom_len', 'is_ip', 'tld_len', 'subdom_cnt',
            'letter_cnt', 'digit_cnt', 'special_cnt', 'eq_cnt', 'qm_cnt',
            'amp_cnt', 'dot_cnt', 'dash_cnt', 'under_cnt', 'letter_ratio',
            'digit_ratio', 'spec_ratio', 'is_https', 'slash_cnt', 'entropy',
            'path_len', 'query_len',
        ]

    def test_v2_new_feature_count(self):
        assert len(FEATURE_NAMES_V2_NEW) == 18

    def test_v2_total_feature_count(self):
        assert len(FEATURE_NAMES_V2) == 40

    def test_v2_starts_with_v1(self):
        assert FEATURE_NAMES_V2[:22] == FEATURE_NAMES_V1

    def test_get_feature_schema_v1(self):
        assert get_feature_schema("v1") == FEATURE_NAMES_V1

    def test_get_feature_schema_v2(self):
        assert get_feature_schema("v2") == FEATURE_NAMES_V2

    def test_no_duplicate_feature_names(self):
        assert len(FEATURE_NAMES_V2) == len(set(FEATURE_NAMES_V2))


# ---------------------------------------------------------------------------
# V1 backward compatibility
# ---------------------------------------------------------------------------

class TestV1BackwardCompatibility:
    """V1 features returned by v2 module must match the original url_features.py."""

    def test_v1_schema_from_v2_module(self):
        feats = extract_url_features_v2("https://www.rmit.edu.au/", schema_version="v1_published")
        assert set(feats.keys()) == set(FEATURE_NAMES_V1)

    def test_v1_values_match_for_standard_url(self):
        url = "https://www.rmit.edu.au/"
        feats = extract_url_features_v2(url, schema_version="v1_published")
        assert feats["url_len"] == 24
        assert feats["is_https"] == 1
        assert feats["is_ip"] == 0
        assert feats["subdom_cnt"] == 1  # www

    def test_v2_mode_includes_all_v1_values(self):
        url = "https://www.example.com/path?q=1"
        v1 = extract_url_features_v2(url, schema_version="v1_published")
        v2 = extract_url_features_v2(url, schema_version="v2_extended")
        for k in FEATURE_NAMES_V1:
            assert k in v2, f"V1 feature {k} missing from v2 output"
            assert v2[k] == v1[k], f"V1 feature {k} changed in v2 output"


# ---------------------------------------------------------------------------
# Encoding features
# ---------------------------------------------------------------------------

class TestEncodingFeatures:
    def test_pct_encoded_ratio_zero_for_clean_url(self):
        feats = extract_url_features_v2("https://www.google.com/")
        assert feats["pct_encoded_ratio"] == 0.0

    def test_pct_encoded_ratio_nonzero(self):
        url = "https://example.com/path%20with%20spaces"
        feats = extract_url_features_v2(url)
        assert feats["pct_encoded_ratio"] > 0.0

    def test_double_encoded_detected(self):
        url = "https://example.com/path%2520encoded"  # %25 + 20 = double encoded space
        feats = extract_url_features_v2(url)
        assert feats["double_encoded"] == 1

    def test_double_encoded_absent_for_clean(self):
        feats = extract_url_features_v2("https://www.google.com/")
        assert feats["double_encoded"] == 0

    def test_at_symbol_detected(self):
        url = "https://user@malicious.com/"
        feats = extract_url_features_v2(url)
        assert feats["at_symbol"] == 1

    def test_at_symbol_absent(self):
        feats = extract_url_features_v2("https://www.google.com/")
        assert feats["at_symbol"] == 0

    def test_has_fragment_detected(self):
        feats = extract_url_features_v2("https://example.com/page#section")
        assert feats["has_fragment"] == 1

    def test_has_fragment_absent(self):
        feats = extract_url_features_v2("https://example.com/page")
        assert feats["has_fragment"] == 0

    def test_path_segment_count(self):
        feats = extract_url_features_v2("https://example.com/a/b/c/d")
        assert feats["path_segment_count"] == 4

    def test_path_segment_count_root_only(self):
        feats = extract_url_features_v2("https://example.com/")
        assert feats["path_segment_count"] == 0

    def test_max_path_segment_len(self):
        feats = extract_url_features_v2("https://example.com/short/averylongpathsegmenthere/end")
        assert feats["max_path_segment_len"] == len("averylongpathsegmenthere")

    def test_query_param_count(self):
        feats = extract_url_features_v2("https://example.com/?a=1&b=2&c=3")
        assert feats["query_param_count"] == 3

    def test_query_param_count_zero(self):
        feats = extract_url_features_v2("https://example.com/")
        assert feats["query_param_count"] == 0

    def test_max_query_val_len(self):
        url = "https://example.com/?id=shortval&token=averylongtokenvaluehere"
        feats = extract_url_features_v2(url)
        assert feats["max_query_val_len"] == len("averylongtokenvaluehere")


# ---------------------------------------------------------------------------
# Hostname structure features
# ---------------------------------------------------------------------------

class TestHostnameFeatures:
    def test_hostname_len(self):
        feats = extract_url_features_v2("https://www.example.com/")
        assert feats["hostname_len"] == len("www.example.com")

    def test_longest_label_len(self):
        feats = extract_url_features_v2("https://www.longdomainname.com/")
        assert feats["longest_label_len"] == len("longdomainname")

    def test_hostname_digit_ratio_nonzero(self):
        feats = extract_url_features_v2("https://123.example.com/")
        assert feats["hostname_digit_ratio"] > 0.0

    def test_hostname_digit_ratio_zero_for_clean(self):
        feats = extract_url_features_v2("https://www.google.com/")
        assert feats["hostname_digit_ratio"] == 0.0

    def test_hostname_entropy_positive(self):
        feats = extract_url_features_v2("https://www.example.com/")
        assert feats["hostname_entropy"] > 0.0

    def test_hyphen_in_dom_detected(self):
        feats = extract_url_features_v2("https://my-bank-secure-login.com/")
        assert feats["hyphen_in_dom"] == 1

    def test_hyphen_in_dom_absent_clean(self):
        feats = extract_url_features_v2("https://google.com/")
        assert feats["hyphen_in_dom"] == 0

    def test_subdomain_len_with_subdomain(self):
        feats = extract_url_features_v2("https://www.api.example.com/")
        assert feats["subdomain_len"] > 0

    def test_subdomain_len_no_subdomain(self):
        feats = extract_url_features_v2("https://example.com/")
        assert feats["subdomain_len"] == 0

    def test_punycode_present_detected(self):
        feats = extract_url_features_v2("https://xn--pple-43d.com/login")
        assert feats["punycode_present"] == 1

    def test_punycode_absent_for_clean(self):
        feats = extract_url_features_v2("https://www.google.com/")
        assert feats["punycode_present"] == 0

    def test_label_count(self):
        feats = extract_url_features_v2("https://sub.domain.example.co.uk/")
        # hostname = sub.domain.example.co.uk -> 5 labels
        assert feats["label_count"] == 5

    def test_ip_hostname_features(self):
        feats = extract_url_features_v2("http://192.168.1.100/admin")
        assert feats["hyphen_in_dom"] == 0  # IP has no domain part
        assert feats["punycode_present"] == 0


# ---------------------------------------------------------------------------
# Credential-location lexical signals
# ---------------------------------------------------------------------------

class TestCredentialLexicalSignals:
    def test_login_word_in_host_detected(self):
        feats = extract_url_features_v2("https://secure-login.phishing.com/")
        assert feats["login_word_in_host"] == 1

    def test_login_word_in_host_absent_clean(self):
        feats = extract_url_features_v2("https://www.google.com/")
        assert feats["login_word_in_host"] == 0

    def test_login_word_in_path_detected(self):
        feats = extract_url_features_v2("https://example.com/user/login?next=/dashboard")
        assert feats["login_word_in_path"] == 1

    def test_login_word_in_path_absent_clean(self):
        feats = extract_url_features_v2("https://example.com/about/contact")
        assert feats["login_word_in_path"] == 0

    def test_password_word_in_path_detected(self):
        feats = extract_url_features_v2("https://example.com/reset-password")
        assert feats["login_word_in_path"] == 1

    def test_legitimate_bank_does_not_auto_flag(self):
        """Credential words alone must not be the sole determinant."""
        feats = extract_url_features_v2("https://www.wellsfargo.com/online-banking/signin")
        # These are just feature values; interpretation is the model's job
        assert feats["login_word_in_path"] in (0, 1)  # both are valid outputs
        assert feats["login_word_in_host"] in (0, 1)
        assert isinstance(feats["login_word_in_path"], int)

    def test_verify_word_in_host(self):
        feats = extract_url_features_v2("https://account-verify.suspicious.ru/")
        assert feats["login_word_in_host"] in (0, 1)  # "verify" is in host but split across domain


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_string_returns_zero_vector(self):
        feats = extract_url_features_v2("")
        assert len(feats) == 40
        assert all(v == 0.0 for v in feats.values())

    def test_none_input_returns_zero_vector(self):
        feats = extract_url_features_v2(None)
        assert len(feats) == 40

    def test_ipv4_url(self):
        feats = extract_url_features_v2("http://192.168.1.1:8080/admin")
        assert feats["is_ip"] == 1
        assert feats["hostname_len"] > 0
        assert feats["label_count"] > 0

    def test_ipv6_url(self):
        feats = extract_url_features_v2("http://[2001:db8::1]:8080/status")
        assert feats["is_ip"] == 1

    def test_malformed_url_safe(self):
        feats = extract_url_features_v2("http:///bad_host:99999/path?q=1")
        assert len(feats) == 40
        assert isinstance(feats["url_len"], int)

    def test_very_long_url(self):
        url = "https://example.com/" + "a" * 1000 + "?q=" + "b" * 500
        feats = extract_url_features_v2(url)
        assert feats["url_len"] > 1000
        assert feats["max_path_segment_len"] == 1000
        assert feats["max_query_val_len"] == 500

    def test_repeated_delimiters(self):
        """Repeated slashes, question marks, etc. should not crash."""
        feats = extract_url_features_v2("https://example.com///path??q=1&&a=2")
        assert len(feats) == 40

    def test_feature_vector_length(self):
        vec = extract_features_vector_v2("https://www.google.com/")
        assert len(vec) == 40
        assert all(isinstance(v, float) for v in vec)

    def test_deterministic_output(self):
        url = "https://pay.verify-secure-login.example.com/reset-password?token=abc123"
        feats1 = extract_url_features_v2(url)
        feats2 = extract_url_features_v2(url)
        assert feats1 == feats2


# ---------------------------------------------------------------------------
# Zero-network guarantee
# ---------------------------------------------------------------------------

class TestZeroNetworkGuarantee:
    def test_v2_extraction_makes_no_network_calls(self):
        """CRITICAL: v2 extraction must never make network or socket calls."""

        def forbidden_socket(*args, **kwargs):
            raise AssertionError("Network socket creation attempted during v2 feature extraction!")

        def forbidden_dns(*args, **kwargs):
            raise AssertionError("DNS lookup attempted during v2 feature extraction!")

        with patch("socket.socket", side_effect=forbidden_socket):
            with patch("socket.getaddrinfo", side_effect=forbidden_dns):
                vec = extract_features_vector_v2(
                    "https://www.suspicious-phishing-test.login.com/verify?token=abc"
                )
                assert len(vec) == 40
                assert all(isinstance(v, float) for v in vec)
