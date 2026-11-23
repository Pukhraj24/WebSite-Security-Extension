"""
URL Lexical and Structural Feature Extraction Pipeline.

Extracts deterministic lexical, structural, and character-distribution features
from a raw URL string without making any network, DNS, or socket requests.

Adheres to:
1. Zero network requests (offline suffix extraction with TLDExtract(suffix_list_urls=())).
2. Robust input sanitization (handles malformed, IPv4, IPv6, punycode, empty strings).
3. Schema alignment with published dataset (22 features for v1_published).
"""

import math
import ipaddress
from collections import Counter
from urllib.parse import urlparse
from typing import Dict, Any, List, Union, Optional
import tldextract


# Offline TLD extractor with empty suffix URLs (strict zero-network guarantee)
_OFFLINE_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

# Ordered feature names matching the Mendeley URL-Phish Version 2 dataset schema
FEATURE_NAMES_V1 = [
    'url_len',
    'dom_len',
    'is_ip',
    'tld_len',
    'subdom_cnt',
    'letter_cnt',
    'digit_cnt',
    'special_cnt',
    'eq_cnt',
    'qm_cnt',
    'amp_cnt',
    'dot_cnt',
    'dash_cnt',
    'under_cnt',
    'letter_ratio',
    'digit_ratio',
    'spec_ratio',
    'is_https',
    'slash_cnt',
    'entropy',
    'path_len',
    'query_len'
]


def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_ip_address(host: str) -> bool:
    """Check if host string is a valid IPv4 or IPv6 literal."""
    if not host:
        return False
    clean_host = host.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def extract_url_features(url: str, schema_version: str = "v1_published") -> Dict[str, Union[float, int]]:
    """
    Extract numerical lexical and structural features from a single URL string.

    Args:
        url: The raw URL string to analyze.
        schema_version: 'v1_published' (default, 22 features matching Dataset.csv)
                        or 'v2_extended' (includes additional security indicators).

    Returns:
        Dictionary mapping feature name to numeric value.
    """
    if not isinstance(url, str) or not url.strip():
        # Return zeroed vector for empty or invalid inputs
        base_features = {feat: 0.0 for feat in FEATURE_NAMES_V1}
        return base_features

    url_str = url.strip()
    url_len = len(url_str)

    # Parse components safely
    parsed = urlparse(url_str)
    # If scheme was omitted, assist urlparse by checking host prefix
    if not parsed.scheme and not parsed.netloc:
        parsed = urlparse("//" + url_str)

    # Domain, TLD, and Subdomain extraction via offline PSL
    ext = _OFFLINE_EXTRACTOR(url_str)

    # Check IP literal
    raw_host = (parsed.hostname or "").lower()
    ip_literal = 1 if is_ip_address(raw_host) else 0

    if ip_literal:
        dom = raw_host
        tld = ""
        subdom_cnt = 0
    else:
        dom = f"{ext.domain}.{ext.suffix}" if ext.suffix else (ext.domain or raw_host)
        tld = ext.suffix or ""
        subdom_cnt = len(ext.subdomain.split('.')) if ext.subdomain else 0

    dom_len = len(dom)
    tld_len = len(tld)

    # Character counts
    letter_cnt = sum(c.isalpha() for c in url_str)
    digit_cnt = sum(c.isdigit() for c in url_str)
    special_cnt = url_len - letter_cnt - digit_cnt

    eq_cnt = url_str.count('=')
    qm_cnt = url_str.count('?')
    amp_cnt = url_str.count('&')
    dot_cnt = url_str.count('.')
    dash_cnt = url_str.count('-')
    under_cnt = url_str.count('_')
    slash_cnt = url_str.count('/')

    # Ratios
    letter_ratio = (letter_cnt / url_len) if url_len > 0 else 0.0
    digit_ratio = (digit_cnt / url_len) if url_len > 0 else 0.0
    spec_ratio = (special_cnt / url_len) if url_len > 0 else 0.0

    # Transport scheme
    is_https = 1 if url_str.lower().startswith('https://') else 0

    # Shannon Entropy of the entire URL string
    entropy = calculate_shannon_entropy(url_str)

    # Path and query lengths
    path_len = len(parsed.path) if parsed.path else 0
    query_len = len(parsed.query) if parsed.query else 0

    features = {
        'url_len': url_len,
        'dom_len': dom_len,
        'is_ip': ip_literal,
        'tld_len': tld_len,
        'subdom_cnt': subdom_cnt,
        'letter_cnt': letter_cnt,
        'digit_cnt': digit_cnt,
        'special_cnt': special_cnt,
        'eq_cnt': eq_cnt,
        'qm_cnt': qm_cnt,
        'amp_cnt': amp_cnt,
        'dot_cnt': dot_cnt,
        'dash_cnt': dash_cnt,
        'under_cnt': under_cnt,
        'letter_ratio': letter_ratio,
        'digit_ratio': digit_ratio,
        'spec_ratio': spec_ratio,
        'is_https': is_https,
        'slash_cnt': slash_cnt,
        'entropy': entropy,
        'path_len': path_len,
        'query_len': query_len
    }

    if schema_version == "v2_extended":
        features['at_cnt'] = url_str.count('@')
        features['has_punycode'] = 1 if 'xn--' in url_str.lower() else 0
        features['hostname_len'] = len(raw_host)
        features['hostname_entropy'] = calculate_shannon_entropy(raw_host)

    return features


def extract_features_vector(url: str, feature_names: Optional[List[str]] = None) -> List[float]:
    """Extract ordered numeric feature vector for scikit-learn model inference."""
    names = feature_names or FEATURE_NAMES_V1
    feat_dict = extract_url_features(url, schema_version="v1_published")
    return [float(feat_dict.get(name, 0.0)) for name in names]
