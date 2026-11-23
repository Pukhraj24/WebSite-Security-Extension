"""
Extended URL Lexical Feature Extraction Pipeline - Version 2 (Phase 8).

Adds 18 new features to the existing 22-feature v1 schema, grouped into:
  - URL encoding and structure features
  - Hostname structure features
  - Credential-location lexical signals

SAFETY CONTRACT (identical to v1):
  - ZERO network requests: No DNS, HTTP, WHOIS, RDAP, reputation, or socket calls.
  - All features are computable offline from the URL string alone.
  - Handles malformed inputs, IPv4, IPv6, Punycode, empty strings, long URLs,
    repeated delimiters, and percent-encoded characters safely.
  - Deterministic: identical input always produces identical output.

Schema versioning:
  - v1_published : 22 features matching Dataset.csv (preserved, unchanged)
  - v2_extended  : 22 + 18 = 40 features (this module)

Do not modify FEATURE_NAMES_V1 or the v1 extraction logic; the existing
model artifact (phishing_detector_v1.joblib) depends on it.
"""

import math
import re
import ipaddress
from collections import Counter
from urllib.parse import urlparse
from typing import Dict, List, Optional, Union

import tldextract

# Offline TLD extractor -- strict zero-network guarantee
_OFFLINE_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

# ---------------------------------------------------------------------------
# V1 Feature schema (unchanged -- matches Dataset.csv exactly)
# ---------------------------------------------------------------------------
FEATURE_NAMES_V1 = [
    'url_len', 'dom_len', 'is_ip', 'tld_len', 'subdom_cnt',
    'letter_cnt', 'digit_cnt', 'special_cnt', 'eq_cnt', 'qm_cnt',
    'amp_cnt', 'dot_cnt', 'dash_cnt', 'under_cnt', 'letter_ratio',
    'digit_ratio', 'spec_ratio', 'is_https', 'slash_cnt', 'entropy',
    'path_len', 'query_len'
]

# ---------------------------------------------------------------------------
# V2 additional feature names (18 new features)
# ---------------------------------------------------------------------------
FEATURE_NAMES_V2_NEW = [
    # URL encoding and structure
    'pct_encoded_ratio',      # fraction of characters that are percent-encoded sequences
    'double_encoded',         # 1 if URL contains %25xx (double encoding attempt)
    'at_symbol',              # 1 if URL contains '@' (credential injection indicator)
    'has_fragment',           # 1 if URL contains '#' fragment
    'path_segment_count',     # number of '/' delimited path segments (excluding empty)
    'max_path_segment_len',   # length of longest individual path segment
    'query_param_count',      # number of '&'-separated query parameters
    'max_query_val_len',      # length of longest query param value
    # Hostname structure
    'hostname_len',           # total character length of the hostname
    'longest_label_len',      # length of the longest DNS label in the hostname
    'hostname_digit_ratio',   # digit count / hostname length
    'hostname_entropy',       # Shannon entropy of the hostname string
    'hyphen_in_dom',          # 1 if the registrable domain (not subdomain) contains a hyphen
    'subdomain_len',          # character length of the full subdomain string
    'punycode_present',       # 1 if hostname contains any xn-- label
    'label_count',            # number of '.' labels in the full hostname
    # Credential-location lexical signals
    'login_word_in_host',     # 1 if login/signin/account/verify/secure appears in hostname
    'login_word_in_path',     # 1 if login/signin/account/verify/password/secure in path/query
]

FEATURE_NAMES_V2 = FEATURE_NAMES_V1 + FEATURE_NAMES_V2_NEW

# Suspicious credential words - note: presence alone never labels a URL as phishing.
# These are input signals whose predictive value is evaluated empirically via ablation.
_CRED_WORDS_HOST = re.compile(
    r'(login|signin|sign-in|account|verify|secure|update|webscr|banking)',
    re.IGNORECASE
)
_CRED_WORDS_PATH = re.compile(
    r'(login|signin|sign-in|account|verify|password|passwd|secure|update|webscr|banking|credential)',
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    """Shannon entropy of a string (bits). Returns 0.0 for empty input."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_ip_literal(host: str) -> bool:
    """True if host is a raw IPv4 or IPv6 literal address."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _count_pct_encoded(url_str: str) -> int:
    """Count the number of percent-encoded sequences (%xx) in a URL string."""
    return len(re.findall(r'%[0-9A-Fa-f]{2}', url_str))


def _has_double_encoding(url_str: str) -> int:
    """Return 1 if URL contains %25xx (encoded percent sign = double encoding)."""
    return 1 if re.search(r'%25[0-9A-Fa-f]{2}', url_str, re.IGNORECASE) else 0


def _query_param_count(query_str: str) -> int:
    """Count number of '&'-separated query parameters."""
    if not query_str:
        return 0
    return len(query_str.split('&'))


def _max_query_val_len(query_str: str) -> int:
    """Length of the longest query parameter value."""
    if not query_str:
        return 0
    max_len = 0
    for param in query_str.split('&'):
        if '=' in param:
            val = param.split('=', 1)[1]
            max_len = max(max_len, len(val))
        else:
            max_len = max(max_len, len(param))
    return max_len


def _path_segments(path_str: str) -> List[str]:
    """Return non-empty path segments."""
    if not path_str:
        return []
    return [seg for seg in path_str.split('/') if seg]


# ---------------------------------------------------------------------------
# V1 extraction (canonical -- do not modify)
# ---------------------------------------------------------------------------

def _extract_v1_features(url_str: str) -> Dict[str, Union[float, int]]:
    """
    Extract the canonical 22 v1 features.
    Contains the same logic as url_features.py to avoid import cycles.
    Returns a dict that also includes internal '_*' keys needed by v2.
    """
    url_len = len(url_str)
    parsed = urlparse(url_str)
    if not parsed.scheme and not parsed.netloc:
        parsed = urlparse("//" + url_str)

    ext = _OFFLINE_EXTRACTOR(url_str)
    raw_host = (parsed.hostname or "").lower()
    ip_literal = 1 if _is_ip_literal(raw_host) else 0

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

    letter_ratio = (letter_cnt / url_len) if url_len > 0 else 0.0
    digit_ratio = (digit_cnt / url_len) if url_len > 0 else 0.0
    spec_ratio = (special_cnt / url_len) if url_len > 0 else 0.0

    is_https = 1 if url_str.lower().startswith('https://') else 0
    entropy = _shannon_entropy(url_str)
    path_len = len(parsed.path) if parsed.path else 0
    query_len = len(parsed.query) if parsed.query else 0

    return {
        'url_len': url_len, 'dom_len': dom_len, 'is_ip': ip_literal,
        'tld_len': tld_len, 'subdom_cnt': subdom_cnt,
        'letter_cnt': letter_cnt, 'digit_cnt': digit_cnt,
        'special_cnt': special_cnt, 'eq_cnt': eq_cnt, 'qm_cnt': qm_cnt,
        'amp_cnt': amp_cnt, 'dot_cnt': dot_cnt, 'dash_cnt': dash_cnt,
        'under_cnt': under_cnt, 'letter_ratio': letter_ratio,
        'digit_ratio': digit_ratio, 'spec_ratio': spec_ratio,
        'is_https': is_https, 'slash_cnt': slash_cnt,
        'entropy': entropy, 'path_len': path_len, 'query_len': query_len,
        # Internal keys for v2 use only
        '_raw_host': raw_host,
        '_ext': ext,
        '_parsed_path': parsed.path or '',
        '_parsed_query': parsed.query or '',
        '_ip_literal': ip_literal,
    }


# ---------------------------------------------------------------------------
# V2 new feature extraction
# ---------------------------------------------------------------------------

def _extract_v2_new_features(
    url_str: str,
    v1: Dict,
) -> Dict[str, Union[float, int]]:
    """
    Extract the 18 new v2 features using the pre-computed v1 dict
    (including internal '_*' keys).
    """
    raw_host: str = v1.get('_raw_host', '')
    ext = v1.get('_ext')
    path_str: str = v1.get('_parsed_path', '')
    query_str: str = v1.get('_parsed_query', '')
    ip_literal: int = v1.get('_ip_literal', 0)
    url_len: int = v1['url_len']

    # Encoding features
    pct_count = _count_pct_encoded(url_str)
    pct_encoded_ratio = pct_count / url_len if url_len > 0 else 0.0
    double_encoded = _has_double_encoding(url_str)
    at_symbol = 1 if '@' in url_str else 0
    has_fragment = 1 if '#' in url_str else 0

    segments = _path_segments(path_str)
    path_segment_count = len(segments)
    max_path_segment_len = max((len(s) for s in segments), default=0)

    q_param_count = _query_param_count(query_str)
    max_q_val_len = _max_query_val_len(query_str)

    # Hostname features
    hostname_len = len(raw_host)
    hostname_labels = raw_host.split('.') if raw_host else []
    longest_label_len = max((len(lbl) for lbl in hostname_labels), default=0)

    host_digits = sum(c.isdigit() for c in raw_host)
    hostname_digit_ratio = host_digits / hostname_len if hostname_len > 0 else 0.0
    hostname_entropy = _shannon_entropy(raw_host)

    dom_part = (ext.domain if ext else '') if not ip_literal else ''
    hyphen_in_dom = 1 if '-' in dom_part else 0

    subdomain_str = (ext.subdomain if ext else '') if not ip_literal else ''
    subdomain_len = len(subdomain_str)

    punycode_present = 1 if 'xn--' in raw_host.lower() else 0
    label_count = len(hostname_labels) if raw_host else 0

    # Credential lexical signals
    login_word_in_host = 1 if _CRED_WORDS_HOST.search(raw_host) else 0
    path_query_combined = path_str + '?' + query_str if query_str else path_str
    login_word_in_path = 1 if _CRED_WORDS_PATH.search(path_query_combined) else 0

    return {
        'pct_encoded_ratio': round(pct_encoded_ratio, 6),
        'double_encoded': double_encoded,
        'at_symbol': at_symbol,
        'has_fragment': has_fragment,
        'path_segment_count': path_segment_count,
        'max_path_segment_len': max_path_segment_len,
        'query_param_count': q_param_count,
        'max_query_val_len': max_q_val_len,
        'hostname_len': hostname_len,
        'longest_label_len': longest_label_len,
        'hostname_digit_ratio': round(hostname_digit_ratio, 6),
        'hostname_entropy': round(hostname_entropy, 6),
        'hyphen_in_dom': hyphen_in_dom,
        'subdomain_len': subdomain_len,
        'punycode_present': punycode_present,
        'label_count': label_count,
        'login_word_in_host': login_word_in_host,
        'login_word_in_path': login_word_in_path,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_url_features_v2(
    url: str,
    schema_version: str = "v2_extended"
) -> Dict[str, Union[float, int]]:
    """
    Extract URL features.

    Args:
        url: Raw URL string.
        schema_version:
            'v1_published' -- Return only the canonical 22 v1 features.
            'v2_extended'  -- Return 40 features (v1 + 18 new v2 features).

    Returns:
        Feature dictionary. Internal _* keys are stripped from the output.
    """
    if not isinstance(url, str) or not url.strip():
        zeroed: Dict[str, Union[float, int]] = {f: 0.0 for f in FEATURE_NAMES_V2}
        return zeroed

    url_str = url.strip()
    v1_raw = _extract_v1_features(url_str)

    # Strip internal keys for output
    v1_out = {k: v for k, v in v1_raw.items() if not k.startswith('_')}

    if schema_version == "v1_published":
        return v1_out

    v2_new = _extract_v2_new_features(url_str, v1_raw)
    return {**v1_out, **v2_new}


def extract_features_vector_v2(
    url: str,
    feature_names: Optional[List[str]] = None
) -> List[float]:
    """
    Extract an ordered numeric feature vector for scikit-learn inference.

    Args:
        url: Raw URL string.
        feature_names: Ordered list of feature names (default: FEATURE_NAMES_V2).

    Returns:
        List of float values.
    """
    names = feature_names or FEATURE_NAMES_V2
    feat_dict = extract_url_features_v2(url, schema_version="v2_extended")
    return [float(feat_dict.get(name, 0.0)) for name in names]


def get_feature_schema(version: str = "v2") -> List[str]:
    """Return the ordered feature list for the given schema version."""
    if version == "v1":
        return list(FEATURE_NAMES_V1)
    return list(FEATURE_NAMES_V2)
