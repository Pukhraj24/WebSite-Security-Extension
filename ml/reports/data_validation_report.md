# Dataset Validation Report: URL-Phish (Mendeley Data v2)

**Generated:** 2026-11-24 01:48:00
**Source Dataset:** `ml\data\raw\Dataset.csv`
**Status:** VALIDATED

---

## 1. Dataset Dimensions & Basic Metadata
- **Total Records:** 116,600
- **Total Columns:** 26
- **File Size:** 14.45 MB (15,149,338 bytes)
- **Target Label Column:** `label`

## 2. Target Label Distribution
| Label | Meaning | Sample Count | Percentage |
| :--- | :--- | :--- | :--- |
| **0** | Legitimate / Benign | 100,000 | 85.76% |
| **1** | Phishing / Malicious | 16,600 | 14.24% |
| **Total** | | 116,600 | 100.00% |

*Imbalance Ratio:* Approximately 6.02:1 benign-to-phishing.

## 3. Schema & Column Segregation

### Numerical Feature Columns (22 features)
These columns constitute the feature vector input for machine learning models:
`url_len, dom_len, is_ip, tld_len, subdom_cnt, letter_cnt, digit_cnt, special_cnt, eq_cnt, qm_cnt, amp_cnt, dot_cnt, dash_cnt, under_cnt, letter_ratio, digit_ratio, spec_ratio, is_https, slash_cnt, entropy, path_len, query_len`

### Reference & Metadata Columns (Excluded from model features)
These columns are strictly retained for domain grouping, auditing, and ground-truth evaluation, never fed as raw inputs to ML models:
- `url`: Raw URL string (untrusted input)
- `dom`: Registrable domain (used for GroupShuffleSplit domain-isolation)
- `tld`: Top-level domain string

### Missing Expected Features
None. All 22 expected numerical features are present.

## 4. Data Quality & Integrity Checks
- **Missing Values:** {'tld': 14} (Note: `tld` column has 14 missing values for raw IP hostnames).
- **Infinite / NaN Values in Features:** 0
- **Unique URLs:** 115,231
- **Duplicate URLs:** 1,369 (1.17%)
- **Unique Registrable Domains:** 90,860
- **Mixed Domains (having both 0 and 1 records):** 24 (Cloud platforms, free hosting, e.g. `amazonaws.com`, `blogspot.com`, `azurewebsites.net`).

## 5. Domain Grouping Feasibility
Because the `dom` (registrable domain) column is explicitly available for all records, a strict domain-grouped train/validation/test split (`GroupShuffleSplit`) is feasible and will be enforced to prevent domain leakage.
