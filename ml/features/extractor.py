"""URL feature extraction — 35 lexical, structural, obfuscation, and typosquatting features."""
import re
import math
import sys
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ml.features.obfuscation import decode_url, detect_obfuscation_signals  # noqa: E402
from ml.features.typosquatting import check_typosquatting  # noqa: E402
from shared.url_utils import normalize_url  # noqa: E402


URL_SHORTENERS = frozenset([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "ift.tt", "dlvr.it", "short.to", "rb.gy",
    "is.gd", "cli.gs", "pic.gd", "tiny.cc", "lnkd.in",
])

SUSPICIOUS_KEYWORDS = frozenset([
    "login", "signin", "secure", "verify", "account", "update",
    "banking", "password", "credential", "authenticate", "confirm", "wallet",
    "suspended", "unusual", "alert", "notification",
])

HIGH_RISK_TLDS = frozenset([
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top",
    ".club", ".work", ".click", ".link", ".party", ".download",
    ".zip", ".mov", ".phishing",
    # Commonly abused new gTLDs not in the original list
    ".shop", ".store", ".online", ".site", ".icu", ".vip",
    ".buzz", ".cam", ".cyou", ".fun", ".monster", ".uno",
])

IMPERSONATED_BRANDS = frozenset([
    "paypal", "ebay", "amazon", "apple", "google", "microsoft",
    "netflix", "facebook", "instagram", "twitter", "linkedin",
    "chase", "bankofamerica", "wellsfargo", "citibank",
])

# Column order must match ml/data/processed/ feature names and shared/constants.py
FEATURE_ORDER = [
    "url_length", "domain_length", "subdomain_count", "has_ip",
    "uses_https", "dot_count", "hyphen_count", "at_sign_count",
    "special_char_count", "digit_ratio", "entropy", "suspicious_keywords",
    "is_url_shortener", "tld_risk", "path_depth", "query_param_count",
    "has_encoded_chars", "double_slash_in_path", "has_port", "is_punycode",
    "tilde_in_path", "hex_in_domain", "redirect_double_slash",
    "domain_digit_count", "url_shortener_flag", "brand_count",
    "num_dots_in_path", "query_length", "fragment_present", "multi_subdomain",
    "obfuscation_signal_count", "has_at_misdirect", "decode_changed_url",
    "typosquat_distance", "is_typosquatting",
]

# Distances above this carry no signal — every unrelated domain lands far away.
_TYPOSQUAT_DISTANCE_CAP = 10


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class URLFeatureExtractor:
    def extract(self, raw_url: str) -> dict[str, Any]:
        # Lexical features come from the normalized URL so training and serving
        # see identical vectors; obfuscation signals come from the raw URL,
        # which still carries the userinfo and encoding that normalization strips.
        url = normalize_url(raw_url)
        obfuscation_signals = detect_obfuscation_signals(raw_url)
        typosquat = check_typosquatting(urllib.parse.urlparse(url).netloc.split(":")[0])

        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        # Strip port from domain string
        domain = domain.split(":")[0]
        path = parsed.path
        query = parsed.query
        full = url.lower()

        parts = domain.split(".")
        tld = ("." + parts[-1]) if len(parts) > 1 else ""
        digits_in_domain = sum(c.isdigit() for c in domain)

        return {
            "url_length": len(url),
            "domain_length": len(domain),
            "subdomain_count": max(len(parts) - 2, 0),
            "has_ip": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain)),
            "uses_https": parsed.scheme == "https",
            "dot_count": url.count("."),
            "hyphen_count": domain.count("-"),
            "at_sign_count": url.count("@"),
            "special_char_count": sum(url.count(c) for c in ("@", "?", "%", "+", "=")),
            "digit_ratio": round(digits_in_domain / len(domain), 4) if domain else 0.0,
            "entropy": round(_shannon_entropy(domain), 4),
            "suspicious_keywords": sum(kw in full for kw in SUSPICIOUS_KEYWORDS),
            "is_url_shortener": domain in URL_SHORTENERS,
            "tld_risk": 1.0 if tld in HIGH_RISK_TLDS else 0.0,
            "path_depth": len([p for p in path.split("/") if p]),
            "query_param_count": len(urllib.parse.parse_qs(query)),
            "has_encoded_chars": "%" in url,
            "double_slash_in_path": "//" in path,
            "has_port": bool(parsed.port),
            "is_punycode": "xn--" in domain,
            "tilde_in_path": "~" in path,
            "hex_in_domain": bool(re.search(r"0x[0-9a-fA-F]+", domain)),
            "redirect_double_slash": url.count("//") > 1,
            "domain_digit_count": digits_in_domain,
            "url_shortener_flag": 1 if domain in URL_SHORTENERS else 0,
            "brand_count": sum(b in domain for b in IMPERSONATED_BRANDS),
            "num_dots_in_path": path.count("."),
            "query_length": len(query),
            "fragment_present": bool(parsed.fragment),
            "multi_subdomain": 1 if len(parts) > 3 else 0,
            "obfuscation_signal_count": len(obfuscation_signals),
            "has_at_misdirect": "at_sign_misdirect" in obfuscation_signals,
            "decode_changed_url": decode_url(raw_url) != raw_url,
            "typosquat_distance": min(typosquat["edit_distance"], _TYPOSQUAT_DISTANCE_CAP),
            "is_typosquatting": typosquat["is_typosquatting"],
        }

    def to_vector(self, features: dict[str, Any]) -> np.ndarray:
        return np.array(
            [
                int(features[k]) if isinstance(features[k], bool) else features[k]
                for k in FEATURE_ORDER
            ],
            dtype=float,
        )
