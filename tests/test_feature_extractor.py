"""Tests for URLFeatureExtractor — all 35 features, edge cases, and vector shape."""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ml.features.extractor import URLFeatureExtractor, FEATURE_ORDER


@pytest.fixture
def extractor():
    return URLFeatureExtractor()


class TestVectorShape:
    def test_returns_35_features(self, extractor):
        vec = extractor.to_vector(extractor.extract("https://example.com"))
        assert vec.shape == (35,)

    def test_feature_order_has_35_entries(self):
        assert len(FEATURE_ORDER) == 35

    def test_feature_keys_match_order(self, extractor):
        feats = extractor.extract("https://example.com/path")
        assert set(feats.keys()) == set(FEATURE_ORDER)

    def test_vector_dtype_is_float(self, extractor):
        vec = extractor.to_vector(extractor.extract("https://example.com"))
        assert vec.dtype == float


class TestUrlLengthAndDomain:
    def test_url_length_correct(self, extractor):
        url = "http://abc.com/path"
        feats = extractor.extract(url)
        assert feats["url_length"] == len(url)

    def test_domain_length_strips_www(self, extractor):
        feats = extractor.extract("https://www.google.com/")
        assert feats["domain_length"] == len("google.com")

    def test_subdomain_count_none(self, extractor):
        feats = extractor.extract("https://google.com/")
        assert feats["subdomain_count"] == 0

    def test_subdomain_count_one(self, extractor):
        feats = extractor.extract("https://mail.google.com/")
        assert feats["subdomain_count"] == 1

    def test_subdomain_count_two(self, extractor):
        feats = extractor.extract("https://a.b.google.com/")
        assert feats["subdomain_count"] == 2


class TestProtocolAndIPFlags:
    def test_https_flag_true(self, extractor):
        assert extractor.extract("https://example.com")["uses_https"] is True

    def test_https_flag_false(self, extractor):
        assert extractor.extract("http://example.com")["uses_https"] is False

    def test_has_ip_true(self, extractor):
        assert extractor.extract("http://192.168.1.1/path")["has_ip"] is True

    def test_has_ip_false(self, extractor):
        assert extractor.extract("https://google.com")["has_ip"] is False

    def test_has_port_true(self, extractor):
        assert extractor.extract("http://example.com:8080/path")["has_port"] is True

    def test_has_port_false(self, extractor):
        assert extractor.extract("https://example.com/path")["has_port"] is False


class TestSuspiciousSignals:
    def test_suspicious_keywords_counted(self, extractor):
        feats = extractor.extract("http://paypal-login-verify.com/secure")
        assert feats["suspicious_keywords"] >= 2  # login, verify

    def test_suspicious_keywords_zero_for_clean(self, extractor):
        feats = extractor.extract("https://github.com/user/repo")
        assert feats["suspicious_keywords"] == 0

    def test_tld_risk_high_for_xyz(self, extractor):
        assert extractor.extract("http://bad-site.xyz/")["tld_risk"] == 1.0

    def test_tld_risk_zero_for_com(self, extractor):
        assert extractor.extract("https://example.com/")["tld_risk"] == 0.0

    def test_url_shortener_flag(self, extractor):
        feats = extractor.extract("https://bit.ly/abc123")
        assert feats["is_url_shortener"] is True
        assert feats["url_shortener_flag"] == 1

    def test_at_sign_misdirect_survives_normalization(self, extractor):
        # Normalization drops the userinfo, so at_sign_count cannot carry this
        # signal any more — has_at_misdirect reads it off the raw URL instead.
        feats = extractor.extract("http://legit-bank.com@evil.com/page")
        assert feats["at_sign_count"] == 0
        assert feats["has_at_misdirect"] is True
        assert feats["obfuscation_signal_count"] >= 1

    def test_encoded_chars_detected(self, extractor):
        feats = extractor.extract("http://example.com/path%20with%20spaces")
        assert feats["has_encoded_chars"] is True

    def test_punycode_detected(self, extractor):
        feats = extractor.extract("http://xn--pple-43d.com/")
        assert feats["is_punycode"] is True

    def test_brand_in_domain(self, extractor):
        feats = extractor.extract("http://paypal-login.xyz/")
        assert feats["brand_count"] >= 1

    def test_multi_subdomain_true(self, extractor):
        feats = extractor.extract("http://a.b.c.evil.com/")
        assert feats["multi_subdomain"] == 1

    def test_multi_subdomain_false(self, extractor):
        feats = extractor.extract("http://evil.com/")
        assert feats["multi_subdomain"] == 0


class TestEntropyAndDigits:
    def test_entropy_positive(self, extractor):
        feats = extractor.extract("http://xkcd29abc.xyz/randompath")
        assert feats["entropy"] > 0.0

    def test_entropy_increases_with_randomness(self, extractor):
        clean = extractor.extract("https://google.com")
        random = extractor.extract("http://a1b2c3d4e5f6g7h8.xyz/q?x=y")
        assert random["entropy"] >= clean["entropy"]

    def test_digit_ratio_zero_for_letters_only(self, extractor):
        feats = extractor.extract("https://google.com/search")
        assert feats["digit_ratio"] == 0.0

    def test_fragment_detected(self, extractor):
        feats = extractor.extract("https://example.com/page#section")
        assert feats["fragment_present"] is True

    def test_query_length(self, extractor):
        feats = extractor.extract("https://example.com/?q=hello&x=1")
        assert feats["query_length"] == len("q=hello&x=1")
        assert feats["query_param_count"] == 2


class TestObfuscationAndTyposquatFeatures:
    def test_clean_url_has_no_obfuscation_signals(self, extractor):
        feats = extractor.extract("https://github.com/torvalds/linux")
        assert feats["obfuscation_signal_count"] == 0
        assert feats["has_at_misdirect"] is False
        assert feats["decode_changed_url"] is False

    def test_percent_encoding_flags_decode_change(self, extractor):
        feats = extractor.extract("http://evil.com/path%20with%20space")
        assert feats["decode_changed_url"] is True
        assert feats["obfuscation_signal_count"] >= 1

    def test_typosquat_domain_detected(self, extractor):
        feats = extractor.extract("http://paypa1.com/login")
        assert feats["is_typosquatting"] is True
        assert feats["typosquat_distance"] <= 2

    def test_real_brand_is_not_typosquatting(self, extractor):
        feats = extractor.extract("https://paypal.com/signin")
        assert feats["is_typosquatting"] is False
        assert feats["typosquat_distance"] == 0

    def test_unrelated_domain_distance_is_capped(self, extractor):
        feats = extractor.extract("https://docs.python.org/3/library/asyncio.html")
        assert feats["is_typosquatting"] is False
        assert feats["typosquat_distance"] == 10


class TestNormalizationConsistency:
    def test_default_port_does_not_change_features(self, extractor):
        bare = extractor.extract("https://example.com/path")
        ported = extractor.extract("https://example.com:443/path")
        assert bare == ported

    def test_host_case_does_not_change_features(self, extractor):
        lower = extractor.extract("https://example.com/Path")
        upper = extractor.extract("https://EXAMPLE.COM/Path")
        assert lower == upper
