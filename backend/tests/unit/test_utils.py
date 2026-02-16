"""Tests for domain normalization and validation."""

from app.utils.domain_utils import normalize_domain, validate_domain


class TestNormalizeDomain:

    def test_strips_https(self):
        assert normalize_domain("https://example.com") == "example.com"

    def test_strips_http(self):
        assert normalize_domain("http://example.com") == "example.com"

    def test_strips_www(self):
        assert normalize_domain("www.example.com") == "example.com"

    def test_strips_path(self):
        assert normalize_domain("https://example.com/path/to/page") == "example.com"

    def test_strips_port(self):
        assert normalize_domain("example.com:8080") == "example.com"

    def test_lowercases(self):
        assert normalize_domain("EXAMPLE.COM") == "example.com"

    def test_strips_trailing_slash(self):
        assert normalize_domain("example.com/") == "example.com"

    def test_full_cleanup(self):
        assert normalize_domain("  https://WWW.Example.COM/path?q=1  ") == "example.com"

    def test_bare_domain_unchanged(self):
        assert normalize_domain("example.com") == "example.com"


class TestValidateDomain:

    def test_valid_domain(self):
        assert validate_domain("example.com") is True

    def test_valid_subdomain(self):
        assert validate_domain("sub.example.com") is True

    def test_invalid_no_tld(self):
        assert validate_domain("example") is False

    def test_invalid_spaces(self):
        assert validate_domain("example .com") is False

    def test_invalid_empty(self):
        assert validate_domain("") is False

    def test_invalid_too_long(self):
        assert validate_domain("a" * 254 + ".com") is False
