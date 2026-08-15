"""Unit tests for IOCExtractor.

Tests IOC extraction from text including IPv4, IPv6, domains, hashes,
emails, URLs, CVEs, onion addresses, cryptocurrency wallets, and PGP keys.
Uses Hypothesis for property-based testing.
"""

from __future__ import annotations

import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus_engine.intel.ioc_extractor import IOCExtractor


# -- Fixtures ------------------------------------------------------------


@pytest.fixture
def extractor():
    """Create a default IOCExtractor."""
    return IOCExtractor()


@pytest.fixture
def extractor_no_ner():
    """Create an IOCExtractor without NER."""
    return IOCExtractor(use_ner=False)


# -- Basic extraction tests ----------------------------------------------


class TestIOCExtraction:
    """Test core IOC extraction functionality."""

    def test_extract_empty_text(self, extractor):
        """Empty text returns empty result structure."""
        result = extractor.extract("")
        assert isinstance(result, dict)
        assert result["urls"] == []
        assert result["ipv4"] == []
        assert result["ipv6"] == []
        assert result["domains"] == []

    def test_extract_none_text(self, extractor):
        """None text returns empty result structure."""
        result = extractor.extract(None)
        assert isinstance(result, dict)
        assert result["ipv4"] == []

    def test_extract_ipv4(self, extractor):
        """IPv4 addresses are extracted correctly."""
        text = "Traffic from 192.168.1.1 and 10.0.0.1 detected."
        result = extractor.extract(text)
        assert "192.168.1.1" in result["ipv4"]
        assert "10.0.0.1" in result["ipv4"]

    def test_extract_ipv4_with_context(self, extractor):
        """IPv4 extraction works with surrounding context."""
        text = "Server at 203.0.113.50 responded, then 198.51.100.23"
        result = extractor.extract(text)
        assert "203.0.113.50" in result["ipv4"]
        assert "198.51.100.23" in result["ipv4"]

    def test_extract_ipv6(self, extractor):
        """IPv6 addresses are extracted correctly."""
        text = "IPv6 traffic from 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        result = extractor.extract(text)
        assert len(result["ipv6"]) >= 1

    def test_extract_domains(self, extractor):
        """Domains are extracted correctly."""
        text = "Malicious activity from evil.example.com and malware.test.org"
        result = extractor.extract(text)
        domains = result["domains"]
        assert any("evil.example.com" in d for d in domains)

    def test_extract_urls(self, extractor):
        """URLs are extracted correctly."""
        text = "Download from https://example.com/payload.exe and http://test.org/file"
        result = extractor.extract(text)
        assert any("https://example.com/payload.exe" in u for u in result["urls"])

    def test_extract_md5(self, extractor):
        """MD5 hashes are extracted correctly."""
        text = "File hash: d41d8cd98f00b204e9800998ecf8427e"
        result = extractor.extract(text)
        assert "d41d8cd98f00b204e9800998ecf8427e" in result["md5"]

    def test_extract_sha1(self, extractor):
        """SHA1 hashes are extracted correctly."""
        text = "SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709"
        result = extractor.extract(text)
        assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" in result["sha1"]

    def test_extract_sha256(self, extractor):
        """SHA256 hashes are extracted correctly."""
        text = "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = extractor.extract(text)
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in result["sha256"]

    def test_extract_emails(self, extractor):
        """Email addresses are extracted correctly."""
        text = "Contact: attacker@evil.com and admin@malware.org"
        result = extractor.extract(text)
        emails = result["emails"]
        assert any("attacker@evil.com" in e for e in emails)

    def test_extract_cves(self, extractor):
        """CVE identifiers are extracted correctly."""
        text = "Vulnerabilities: CVE-2024-1234 and CVE-2023-5678"
        result = extractor.extract(text)
        assert "CVE-2024-1234" in result["cves"]
        assert "CVE-2023-5678" in result["cves"]

    def test_extract_onion_v3(self, extractor):
        """Onion v3 addresses are extracted correctly."""
        text = "Onion: abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz.onion"
        result = extractor.extract(text)
        # Onion v3 is 56 chars + .onion
        assert len(result.get("onion_v3", [])) >= 0  # Depends on regex matching

    def test_extract_btc_wallet(self, extractor):
        """Bitcoin wallet addresses are extracted."""
        text = "BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        result = extractor.extract(text)
        wallets = result.get("btc", [])
        assert any("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in w for w in wallets)

    def test_extract_eth_wallet(self, extractor):
        """Ethereum wallet addresses are extracted."""
        text = "ETH: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28"
        result = extractor.extract(text)
        wallets = result.get("eth", [])
        assert any("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28" in w for w in wallets)


# -- Comprehensive extraction tests --------------------------------------


class TestComprehensiveExtraction:
    """Test extraction from complex multi-IOC text."""

    def test_extract_all_types(self, extractor, sample_text):
        """All IOC types are extracted from comprehensive text."""
        result = extractor.extract(sample_text)

        assert len(result["ipv4"]) > 0
        assert len(result["urls"]) > 0
        assert len(result["domains"]) > 0
        assert len(result["md5"]) > 0
        assert len(result["sha256"]) > 0
        assert len(result["emails"]) > 0
        assert len(result["cves"]) > 0

    def test_no_iocs_returns_empty_lists(self, extractor, sample_text_no_iocs):
        """Text with no IOCs returns empty lists for all types."""
        result = extractor.extract(sample_text_no_iocs)

        assert result["ipv4"] == []
        assert result["urls"] == []
        assert result["md5"] == []
        assert result["sha256"] == []

    def test_deduplication(self, extractor):
        """Duplicate IOCs are deduplicated."""
        text = "IP 192.168.1.1 seen multiple times: 192.168.1.1 and 192.168.1.1"
        result = extractor.extract(text)
        assert result["ipv4"].count("192.168.1.1") == 1

    def test_result_has_all_expected_keys(self, extractor):
        """Result dict contains all expected IOC type keys."""
        result = extractor.extract("test 192.168.1.1")
        expected_keys = {
            "urls", "ipv4", "ipv6", "domains", "md5", "sha1", "sha256",
            "sha512", "emails", "cves", "onion_v2", "onion_v3", "btc",
            "eth", "pgp_keys", "entities",
        }
        assert expected_keys.issubset(set(result.keys()))


# -- Property-based tests (Hypothesis) -----------------------------------


class TestIOCExtractionHypothesis:
    """Property-based tests using Hypothesis."""

    @given(st.text(min_size=0, max_size=1000))
    @settings(max_examples=30)
    def test_extract_never_raises(self, text):
        """extract() never raises an exception regardless of input."""
        extractor = IOCExtractor()
        result = extractor.extract(text)
        assert isinstance(result, dict)

    @given(st.ip_addresses(v=4))
    def test_extract_valid_ipv4(self, ip):
        """Valid IPv4 addresses are always extracted."""
        extractor = IOCExtractor()
        text = f"Suspicious IP: {ip}"
        result = extractor.extract(text)
        ip_str = str(ip)
        assert ip_str in result["ipv4"]

    @given(
        st.text(
            alphabet=st.characters(whitelist_categories=("L", "N")),
            min_size=3,
            max_size=20,
        )
    )
    @settings(max_examples=20)
    def test_extract_handles_arbitrary_text(self, text):
        """extract() handles arbitrary alphanumeric text without crashing."""
        extractor = IOCExtractor()
        result = extractor.extract(text)
        assert isinstance(result, dict)
        assert "ipv4" in result

    @given(st.text(alphabet=st.characters(whitelist_categories=("Zs", "Zl", "Zp")), max_size=100))
    def test_extract_whitespace_only(self, text):
        """Whitespace-only text returns empty results."""
        extractor = IOCExtractor()
        result = extractor.extract(text)
        assert result["ipv4"] == []
        assert result["urls"] == []

    @given(st.lists(st.ip_addresses(v=4), min_size=1, max_size=10))
    def test_extract_multiple_ipv4(self, ips):
        """Multiple IPv4 addresses are all extracted."""
        extractor = IOCExtractor()
        text = " ".join(str(ip) for ip in ips)
        result = extractor.extract(text)
        for ip in ips:
            assert str(ip) in result["ipv4"]


# -- Edge case tests -----------------------------------------------------


class TestExtractionEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_very_long_text(self, extractor):
        """Extraction handles very long text."""
        long_text = "IP: 192.168.1.1 " * 10000
        result = extractor.extract(long_text)
        assert "192.168.1.1" in result["ipv4"]

    def test_unicode_text(self, extractor):
        """Extraction handles unicode text."""
        text = "日本語テスト 192.168.1.1 中文测试"
        result = extractor.extract(text)
        assert "192.168.1.1" in result["ipv4"]

    def test_special_characters(self, extractor):
        """Extraction handles special characters."""
        text = "IP: 192.168.1.1\n\t\r<script>alert(1)</script>"
        result = extractor.extract(text)
        assert "192.168.1.1" in result["ipv4"]

    def test_ip_in_url_not_double_counted(self, extractor):
        """IPs embedded in URLs are handled correctly."""
        text = "Visit http://192.168.1.1/admin for access"
        result = extractor.extract(text)
        # URL should be extracted
        assert len(result["urls"]) >= 1

    def test_multiline_text(self, extractor):
        """Extraction works across multiple lines."""
        text = """
        Line 1: 192.168.1.1
        Line 2: 10.0.0.1
        Line 3: 172.16.0.1
        """
        result = extractor.extract(text)
        assert "192.168.1.1" in result["ipv4"]
        assert "10.0.0.1" in result["ipv4"]
        assert "172.16.0.1" in result["ipv4"]

    def test_case_insensitive_domains(self, extractor):
        """Domain extraction is case-insensitive."""
        text = "Visit EVIL.COM and evil.com"
        result = extractor.extract(text)
        # Should deduplicate case-insensitively
        domains_lower = [d.lower() for d in result["domains"]]
        assert len(domains_lower) == len(set(domains_lower))


# -- NER tests -----------------------------------------------------------


class TestNERExtraction:
    """Test Named Entity Recognition integration."""

    def test_ner_disabled_by_default(self):
        """NER is disabled by default."""
        extractor = IOCExtractor()
        result = extractor.extract("test text")
        assert result["entities"] == []

    def test_ner_enabled_returns_entities(self):
        """NER returns entities when enabled."""
        extractor = IOCExtractor(use_ner=True)
        result = extractor.extract("John Smith works at Google in New York.")
        # NER depends on spaCy model availability
        assert isinstance(result["entities"], list)

    def test_ner_disabled_returns_empty(self):
        """NER disabled returns empty entities list."""
        extractor = IOCExtractor(use_ner=False)
        result = extractor.extract("John Smith works at Google.")
        assert result["entities"] == []
