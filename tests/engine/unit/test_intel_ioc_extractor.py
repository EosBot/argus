"""Tests for IOCExtractor."""

import pytest

from argus_engine.intel.ioc_extractor import IOCExtractor


class TestIOCExtractor:
    """Test suite for IOCExtractor."""

    def test_extract_empty_text(self):
        """extract should return empty results for empty text."""
        extractor = IOCExtractor(use_ner=False)
        result = extractor.extract("")
        assert result["urls"] == []
        assert result["ipv4"] == []
        assert result["domains"] == []

    def test_extract_none_text(self):
        """extract should return empty results for None text."""
        extractor = IOCExtractor(use_ner=False)
        result = extractor.extract(None)
        assert result["urls"] == []

    def test_extract_ipv4(self):
        """extract should find IPv4 addresses."""
        extractor = IOCExtractor(use_ner=False)
        result = extractor.extract("Server at 192.168.1.1 and 10.0.0.1")
        assert "192.168.1.1" in result["ipv4"]
        assert "10.0.0.1" in result["ipv4"]

    def test_extract_urls(self):
        """extract should find URLs."""
        extractor = IOCExtractor(use_ner=False)
        result = extractor.extract("Visit http://example.com and https://test.org/path")
        assert len(result["urls"]) >= 1

    def test_extract_domains(self):
        """extract should find domains."""
        extractor = IOCExtractor(use_ner=False)
        result = extractor.extract("Check example.com and test.org")
        assert len(result["domains"]) >= 1

    def test_extract_emails(self):
        """extract should find email addresses."""
        extractor = IOCExtractor(use_ner=False)
        result = extractor.extract("Contact user@example.com")
        assert "user@example.com" in result["emails"]

    def test_extract_md5(self):
        """extract should find MD5 hashes."""
        extractor = IOCExtractor(use_ner=False)
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        result = extractor.extract(f"Hash: {md5_hash}")
        assert md5_hash in result["md5"]

    def test_extract_sha256(self):
        """extract should find SHA256 hashes."""
        extractor = IOCExtractor(use_ner=False)
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = extractor.extract(f"Hash: {sha256_hash}")
        assert sha256_hash in result["sha256"]

    def test_extract_cve(self):
        """extract should find CVE identifiers."""
        extractor = IOCExtractor(use_ner=False)
        result = extractor.extract("Vulnerability CVE-2024-1234 found")
        assert "CVE-2024-1234" in result["cves"]

    def test_extract_onion_v3(self):
        """extract should find v3 onion addresses."""
        extractor = IOCExtractor(use_ner=False)
        onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567abcd.onion"
        result = extractor.extract(f"Visit {onion}")
        assert len(result["onion_v3"]) >= 1

    def test_extract_btc(self):
        """extract should find Bitcoin addresses."""
        extractor = IOCExtractor(use_ner=False)
        result = extractor.extract("Send to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
        assert len(result["btc"]) >= 1

    def test_extract_eth(self):
        """extract should find Ethereum addresses."""
        extractor = IOCExtractor(use_ner=False)
        eth_addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD08"
        result = extractor.extract(f"Send to {eth_addr}")
        assert eth_addr in result["eth"]

    def test_extract_deduplicates(self):
        """extract should deduplicate results."""
        extractor = IOCExtractor(use_ner=False)
        result = extractor.extract("192.168.1.1 192.168.1.1 192.168.1.1")
        assert result["ipv4"].count("192.168.1.1") == 1

    def test_extract_returns_all_keys(self):
        """extract should always return all IOC type keys."""
        extractor = IOCExtractor(use_ner=False)
        result = extractor.extract("test")
        expected_keys = [
            "urls", "ipv4", "ipv6", "domains", "md5", "sha1", "sha256",
            "sha512", "emails", "cves", "onion_v2", "onion_v3", "btc",
            "eth", "pgp_keys", "entities"
        ]
        for key in expected_keys:
            assert key in result, f"Missing key: {key}"

    def test_extract_complex_text(self):
        """extract should handle complex text with multiple IOC types."""
        extractor = IOCExtractor(use_ner=False)
        text = """
        Malware sample from http://evil.com/malware.exe
        connects to 192.168.100.50 on port 443.
        C2 domain: command.example.org
        MD5: d41d8cd98f00b204e9800998ecf8427e
        CVE-2024-5678
        Contact: attacker@evil.com
        """
        result = extractor.extract(text)
        assert len(result["urls"]) >= 1
        assert "192.168.100.50" in result["ipv4"]
        assert len(result["emails"]) >= 1

    def test_empty_result_structure(self):
        """_empty_result should return correct structure."""
        result = IOCExtractor._empty_result()
        assert isinstance(result, dict)
        assert all(isinstance(v, list) for v in result.values())

    def test_deduplicate_preserves_order(self):
        """_deduplicate should preserve insertion order."""
        result = IOCExtractor._deduplicate(["b", "a", "b", "c", "a"])
        assert result == ["b", "a", "c"]

    def test_deduplicate_lowercase(self):
        """_deduplicate with normalize_lowercase should work case-insensitively."""
        result = IOCExtractor._deduplicate(
            ["User@Example.com", "user@example.com", "OTHER@TEST.COM"],
            normalize_lowercase=True
        )
        assert len(result) == 2

    def test_extract_from_url_empty(self):
        """extract_from_url should handle fetch failures gracefully."""
        extractor = IOCExtractor(use_ner=False)
        # Without mocking requests, this should return empty result
        result = extractor.extract_from_url("http://nonexistent.invalid")
        assert isinstance(result, dict)
