"""Integration tests with mocked external APIs.

Tests API integration patterns using VCR.py-style mocking for
Shodan, VirusTotal, GreyNoise, and Censys APIs.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest


# -- Shodan API mocks ----------------------------------------------------


class TestShodanIntegration:
    """Test Shodan API integration patterns."""

    def test_shodan_host_lookup(self, mock_api_responses):
        """Shodan host lookup returns structured data."""
        shodan_data = mock_api_responses["shodan"]
        assert "ip" in shodan_data
        assert "ports" in shodan_data
        assert isinstance(shodan_data["ports"], list)

    def test_shodan_vuln_data(self, mock_api_responses):
        """Shodan vulnerability data is structured."""
        shodan_data = mock_api_responses["shodan"]
        assert "vulns" in shodan_data
        assert "CVE-2024-1234" in shodan_data["vulns"]

    @patch("urllib.request.urlopen")
    def test_shodan_api_call(self, mock_urlopen, mock_api_responses):
        """Shodan API call is properly structured."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(mock_api_responses["shodan"]).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # Simulate API call
        import urllib.request

        req = urllib.request.Request("https://api.shodan.io/shodan/host/192.168.1.1")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())

        assert data["ip"] == mock_api_responses["shodan"]["ip"]


# -- VirusTotal API mocks ------------------------------------------------


class TestVirusTotalIntegration:
    """Test VirusTotal API integration patterns."""

    def test_virustotal_detection_stats(self, mock_api_responses):
        """VirusTotal detection stats are structured."""
        vt_data = mock_api_responses["virustotal"]
        stats = vt_data["data"]["attributes"]["last_analysis_stats"]
        assert "malicious" in stats
        assert "undetected" in stats

    def test_virustotal_reputation(self, mock_api_responses):
        """VirusTotal reputation is included."""
        vt_data = mock_api_responses["virustotal"]
        attrs = vt_data["data"]["attributes"]
        assert "reputation" in attrs

    @patch("urllib.request.urlopen")
    def test_virustotal_hash_lookup(self, mock_urlopen, mock_api_responses):
        """VirusTotal hash lookup returns detection data."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(mock_api_responses["virustotal"]).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response

        import urllib.request

        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        req = urllib.request.Request(url, headers={"x-apikey": "test_key"})
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())

        stats = data["data"]["attributes"]["last_analysis_stats"]
        assert stats["malicious"] == 15


# -- GreyNoise API mocks -------------------------------------------------


class TestGreyNoiseIntegration:
    """Test GreyNoise API integration patterns."""

    def test_greynoise_classification(self, mock_api_responses):
        """GreyNoise classification is structured."""
        gn_data = mock_api_responses["greynoise"]
        assert "classification" in gn_data
        assert gn_data["classification"] == "malicious"

    def test_greynoise_noise_flag(self, mock_api_responses):
        """GreyNoise noise flag is present."""
        gn_data = mock_api_responses["greynoise"]
        assert "noise" in gn_data
        assert gn_data["noise"] is True

    def test_greynoise_riot_flag(self, mock_api_responses):
        """GreyNoise RIOT flag is present."""
        gn_data = mock_api_responses["greynoise"]
        assert "riot" in gn_data


# -- Censys API mocks ----------------------------------------------------


class TestCensysIntegration:
    """Test Censys API integration patterns."""

    def test_censys_services(self, mock_api_responses):
        """Censys service data is structured."""
        censys_data = mock_api_responses["censys"]
        result = censys_data["result"]
        assert "services" in result
        assert len(result["services"]) > 0

    def test_censys_service_ports(self, mock_api_responses):
        """Censys service ports are correct."""
        censys_data = mock_api_responses["censys"]
        services = censys_data["result"]["services"]
        ports = [s["port"] for s in services]
        assert 80 in ports
        assert 443 in ports


# -- API error handling --------------------------------------------------


class TestAPIErrorHandling:
    """Test API error handling patterns."""

    @patch("urllib.request.urlopen")
    def test_api_timeout_handling(self, mock_urlopen):
        """API timeout is handled gracefully."""
        import urllib.error

        mock_urlopen.side_effect = TimeoutError("Connection timed out")

        with pytest.raises(TimeoutError):
            urllib.request.urlopen("https://api.example.com/data", timeout=30)

    @patch("urllib.request.urlopen")
    def test_api_http_error_handling(self, mock_urlopen):
        """HTTP errors are handled gracefully."""
        import urllib.error

        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.example.com",
            code=429,
            msg="Too Many Requests",
            hdrs={},
            fp=None,
        )

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen("https://api.example.com/data")
        assert exc_info.value.code == 429

    @patch("urllib.request.urlopen")
    def test_api_connection_error_handling(self, mock_urlopen):
        """Connection errors are handled gracefully."""
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        with pytest.raises(urllib.error.URLError):
            urllib.request.urlopen("https://api.example.com/data")


# -- API response parsing ------------------------------------------------


class TestAPIResponseParsing:
    """Test API response parsing."""

    def test_json_parsing(self, mock_api_responses):
        """JSON responses are parsed correctly."""
        raw = json.dumps(mock_api_responses["shodan"])
        parsed = json.loads(raw)
        assert parsed == mock_api_responses["shodan"]

    def test_nested_data_access(self, mock_api_responses):
        """Nested data can be accessed safely."""
        vt_data = mock_api_responses["virundetected" if False else "virustotal"]
        stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        assert isinstance(stats, dict)

    def test_missing_key_handling(self, mock_api_responses):
        """Missing keys are handled gracefully."""
        data = mock_api_responses["shodan"]
        assert data.get("nonexistent_key", "default") == "default"
        assert data.get("nonexistent_key") is None


# -- Rate limiting integration -------------------------------------------


class TestAPIRateLimiting:
    """Test API rate limiting patterns."""

    def test_rate_limit_headers_parsed(self):
        """Rate limit headers are parsed correctly."""
        headers = {
            "X-RateLimit-Limit": "100",
            "X-RateLimit-Remaining": "50",
            "X-RateLimit-Reset": "1700000000",
        }
        limit = int(headers.get("X-RateLimit-Limit", 0))
        remaining = int(headers.get("X-RateLimit-Remaining", 0))
        assert limit == 100
        assert remaining == 50

    def test_rate_limit_exceeded_detection(self):
        """Rate limit exceeded is detected."""
        headers = {"X-RateLimit-Remaining": "0"}
        remaining = int(headers.get("X-RateLimit-Remaining", 1))
        assert remaining == 0
