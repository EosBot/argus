"""Tests for GeoLocator with TTL cache."""

import time
from unittest.mock import MagicMock, patch

import pytest

from argus_engine.intel.geolocate import GeoLocator, _TTLCache


class TestGeoLocator:
    """Test suite for GeoLocator."""

    def test_init(self):
        """GeoLocator should initialize with defaults."""
        locator = GeoLocator()
        assert locator._timeout == 10

    def test_init_with_tokens(self):
        """GeoLocator should accept API tokens."""
        locator = GeoLocator(
            ipinfo_token="test-ipinfo",
            shodan_api_key="test-shodan",
        )
        assert locator._ipinfo_token == "test-ipinfo"
        assert locator._shodan_api_key == "test-shodan"

    def test_proxy_is_applied_to_external_requests(self):
        locator = GeoLocator(proxy_url="socks5h://tor:9050")
        assert locator._proxies == {
            "http": "socks5h://tor:9050",
            "https": "socks5h://tor:9050",
        }

    def test_geolocate_ip_invalid(self):
        """geolocate_ip should handle invalid IPs."""
        locator = GeoLocator()
        result = locator.geolocate_ip("not-an-ip")
        assert result == {}

    def test_geolocate_ip_with_mock(self):
        """geolocate_ip should parse IPinfo response."""
        locator = GeoLocator()
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "ip": "8.8.8.8",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "loc": "37.3860,-122.0838",
            "org": "Google LLC",
            "postal": "94035",
            "timezone": "America/Los_Angeles",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.get", return_value=mock_response):
            result = locator.geolocate_ip("8.8.8.8")

        assert result["ip"] == "8.8.8.8"
        assert result["city"] == "Mountain View"
        assert result["country"] == "US"
        assert result["latitude"] == 37.386
        assert result["longitude"] == -122.0838

    def test_geolocate_ip_cached(self):
        """geolocate_ip should cache results."""
        locator = GeoLocator()
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "ip": "8.8.8.8",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "loc": "37.3860,-122.0838",
            "org": "Google LLC",
            "postal": "94035",
            "timezone": "America/Los_Angeles",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.get", return_value=mock_response) as mock_get:
            result1 = locator.geolocate_ip("8.8.8.8")
            result2 = locator.geolocate_ip("8.8.8.8")
            # Should only make one request due to caching
            assert mock_get.call_count == 1

    def test_discover_subdomains_with_mock(self):
        """discover_subdomains should parse crt.sh response."""
        locator = GeoLocator()
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"name_value": "sub1.example.com\nsub2.example.com"},
            {"name_value": "*.example.com"},
        ]
        mock_response.raise_for_status = MagicMock()

        with patch("requests.get", return_value=mock_response):
            result = locator.discover_subdomains("example.com")

        assert "sub1.example.com" in result
        assert "sub2.example.com" in result

    def test_search_shodan_no_key(self):
        """search_shodan should return empty without API key."""
        locator = GeoLocator()
        result = locator.search_shodan("8.8.8.8")
        assert result == []

    def test_search_shodan_with_mock(self):
        """search_shodan should parse Shodan response."""
        locator = GeoLocator(shodan_api_key="test-key")
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "matches": [
                {
                    "ip_str": "8.8.8.8",
                    "port": 53,
                    "hostnames": ["dns.google"],
                    "org": "Google LLC",
                    "isp": "Google LLC",
                    "asn": "AS15169",
                    "location": {"country_code": "US"},
                    "timestamp": "2024-01-01",
                    "product": "Google DNS",
                    "version": "1.0",
                    "data": "test data",
                }
            ]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.get", return_value=mock_response):
            result = locator.search_shodan("8.8.8.8")

        assert len(result) >= 1
        assert result[0]["ip"] == "8.8.8.8"
        assert result[0]["port"] == 53

    def test_correlate(self):
        """correlate should group infrastructure data."""
        locator = GeoLocator()
        infrastructure = [
            {"ip": "1.1.1.1", "org": "Cloudflare", "asn": "AS13335", "country": "US", "port": 443},
            {"ip": "1.1.2.2", "org": "Cloudflare", "asn": "AS13335", "country": "US", "port": 80},
            {"ip": "2.2.2.2", "org": "Google", "asn": "AS15169", "country": "US", "port": 443},
        ]
        result = locator.correlate(infrastructure)
        assert "Cloudflare" in result["by_org"]
        assert "Google" in result["by_org"]
        assert result["summary"]["total"] == 3
        assert result["summary"]["unique_orgs"] == 2

    def test_correlate_relationships(self):
        """correlate should identify relationships."""
        locator = GeoLocator()
        infrastructure = [
            {"ip": "1.1.1.1", "org": "Cloudflare", "asn": "AS13335", "country": "US"},
            {"ip": "1.1.2.2", "org": "Cloudflare", "asn": "AS13335", "country": "US"},
        ]
        result = locator.correlate(infrastructure)
        assert len(result["relationships"]) >= 1

    def test_to_map_data(self):
        """to_map_data should convert locations to plotly format."""
        locator = GeoLocator()
        locations = [
            {"lat": 37.386, "lon": -122.0838, "label": "Google"},
            {"lat": 37.7749, "lon": -122.4194, "label": "SF"},
        ]
        result = locator.to_map_data(locations)
        assert len(result["lat"]) == 2
        assert len(result["lon"]) == 2
        assert result["type"] == "scattergeo"
        assert result["mode"] == "markers"

    def test_to_map_data_skips_invalid(self):
        """to_map_data should skip invalid locations."""
        locator = GeoLocator()
        locations = [
            {"lat": 37.386, "lon": -122.0838},
            {"lat": None, "lon": None},
            {"label": "no coords"},
        ]
        result = locator.to_map_data(locations)
        assert len(result["lat"]) == 1

    def test_to_map_data_empty(self):
        """to_map_data should handle empty locations."""
        locator = GeoLocator()
        result = locator.to_map_data([])
        assert result["lat"] == []
        assert result["lon"] == []

    def test_clear_cache(self):
        """clear_cache should clear all cached results."""
        locator = GeoLocator()
        locator._cache.set("value", "key")
        locator.clear_cache()
        hit, _ = locator._cache.get("key")
        assert hit is False

    def test_geolocate_ip_request_failure(self):
        """geolocate_ip should handle request failures gracefully."""
        import requests as req
        mock_cache = MagicMock()
        mock_cache.get.return_value = (False, None)
        locator = GeoLocator()
        locator._cache = mock_cache
        with patch("argus_engine.intel.geolocate.requests.get", side_effect=req.RequestException("Connection error")):
            result = locator.geolocate_ip("8.8.8.8")
        assert result == {}

    def test_discover_subdomains_request_failure(self):
        """discover_subdomains should handle request failures."""
        import requests as req
        mock_cache = MagicMock()
        mock_cache.get.return_value = (False, None)
        locator = GeoLocator()
        locator._cache = mock_cache
        with patch("argus_engine.intel.geolocate.requests.get", side_effect=req.RequestException("Connection error")):
            result = locator.discover_subdomains("example.com")
        assert result == []
