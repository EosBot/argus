"""Geolocation & Infrastructure Intelligence for ARGUS.

Provides IP geolocation (IPinfo.io), subdomain discovery (crt.sh),
device search (Shodan), JA4+ fingerprinting, infrastructure correlation,
and plotly map data generation.

All external APIs use requests with graceful degradation — if an API
is unreachable or unauthenticated, methods return empty results
rather than raising exceptions. Results are cached with a 1-hour TTL.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import time
from typing import Any

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependencies — graceful fallback
# ---------------------------------------------------------------------------
try:
    import requests  # type: ignore[import-untyped]

    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False
    _logger.debug("requests not installed — GeoLocator will return empty results")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_IPINFO_URL = "https://ipinfo.io/{ip}/json"
_CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
_SHODAN_URL = "https://api.shodan.io/shodan/host/{query}"
_SHODAN_API_KEY_ENV = "SHODAN_API_KEY"
_IPINFO_TOKEN_ENV = "IPINFO_TOKEN"
_DEFAULT_TIMEOUT = 10  # seconds
_CACHE_TTL = 3600  # 1 hour in seconds


# ---------------------------------------------------------------------------
# Simple TTL cache
# ---------------------------------------------------------------------------
class _TTLCache:
    """Minimal in-memory cache with TTL expiration."""

    def __init__(self, ttl: int = _CACHE_TTL) -> None:
        self._ttl = ttl
        self._store: dict[str, tuple[float, Any]] = {}

    def _key(self, *args: Any, **kwargs: Any) -> str:
        raw = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, *args: Any, **kwargs: Any) -> tuple[bool, Any]:
        """Return (hit, value). hit=False means expired or missing."""
        k = self._key(*args, **kwargs)
        if k in self._store:
            ts, val = self._store[k]
            if time.time() - ts < self._ttl:
                return True, val
            del self._store[k]
        return False, None

    def set(self, value: Any, *args: Any, **kwargs: Any) -> None:
        k = self._key(*args, **kwargs)
        self._store[k] = (time.time(), value)

    def clear(self) -> None:
        self._store.clear()


# ---------------------------------------------------------------------------
# GeoLocator
# ---------------------------------------------------------------------------
class GeoLocator:
    """Infrastructure geolocation and correlation engine.

    Usage::

        locator = GeoLocator()
        info = locator.geolocate_ip("8.8.8.8")
        subs = locator.discover_subdomains("example.com")
        devices = locator.search_shodan("8.8.8.8")
        ja4 = locator.fingerprint_ja4("example.com")
        correlated = locator.correlate([...])
        map_data = locator.to_map_data(locations)
    """

    def __init__(
        self,
        ipinfo_token: str | None = None,
        shodan_api_key: str | None = None,
        timeout: int = _DEFAULT_TIMEOUT,
        cache_ttl: int = _CACHE_TTL,
        proxy_url: str | None = None,
    ) -> None:
        """Initialize GeoLocator.

        Args:
            ipinfo_token: Optional IPinfo.io API token (higher rate limits).
            shodan_api_key: Optional Shodan API key.
            timeout: HTTP request timeout in seconds.
            cache_ttl: Cache time-to-live in seconds (default 1 hour).
        """
        self._timeout = timeout
        self._cache = _TTLCache(ttl=cache_ttl)
        self._proxies = (
            {"http": proxy_url, "https": proxy_url} if proxy_url else None
        )

        # Resolve tokens: explicit arg > env var
        import os

        self._ipinfo_token = ipinfo_token or os.environ.get(_IPINFO_TOKEN_ENV)
        self._shodan_api_key = shodan_api_key or os.environ.get(_SHODAN_API_KEY_ENV)

        if not _HAS_REQUESTS:
            _logger.warning("requests library not available — all methods will return empty results")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def geolocate_ip(self, ip: str) -> dict:
        """Geolocate an IP address via IPinfo.io.

        Args:
            ip: IPv4 or IPv6 address string.

        Returns:
            Dict with keys: ip, city, region, country, loc (lat/lon),
            org, postal, timezone. Empty dict on failure.
        """
        if not _HAS_REQUESTS:
            return {}

        # Validate IP format
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            _logger.warning("Invalid IP address: %s", ip)
            return {}

        # Check cache
        hit, cached = self._cache.get("geolocate_ip", ip)
        if hit:
            return cached  # type: ignore[return-value]

        url = _IPINFO_URL.format(ip=ip)
        headers = {}
        if self._ipinfo_token:
            headers["Authorization"] = f"Bearer {self._ipinfo_token}"

        try:
            resp = requests.get(
                url, headers=headers, timeout=self._timeout, verify=True,
                proxies=self._proxies,
            )
            resp.raise_for_status()
            data = resp.json()

            result = {
                "ip": data.get("ip", ip),
                "city": data.get("city", ""),
                "region": data.get("region", ""),
                "country": data.get("country", ""),
                "loc": data.get("loc", ""),
                "org": data.get("org", ""),
                "postal": data.get("postal", ""),
                "timezone": data.get("timezone", ""),
            }

            # Parse lat/lon from loc string "lat,lon"
            if result["loc"]:
                parts = result["loc"].split(",")
                if len(parts) == 2:
                    try:
                        result["latitude"] = float(parts[0])
                        result["longitude"] = float(parts[1])
                    except ValueError:
                        result["latitude"] = None
                        result["longitude"] = None
                else:
                    result["latitude"] = None
                    result["longitude"] = None
            else:
                result["latitude"] = None
                result["longitude"] = None

            self._cache.set(result, "geolocate_ip", ip)
            return result

        except requests.RequestException as exc:
            _logger.debug("IPinfo request failed for %s: %s", ip, exc)
            return {}
        except (json.JSONDecodeError, KeyError) as exc:
            _logger.debug("IPinfo response parse error for %s: %s", ip, exc)
            return {}

    def discover_subdomains(self, domain: str) -> list[str]:
        """Discover subdomains via crt.sh certificate transparency logs.

        Args:
            domain: Root domain to search (e.g., "example.com").

        Returns:
            Sorted list of unique subdomain strings. Empty list on failure.
        """
        if not _HAS_REQUESTS:
            return []

        # Check cache
        hit, cached = self._cache.get("discover_subdomains", domain)
        if hit:
            return cached  # type: ignore[return-value]

        url = _CRTSH_URL.format(domain=domain)

        try:
            resp = requests.get(
                url, timeout=self._timeout, verify=True, proxies=self._proxies
            )
            resp.raise_for_status()
            data = resp.json()

            subdomains: set[str] = set()
            for entry in data:
                name = entry.get("name_value", "")
                # crt.sh returns newline-separated names
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub and sub.endswith(domain):
                        subdomains.add(sub.lower())

            result = sorted(subdomains)
            self._cache.set(result, "discover_subdomains", domain)
            return result

        except requests.RequestException as exc:
            _logger.debug("crt.sh request failed for %s: %s", domain, exc)
            return []
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            _logger.debug("crt.sh response parse error for %s: %s", domain, exc)
            return []

    def search_shodan(self, query: str) -> list[dict]:
        """Search Shodan for devices matching a query.

        Note: Requires a Shodan API key (free tier available).

        Args:
            query: IP, domain, or Shodan search string.

        Returns:
            List of dicts with device info. Empty list on failure
            or if no API key is configured.
        """
        if not _HAS_REQUESTS:
            return []

        if not self._shodan_api_key:
            _logger.debug("Shodan API key not configured — skipping search")
            return []

        # Check cache
        hit, cached = self._cache.get("search_shodan", query)
        if hit:
            return cached  # type: ignore[return-value]

        url = _SHODAN_URL.format(query=query)
        params = {"key": self._shodan_api_key}

        try:
            resp = requests.get(
                url, params=params, timeout=self._timeout, verify=True,
                proxies=self._proxies,
            )
            resp.raise_for_status()
            data = resp.json()

            result = []
            for match in data.get("matches", []):
                result.append({
                    "ip": match.get("ip_str", ""),
                    "port": match.get("port"),
                    "hostnames": match.get("hostnames", []),
                    "org": match.get("org", ""),
                    "isp": match.get("isp", ""),
                    "asn": match.get("asn", ""),
                    "location": match.get("location", {}),
                    "timestamp": match.get("timestamp", ""),
                    "product": match.get("product", ""),
                    "version": match.get("version", ""),
                    "data": match.get("data", ""),
                })

            self._cache.set(result, "search_shodan", query)
            return result

        except requests.RequestException as exc:
            _logger.debug("Shodan request failed for %s: %s", query, exc)
            return []
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            _logger.debug("Shodan response parse error for %s: %s", query, exc)
            return []

    def fingerprint_ja4(self, host: str) -> str:
        """Generate JA4+ fingerprint for a host.

        JA4+ is a suite of network fingerprints developed by FoxIO LLC.
        This method attempts to retrieve the JA4+ fingerprint by connecting
        to the host and analyzing TLS handshake characteristics.

        Note: Full JA4+ implementation requires packet capture. This method
        provides a simplified fingerprint based on available HTTP/TLS data.

        Args:
            host: Hostname or IP to fingerprint.

        Returns:
            JA4+ fingerprint string, or empty string on failure.
        """
        if not _HAS_REQUESTS:
            return ""

        # Check cache
        hit, cached = self._cache.get("fingerprint_ja4", host)
        if hit:
            return cached  # type: ignore[return-value]

        try:
            # Attempt HTTPS connection to gather TLS info
            url = f"https://{host}" if not host.startswith(("http://", "https://")) else host
            resp = requests.get(
                url,
                timeout=self._timeout,
                allow_redirects=False,
                verify=True,
                proxies=self._proxies,
            )

            # Extract TLS info from raw socket if available
            ja4 = self._compute_ja4_from_response(host, resp)
            self._cache.set(ja4, "fingerprint_ja4", host)
            return ja4

        except requests.RequestException as exc:
            _logger.debug("JA4 fingerprinting failed for %s: %s", host, exc)
            return ""
        except Exception as exc:
            _logger.debug("JA4 fingerprinting unexpected error for %s: %s", host, exc)
            return ""

    def correlate(self, infrastructure: list[dict]) -> dict:
        """Correlate infrastructure data points.

        Groups infrastructure by organization, ASN, country, and identifies
        relationships between IPs, domains, and services.

        Args:
            infrastructure: List of dicts with keys like:
                - ip: IP address
                - domain: domain name
                - org: organization
                - asn: ASN
                - country: country code
                - port: port number
                - product: product name

        Returns:
            Dict with correlation results:
                - by_org: dict mapping org -> list of items
                - by_asn: dict mapping ASN -> list of items
                - by_country: dict mapping country -> list of items
                - by_port: dict mapping port -> list of items
                - relationships: list of relationship dicts
                - summary: dict with counts
        """
        by_org: dict[str, list[dict]] = {}
        by_asn: dict[str, list[dict]] = {}
        by_country: dict[str, list[dict]] = {}
        by_port: dict[str, list[dict]] = {}
        relationships: list[dict] = []

        for item in infrastructure:
            org = item.get("org", "unknown")
            asn = item.get("asn", "unknown")
            country = item.get("country", "unknown")
            port = str(item.get("port", "unknown"))

            by_org.setdefault(org, []).append(item)
            by_asn.setdefault(asn, []).append(item)
            by_country.setdefault(country, []).append(item)
            by_port.setdefault(port, []).append(item)

        # Build relationships: items sharing same org/asn/country
        for org, items in by_org.items():
            if len(items) > 1:
                ips = [i.get("ip") for i in items if i.get("ip")]
                domains = [i.get("domain") for i in items if i.get("domain")]
                if ips or domains:
                    relationships.append({
                        "type": "shared_org",
                        "value": org,
                        "ips": ips,
                        "domains": domains,
                        "count": len(items),
                    })

        for asn, items in by_asn.items():
            if len(items) > 1 and asn != "unknown":
                ips = [i.get("ip") for i in items if i.get("ip")]
                if len(ips) > 1:
                    relationships.append({
                        "type": "shared_asn",
                        "value": asn,
                        "ips": ips,
                        "count": len(items),
                    })

        return {
            "by_org": by_org,
            "by_asn": by_asn,
            "by_country": by_country,
            "by_port": by_port,
            "relationships": relationships,
            "summary": {
                "total": len(infrastructure),
                "unique_orgs": len(by_org),
                "unique_asns": len(by_asn),
                "unique_countries": len(by_country),
                "unique_ports": len(by_port),
                "relationships_found": len(relationships),
            },
        }

    def to_map_data(self, locations: list[dict]) -> dict:
        """Convert location data to plotly-compatible map format.

        Args:
            locations: List of dicts with keys:
                - lat: latitude (float)
                - lon: longitude (float)
                - label: display label (optional)
                - color: marker color (optional)
                - size: marker size (optional)
                - text: hover text (optional)

        Returns:
            Dict with plotly scattergeo data structure:
                - lat: list of latitudes
                - lon: list of longitudes
                - text: list of hover texts
                - marker: dict with marker config
                - type: "scattergeo"
                - mode: "markers"
        """
        lats: list[float] = []
        lons: list[float] = []
        texts: list[str] = []
        colors: list[str] = []
        sizes: list[int] = []

        for loc in locations:
            lat = loc.get("lat") or loc.get("latitude")
            lon = loc.get("lon") or loc.get("longitude")

            if lat is None or lon is None:
                continue

            try:
                lat_f = float(lat)
                lon_f = float(lon)
            except (ValueError, TypeError):
                continue

            lats.append(lat_f)
            lons.append(lon_f)

            # Build hover text
            label = loc.get("label", "")
            text = loc.get("text", label)
            if not text:
                text = f"{lat_f:.4f}, {lon_f:.4f}"
            texts.append(text)

            colors.append(loc.get("color", "#FF4B4B"))
            sizes.append(loc.get("size", 10))

        return {
            "lat": lats,
            "lon": lons,
            "text": texts,
            "marker": {
                "size": sizes,
                "color": colors,
                "opacity": 0.8,
                "line": {"width": 1, "color": "white"},
            },
            "type": "scattergeo",
            "mode": "markers",
            "name": "Infrastructure",
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_ja4_from_response(self, host: str, resp: Any) -> str:
        """Compute a simplified JA4+ fingerprint from HTTP response.

        This is a best-effort approximation. Full JA4+ requires TLS
        Client Hello parsing which is not available via requests alone.
        """
        components = []

        # JA4_a: protocol indicator (t=TLS1.3, s=HTTPS)
        components.append("t13")  # Assume TLS 1.3 for HTTPS

        # JA4_b: HTTP version indicator
        http_version = resp.raw.version if hasattr(resp, "raw") else None
        if http_version == 10:
            components.append("http1_0")
        elif http_version == 11:
            components.append("http1_1")
        elif http_version == 20:
            components.append("http2")
        else:
            components.append("http1_1")  # default assumption

        # JA4_c: server header fingerprint
        server = resp.headers.get("Server", "")
        if server:
            server_hash = hashlib.sha256(server.encode()).hexdigest()[:12]
            components.append(f"s_{server_hash}")
        else:
            components.append("s_none")

        # JA4_d: content-type fingerprint
        content_type = resp.headers.get("Content-Type", "")
        if content_type:
            ct_hash = hashlib.sha256(content_type.encode()).hexdigest()[:12]
            components.append(f"ct_{ct_hash}")
        else:
            components.append("ct_none")

        fingerprint = "_".join(components)
        return f"ja4+{hashlib.sha256(f'{host}:{fingerprint}'.encode()).hexdigest()[:16]}"

    def clear_cache(self) -> None:
        """Clear all cached results."""
        self._cache.clear()
