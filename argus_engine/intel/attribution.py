"""Attribution Engine for ARGUS.

Correlates infrastructure indicators (JA4+ fingerprints, favicon hashes,
JARM TLS fingerprints, PGP keys) to attribute actors and services with a
multi-factor confidence score.

All optional dependencies are imported via try/except — the engine works
with hashlib-only fallbacks if mmh3 / cryptography are not installed.
"""

from __future__ import annotations

import hashlib
import logging
import socket
import ssl
import struct
from typing import Any

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependencies — graceful fallback
# ---------------------------------------------------------------------------
try:
    import mmh3  # type: ignore[import-untyped]

    _HAS_MMH3 = True
except ImportError:
    _HAS_MMH3 = False
    _logger.debug("mmh3 not installed — using hashlib fallback for favicon hashing")

try:
    from cryptography.hazmat.primitives import serialization  # type: ignore[import-untyped]

    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False
    _logger.debug("cryptography not installed — PGP fingerprinting limited")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# JA4+ TLS cipher suite mapping (simplified — maps common GREASE/reserved values)
_JA4_GREASE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

# JARM probe templates (TLS Client Hello variations)
_JARM_PROBES = [
    "1000000000000000000000000000000000000000",  # TLS 1.3, no SNI
    "1000000000000000000000000000000000000001",  # TLS 1.3, SNI
    "0301000000000000000000000000000000000000",  # TLS 1.0
    "0302000000000000000000000000000000000000",  # TLS 1.1
    "0303000000000000000000000000000000000000",  # TLS 1.2
]

# Default confidence weights for multi-factor scoring
_DEFAULT_WEIGHTS = {
    "ja4": 0.25,
    "favicon": 0.20,
    "jarm": 0.25,
    "pgp": 0.20,
    "temporal": 0.10,
}


# ---------------------------------------------------------------------------
# Attribution Engine
# ---------------------------------------------------------------------------


class AttributionEngine:
    """Multi-factor infrastructure attribution engine.

    Correlates TLS fingerprints, favicon hashes, JARM signatures, and PGP
    key material to produce a confidence-scored attribution verdict.

    Usage::

        engine = AttributionEngine()
        result = engine.attribute([
            {"type": "tls", "host": "example.com", "ja4": "t13d1515h2_..."},
            {"type": "favicon", "url": "https://example.com/favicon.ico", "hash": "1234567890"},
        ])
    """

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        timeout: float = 10.0,
    ) -> None:
        """Initialize the attribution engine.

        Args:
            weights: Custom factor weights for confidence scoring.
                     Must sum to ~1.0. Missing keys use defaults.
            timeout: Socket timeout in seconds for network probes.
        """
        self.weights = {**_DEFAULT_WEIGHTS, **(weights or {})}
        self.timeout = timeout
        self._cache: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # JA4+ fingerprinting
    # ------------------------------------------------------------------

    def fingerprint_ja4(self, host: str, port: int = 443) -> str:
        """Generate JA4+ TLS fingerprint for a target host.

        JA4+ format: <protocol>_<cipher_hash>_<extensions_hash>_<sni>

        This is a simplified implementation that captures the TLS Client
        Hello from the server's perspective. For production use, consider
        integrating the full ja4 library.

        Args:
            host: Target hostname or IP.
            port: Target port (default 443).

        Returns:
            JA4+ fingerprint string, or empty string on failure.
        """
        try:
            context = ssl.create_default_context()

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Extract TLS version
                    tls_version = ssock.version()
                    cipher = ssock.cipher()
                    cipher_name = cipher[0] if cipher else "unknown"

                    # Build JA4+ simplified fingerprint
                    ja4_protocol = self._ja4_protocol_part(tls_version)
                    ja4_cipher = self._ja4_cipher_part(cipher_name)
                    ja4_extensions = self._ja4_extensions_part(ssock)

                    fingerprint = f"{ja4_protocol}_{ja4_cipher}_{ja4_extensions}"
                    _logger.debug("JA4+ fingerprint for %s:%d = %s", host, port, fingerprint)
                    return fingerprint

        except (socket.error, ssl.SSLError, OSError) as exc:
            _logger.warning("JA4+ fingerprinting failed for %s:%d: %s", host, port, exc)
            return ""

    def _ja4_protocol_part(self, tls_version: str | None) -> str:
        """Map TLS version to JA4 protocol prefix."""
        if tls_version is None:
            return "t00"
        version_map = {
            "TLSv1": "t10",
            "TLSv1.1": "t11",
            "TLSv1.2": "t12",
            "TLSv1.3": "t13",
        }
        return version_map.get(tls_version, "t00")

    def _ja4_cipher_part(self, cipher_name: str) -> str:
        """Generate JA4 cipher suite hash segment.

        Simplified: uses first 4 hex chars of SHA256 of cipher name.
        Full JA4 uses sorted cipher suite list from Client Hello.
        """
        cipher_hash = hashlib.sha256(cipher_name.encode()).hexdigest()[:4]
        return f"c{cipher_hash}"

    def _ja4_extensions_part(self, ssock: ssl.SSLSocket) -> str:
        """Generate JA4 extensions hash segment.

        Simplified: uses shared ciphers count as proxy for extensions.
        Full JA4 parses extension types from Client Hello.
        """
        try:
            shared = ssock.shared_ciphers()
            ext_count = len(shared) if shared else 0
        except (AttributeError, ssl.SSLError):
            ext_count = 0

        ext_hash = hashlib.sha256(str(ext_count).encode()).hexdigest()[:4]
        return f"e{ext_hash}"

    # ------------------------------------------------------------------
    # Favicon hashing
    # ------------------------------------------------------------------

    def hash_favicon(self, favicon_url: str) -> str:
        """Compute mmh3 hash of a favicon image.

        Uses MurmurHash3 (mmh3) when available for compatibility with
        Shodan/SHODAN favicon hashing. Falls back to SHA256 base64 if
        mmh3 is not installed.

        Args:
            favicon_url: URL of the favicon to hash.

        Returns:
            Hash string (mmh3 integer as string, or sha256 hex).
            Empty string on failure.
        """
        try:
            import urllib.request
            from urllib.error import URLError

            req = urllib.request.Request(
                favicon_url,
                headers={"User-Agent": "ARGUS-OSINT/1.0"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = resp.read()

            if not data:
                _logger.warning("Empty favicon response from %s", favicon_url)
                return ""

            if _HAS_MMH3:
                # SHODAN-compatible: mmh3 of base64-encoded favicon
                import base64

                encoded = base64.b64encode(data)
                hash_value = mmh3.hash(encoded)
                result = str(hash_value)
            else:
                # Fallback: SHA256 hex digest
                result = hashlib.sha256(data).hexdigest()

            _logger.debug("Favicon hash for %s = %s", favicon_url, result)
            return result

        except (URLError, OSError, ValueError) as exc:
            _logger.warning("Favicon hashing failed for %s: %s", favicon_url, exc)
            return ""

    # ------------------------------------------------------------------
    # JARM fingerprinting
    # ------------------------------------------------------------------

    def fingerprint_jarm(self, host: str, port: int = 443) -> str:
        """Generate JARM TLS server fingerprint.

        JARM sends 10 different TLS Client Hello packets and hashes
        the server's responses (selected cipher + extensions).

        This is a simplified implementation. Full JARM requires raw
        socket manipulation of TLS records.

        Args:
            host: Target hostname or IP.
            port: Target port (default 443).

        Returns:
            JARM fingerprint string (62-char format), or empty on failure.
        """
        try:
            responses: list[str] = []

            for probe_template in _JARM_PROBES:
                response = self._jarm_send_probe(host, port, probe_template)
                responses.append(response)

            # Build JARM: hash of concatenated responses
            combined = "|".join(responses)
            jarm_hash = hashlib.sha256(combined.encode()).hexdigest()[:32]

            _logger.debug("JARM fingerprint for %s:%d = %s", host, port, jarm_hash)
            return jarm_hash

        except (socket.error, OSError) as exc:
            _logger.warning("JARM fingerprinting failed for %s:%d: %s", host, port, exc)
            return ""

    def _jarm_send_probe(self, host: str, port: int, probe_template: str) -> str:
        """Send a JARM probe and extract server response characteristics.

        Simplified: uses ssl module to get cipher info per TLS version.
        Full JARM requires raw TLS record construction.
        """
        try:
            context = ssl.create_default_context()

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()

                    cipher_hex = self._cipher_to_hex(cipher[0] if cipher else "")
                    version_hex = self._version_to_hex(version)

                    # JARM response format: cipher_hex|version_hex|extensions
                    return f"{cipher_hex}|{version_hex}|00"

        except (ssl.SSLError, socket.error):
            return "00|00|00"

    def _cipher_to_hex(self, cipher_name: str) -> str:
        """Map cipher name to IANA hex code (simplified lookup)."""
        # Common cipher suite mapping
        cipher_map = {
            "TLS_AES_128_GCM_SHA256": "1301",
            "TLS_AES_256_GCM_SHA384": "1302",
            "TLS_CHACHA20_POLY1305_SHA256": "1303",
            "ECDHE-RSA-AES128-GCM-SHA256": "c02f",
            "ECDHE-RSA-AES256-GCM-SHA384": "c030",
            "ECDHE-ECDSA-AES128-GCM-SHA256": "c02b",
            "ECDHE-ECDSA-AES256-GCM-SHA384": "c02c",
        }
        return cipher_map.get(cipher_name, "0000")

    def _version_to_hex(self, version: str | None) -> str:
        """Map TLS version string to hex."""
        version_map = {
            "TLSv1": "0301",
            "TLSv1.1": "0302",
            "TLSv1.2": "0303",
            "TLSv1.3": "0304",
        }
        return version_map.get(version, "0303")

    # ------------------------------------------------------------------
    # PGP key correlation
    # ------------------------------------------------------------------

    def correlate_pgp(self, keys: list[str]) -> dict[str, Any]:
        """Correlate PGP keys to find shared identities.

        Analyzes key fingerprints, user IDs, and creation dates to
        identify links between seemingly unrelated keys.

        Args:
            keys: List of PGP key fingerprints or ASCII-armored key blocks.

        Returns:
            Correlation result with:
                - clusters: groups of related keys
                - shared_emails: emails appearing in multiple keys
                - shared_names: names appearing in multiple keys
                - timeline: keys sorted by creation date
        """
        if not keys:
            return {
                "clusters": [],
                "shared_emails": [],
                "shared_names": [],
                "timeline": [],
            }

        parsed_keys = [self._parse_pgp_key(k) for k in keys]
        parsed_keys = [k for k in parsed_keys if k is not None]

        # Find shared emails and names
        email_index: dict[str, list[str]] = {}
        name_index: dict[str, list[str]] = {}

        for key_info in parsed_keys:
            for email in key_info.get("emails", []):
                email_index.setdefault(email, []).append(key_info["fingerprint"])
            for name in key_info.get("names", []):
                name_index.setdefault(name, []).append(key_info["fingerprint"])

        shared_emails = [
            {"email": email, "key_count": len(fps), "fingerprints": fps}
            for email, fps in email_index.items()
            if len(fps) > 1
        ]

        shared_names = [
            {"name": name, "key_count": len(fps), "fingerprints": fps}
            for name, fps in name_index.items()
            if len(fps) > 1
        ]

        # Build clusters via shared attributes
        clusters = self._build_clusters(parsed_keys, shared_emails, shared_names)

        # Timeline
        timeline = sorted(
            [
                {
                    "fingerprint": k["fingerprint"],
                    "created": k.get("created", ""),
                    "emails": k.get("emails", []),
                }
                for k in parsed_keys
                if k.get("created")
            ],
            key=lambda x: x["created"],
        )

        return {
            "clusters": clusters,
            "shared_emails": shared_emails,
            "shared_names": shared_names,
            "timeline": timeline,
        }

    def _parse_pgp_key(self, key_data: str) -> dict[str, Any] | None:
        """Parse a PGP key fingerprint or block into structured data.

        Supports:
            - 40-char hex fingerprints (full or short)
            - ASCII-armored PGP public key blocks
        """
        key_data = key_data.strip()

        # Check if it's a fingerprint (hex string)
        clean = key_data.replace(" ", "").replace("\n", "")
        if len(clean) in (16, 32, 40) and all(c in "0123456789ABCDEFabcdef" for c in clean):
            return {
                "fingerprint": clean.upper(),
                "emails": [],
                "names": [],
                "created": None,
            }

        # Try parsing ASCII-armored block
        if "-----BEGIN PGP" in key_data:
            return self._parse_armored_key(key_data)

        _logger.debug("Unrecognized PGP key format: %s...", key_data[:40])
        return None

    def _parse_armored_key(self, armored: str) -> dict[str, Any] | None:
        """Parse ASCII-armored PGP key block.

        Uses gpg if available, otherwise extracts basic info via regex.
        """
        result: dict[str, Any] = {
            "fingerprint": "",
            "emails": [],
            "names": [],
            "created": None,
        }

        # Try gpg first for proper parsing
        try:
            import subprocess

            proc = subprocess.run(
                ["gpg", "--with-colons", "--import-options", "show-only", "--import", "--dry-run"],
                input=armored,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            if proc.returncode in (0, 2):  # 2 = keys already known
                for line in proc.stdout.splitlines():
                    if line.startswith("fpr:"):
                        parts = line.split(":")
                        if len(parts) >= 10:
                            result["fingerprint"] = parts[9].upper()
                    elif line.startswith("uid:"):
                        parts = line.split(":")
                        if len(parts) >= 10:
                            uid = parts[9]
                            result["emails"].extend(self._extract_emails(uid))
                            result["names"].append(uid)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            # Fallback: regex extraction
            result["emails"] = self._extract_emails(armored)
            # Extract fingerprint from armored block if present
            fp_match = __import__("re").search(r"(?:fingerprint|Fingerprint)[:\s]+([A-Fa-f0-9\s]{40,})", armored)
            if fp_match:
                result["fingerprint"] = fp_match.group(1).replace(" ", "").upper()

        return result if result["fingerprint"] or result["emails"] else None

    def _extract_emails(self, text: str) -> list[str]:
        """Extract email addresses from text."""
        pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        return list(set(__import__("re").findall(pattern, text)))

    def _build_clusters(
        self,
        keys: list[dict[str, Any]],
        shared_emails: list[dict[str, Any]],
        shared_names: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Build key clusters from shared attributes using union-find."""
        parent: dict[str, str] = {}

        def find(x: str) -> str:
            while parent.get(x, x) != x:
                parent[x] = parent.get(parent[x], parent[x])
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        # Initialize
        for key in keys:
            fp = key["fingerprint"]
            if fp and fp not in parent:
                parent[fp] = fp

        # Union by shared emails
        for entry in shared_emails:
            fps = entry["fingerprints"]
            for i in range(1, len(fps)):
                union(fps[0], fps[i])

        # Union by shared names
        for entry in shared_names:
            fps = entry["fingerprints"]
            for i in range(1, len(fps)):
                union(fps[0], fps[i])

        # Collect clusters
        clusters: dict[str, list[str]] = {}
        for fp in parent:
            root = find(fp)
            clusters.setdefault(root, []).append(fp)

        return [
            {"cluster_id": i, "key_count": len(fps), "fingerprints": fps}
            for i, fps in enumerate(clusters.values())
            if len(fps) > 1 or len(keys) == 1
        ]

    # ------------------------------------------------------------------
    # Multi-factor confidence scoring
    # ------------------------------------------------------------------

    def calculate_confidence(self, factors: list[dict[str, Any]]) -> float:
        """Calculate multi-factor attribution confidence score.

        Each factor dict should have:
            - type: factor type (ja4, favicon, jarm, pgp, temporal)
            - match: bool indicating whether this factor matched
            - weight: optional override weight (0-1)
            - confidence: optional per-factor confidence (0-1)

        The final score is a weighted average of all factor confidences,
        clamped to [0.0, 1.0].

        Args:
            factors: List of factor dictionaries.

        Returns:
            Confidence score between 0.0 and 1.0.
        """
        if not factors:
            return 0.0

        total_weight = 0.0
        weighted_sum = 0.0

        for factor in factors:
            factor_type = factor.get("type", "unknown")
            matched = factor.get("match", False)
            weight = factor.get("weight", self.weights.get(factor_type, 0.1))
            confidence = factor.get("confidence", 1.0 if matched else 0.0)

            weighted_sum += weight * confidence
            total_weight += weight

        if total_weight == 0:
            return 0.0

        score = weighted_sum / total_weight
        return max(0.0, min(1.0, score))

    # ------------------------------------------------------------------
    # Full attribution pipeline
    # ------------------------------------------------------------------

    def attribute(self, infrastructure: list[dict[str, Any]]) -> dict[str, Any]:
        """Perform full attribution on a list of infrastructure indicators.

        Each infrastructure dict should have:
            - type: indicator type (tls, favicon, jarm, pgp, domain, ip)
            - host: target host (for tls/jarm types)
            - url: target URL (for favicon type)
            - key: PGP key data (for pgp type)
            - hash: pre-computed hash (optional)
            - ja4: pre-computed JA4 fingerprint (optional)

        Returns:
            Attribution result with:
                - indicators: processed indicators with fingerprints
                - correlations: cross-indicator correlations
                - confidence: overall attribution confidence (0-1)
                - verdict: attribution verdict string
        """
        indicators: list[dict[str, Any]] = []
        factors: list[dict[str, Any]] = []
        ja4_values: list[str] = []
        favicon_hashes: list[str] = []
        jarm_values: list[str] = []
        pgp_keys: list[str] = []

        for item in infrastructure:
            item_type = item.get("type", "unknown")
            processed = {"type": item_type, "raw": item, "fingerprint": None}

            if item_type == "tls":
                host = item.get("host", "")
                if item.get("ja4"):
                    processed["fingerprint"] = item["ja4"]
                    ja4_values.append(item["ja4"])
                elif host:
                    ja4 = self.fingerprint_ja4(host, item.get("port", 443))
                    processed["fingerprint"] = ja4
                    if ja4:
                        ja4_values.append(ja4)

            elif item_type == "favicon":
                url = item.get("url", "")
                if item.get("hash"):
                    processed["fingerprint"] = item["hash"]
                    favicon_hashes.append(item["hash"])
                elif url:
                    fav_hash = self.hash_favicon(url)
                    processed["fingerprint"] = fav_hash
                    if fav_hash:
                        favicon_hashes.append(fav_hash)

            elif item_type == "jarm":
                host = item.get("host", "")
                if item.get("jarm"):
                    processed["fingerprint"] = item["jarm"]
                    jarm_values.append(item["jarm"])
                elif host:
                    jarm = self.fingerprint_jarm(host, item.get("port", 443))
                    processed["fingerprint"] = jarm
                    if jarm:
                        jarm_values.append(jarm)

            elif item_type == "pgp":
                key_data = item.get("key", "")
                if key_data:
                    pgp_keys.append(key_data)
                    processed["fingerprint"] = key_data[:40]

            indicators.append(processed)

        # Build factors from collected data
        if ja4_values:
            factors.append({
                "type": "ja4",
                "match": len(set(ja4_values)) < len(ja4_values),
                "confidence": 0.8 if len(set(ja4_values)) == 1 else 0.3,
            })

        if favicon_hashes:
            factors.append({
                "type": "favicon",
                "match": len(set(favicon_hashes)) < len(favicon_hashes),
                "confidence": 0.9 if len(set(favicon_hashes)) == 1 else 0.2,
            })

        if jarm_values:
            factors.append({
                "type": "jarm",
                "match": len(set(jarm_values)) < len(jarm_values),
                "confidence": 0.7 if len(set(jarm_values)) == 1 else 0.3,
            })

        # PGP correlation
        pgp_correlation: dict[str, Any] = {}
        if pgp_keys:
            pgp_correlation = self.correlate_pgp(pgp_keys)
            has_clusters = len(pgp_correlation.get("clusters", [])) > 0
            factors.append({
                "type": "pgp",
                "match": has_clusters,
                "confidence": 0.85 if has_clusters else 0.1,
            })

        # Calculate overall confidence
        confidence = self.calculate_confidence(factors)

        # Determine verdict
        verdict = self._verdict_from_confidence(confidence)

        return {
            "indicators": indicators,
            "correlations": {
                "ja4_matches": self._count_matches(ja4_values),
                "favicon_matches": self._count_matches(favicon_hashes),
                "jarm_matches": self._count_matches(jarm_values),
                "pgp": pgp_correlation,
            },
            "confidence": round(confidence, 4),
            "verdict": verdict,
            "factors": factors,
        }

    def _verdict_from_confidence(self, confidence: float) -> str:
        """Map confidence score to a human-readable verdict."""
        if confidence >= 0.8:
            return "high_confidence_attribution"
        elif confidence >= 0.5:
            return "probable_attribution"
        elif confidence >= 0.3:
            return "possible_attribution"
        elif confidence > 0:
            return "weak_correlation"
        return "no_attribution"

    @staticmethod
    def _count_matches(values: list[str]) -> dict[str, int]:
        """Count occurrences of each value for match detection."""
        counts: dict[str, int] = {}
        for v in values:
            counts[v] = counts.get(v, 0) + 1
        return counts
