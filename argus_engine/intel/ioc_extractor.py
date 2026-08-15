"""IOC Extraction Pipeline for ARGUS.

Extracts Indicators of Compromise from text and web pages using
iocextract, spaCy NER, and trafilatura with regex fallback.

All optional dependencies are imported via try/except — the extractor
works with regex-only if iocextract/spaCy/trafilatura are not installed.
"""

from __future__ import annotations

import re
import logging
from typing import Any

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependencies — graceful fallback
# ---------------------------------------------------------------------------
try:
    import iocextract  # type: ignore[import-untyped]

    _HAS_IOCEXTRACT = True
except ImportError:
    _HAS_IOCEXTRACT = False
    _logger.debug("iocextract not installed — using regex fallback for IOC extraction")

try:
    import spacy  # type: ignore[import-untyped]

    _HAS_SPACY = True
except ImportError:
    _HAS_SPACY = False
    _logger.debug("spaCy not installed — NER enrichment disabled")

try:
    import trafilatura  # type: ignore[import-untyped]

    _HAS_TRAFILATURA = True
except ImportError:
    _HAS_TRAFILATURA = False
    _logger.debug("trafilatura not installed — using basic HTML stripping")

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# IPv4 — strict octet bounds (0-255)
_IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4 = rf"(?:(?:{_IPV4_OCTET}\.){{3}}{_IPV4_OCTET})"

# IPv6 — compressed and full forms
_IPV6 = (
    r"(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,7}:|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|"
    r"[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|"
    r":(?::[0-9A-Fa-f]{1,4}){1,7}|"
    r"::(?:[fF]{4}:)?(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}|"
    r"(?:[0-9A-Fa-f]{1,4}:){1,4}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"
    r")"
)

# URLs — http(s), ftp, and generic scheme://
_URL = (
    r"(?:https?|ftp)://"
    r"(?:[^\s<>\"'\)\]\}]+)"
)

# Domains — generic TLD-aware pattern
_DOMAIN = (
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}"
)

# Email
_EMAIL = r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"

# Hashes
_MD5 = r"\b[A-Fa-f0-9]{32}\b"
_SHA1 = r"\b[A-Fa-f0-9]{40}\b"
_SHA256 = r"\b[A-Fa-f0-9]{64}\b"
_SHA512 = r"\b[A-Fa-f0-9]{128}\b"

# CVE identifiers
_CVE = r"CVE-\d{4}-\d{4,}"

# Onion addresses (v2: 16 chars, v3: 56 chars)
_ONION_V2 = r"[a-z2-7]{16}\.onion"
_ONION_V3 = r"[a-z2-7]{56}\.onion"

# Cryptocurrency wallets
_BTC = r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b"
_ETH = r"\b0x[a-fA-F0-9]{40}\b"

# PGP key fingerprints (40 hex chars or spaced blocks)
_PGP_FINGERPRINT = r"(?:[A-Fa-f0-9]{4}\s){9}[A-Fa-f0-9]{4}"
_PGP_LONG_KEY = r"\b[A-Fa-f0-9]{40}\b"

# Compile all patterns
_RE_URL = re.compile(_URL, re.IGNORECASE)
_RE_IPV4 = re.compile(_IPV4)
_RE_IPV6 = re.compile(_IPV6, re.IGNORECASE)
_RE_DOMAIN = re.compile(_DOMAIN)
_RE_EMAIL = re.compile(_EMAIL, re.IGNORECASE)
_RE_MD5 = re.compile(_MD5)
_RE_SHA1 = re.compile(_SHA1)
_RE_SHA256 = re.compile(_SHA256)
_RE_SHA512 = re.compile(_SHA512)
_RE_CVE = re.compile(_CVE, re.IGNORECASE)
_RE_ONION_V2 = re.compile(_ONION_V2, re.IGNORECASE)
_RE_ONION_V3 = re.compile(_ONION_V3, re.IGNORECASE)
_RE_BTC = re.compile(_BTC)
_RE_ETH = re.compile(_ETH)
_RE_PGP_FINGERPRINT = re.compile(_PGP_FINGERPRINT)
_RE_PGP_LONG_KEY = re.compile(_PGP_LONG_KEY)


class IOCExtractor:
    """Extract Indicators of Compromise from text and web pages.

    Uses iocextract when available, spaCy NER for entity enrichment,
    and trafilatura for HTML-to-text extraction. Falls back to regex
    when optional dependencies are missing.

    Example::

        extractor = IOCExtractor()
        iocs = extractor.extract("Check http://evil.com and 1.2.3.4")
        iocs["urls"]   # ["http://evil.com"]
        iocs["ipv4"]   # ["1.2.3.4"]
    """

    def __init__(self, use_ner: bool = True) -> None:
        """Initialize the IOC extractor.

        Args:
            use_ner: Whether to use spaCy NER for entity extraction.
        """
        self.use_ner = use_ner and _HAS_SPACY
        self._nlp: Any = None

        if self.use_ner:
            self._load_spacy_model()

    def _load_spacy_model(self) -> None:
        """Load spaCy English model, downloading if necessary."""
        try:
            self._nlp = spacy.load("en_core_web_sm")
        except OSError:
            _logger.debug("spaCy model 'en_core_web_sm' not found — NER disabled")
            self.use_ner = False
            self._nlp = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self, text: str) -> dict[str, list[str]]:
        """Extract IOCs from the given text.

        Args:
            text: Raw text to analyze.

        Returns:
            Dictionary mapping IOC type to list of unique values found.
        """
        if not text:
            return self._empty_result()

        result: dict[str, list[str]] = {}

        # URLs
        result["urls"] = self._extract_urls(text)

        # IPs
        result["ipv4"] = self._extract_ipv4(text)
        result["ipv6"] = self._extract_ipv6(text)

        # Domains (exclude URLs and onions already captured)
        result["domains"] = self._extract_domains(text, result["urls"])

        # Hashes
        result["md5"] = self._extract_hashes(text, "md5")
        result["sha1"] = self._extract_hashes(text, "sha1")
        result["sha256"] = self._extract_hashes(text, "sha256")
        result["sha512"] = self._extract_hashes(text, "sha512")

        # Emails
        result["emails"] = self._extract_emails(text)

        # CVEs
        result["cves"] = self._extract_cves(text)

        # Onion addresses
        result["onion_v2"] = self._extract_onion_v2(text)
        result["onion_v3"] = self._extract_onion_v3(text)

        # Wallets
        result["btc"] = self._extract_btc(text)
        result["eth"] = self._extract_eth(text)

        # PGP keys
        result["pgp_keys"] = self._extract_pgp_keys(text)

        # NER entities (optional)
        if self.use_ner:
            entities = self._extract_ner_entities(text)
            result["entities"] = entities
        else:
            result["entities"] = []

        return result

    def extract_from_url(self, url: str) -> dict[str, list[str]]:
        """Fetch a web page and extract IOCs from its content.

        Args:
            url: URL to fetch and analyze.

        Returns:
            Dictionary mapping IOC type to list of unique values found.
        """
        text = self._fetch_page(url)
        if not text:
            return self._empty_result()
        return self.extract(text)

    # ------------------------------------------------------------------
    # URL fetching
    # ------------------------------------------------------------------

    def _fetch_page(self, url: str) -> str:
        """Fetch page content and extract clean text."""
        try:
            import requests
        except ImportError:
            _logger.debug("requests not installed — cannot fetch URL")
            return ""

        try:
            resp = requests.get(
                url,
                timeout=(5, 25),
                headers={
                    "User-Agent": "ARGUS-OSINT/1.0",
                    "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
                },
                verify=True,
            )
            resp.raise_for_status()
            html = resp.text

            if _HAS_TRAFILATURA:
                text = trafilatura.extract(
                    html,
                    include_comments=False,
                    include_tables=False,
                    no_fallback=False,
                ) or ""
            else:
                text = self._basic_html_strip(html)

            return text
        except Exception as exc:
            _logger.debug("Failed to fetch URL %s: %s", url, exc)
            return ""

    @staticmethod
    def _basic_html_strip(html: str) -> str:
        """Minimal HTML tag stripping fallback."""
        # Remove script/style blocks first
        text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.DOTALL | re.IGNORECASE)
        # Remove remaining tags
        text = re.sub(r"<[^>]+>", " ", text)
        # Decode common entities
        text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&#39;", "'")
        # Normalize whitespace
        return " ".join(text.split())

    # ------------------------------------------------------------------
    # Extraction methods
    # ------------------------------------------------------------------

    def _extract_urls(self, text: str) -> list[str]:
        """Extract URLs using iocextract or regex fallback."""
        urls: list[str] = []

        if _HAS_IOCEXTRACT:
            try:
                urls = list(iocextract.extract_urls(text, refang=True))
            except Exception as exc:
                _logger.debug("iocextract URL extraction failed: %s", exc)

        if not urls:
            urls = _RE_URL.findall(text)

        return self._deduplicate(urls)

    def _extract_ipv4(self, text: str) -> list[str]:
        """Extract IPv4 addresses."""
        if _HAS_IOCEXTRACT:
            try:
                ips = list(iocextract.extract_ipv4s(text, refang=True))
                if ips:
                    return self._deduplicate(ips)
            except Exception as exc:
                _logger.debug("iocextract IPv4 extraction failed: %s", exc)

        return self._deduplicate(_RE_IPV4.findall(text))

    def _extract_ipv6(self, text: str) -> list[str]:
        """Extract IPv6 addresses."""
        return self._deduplicate(_RE_IPV6.findall(text))

    def _extract_domains(self, text: str, urls: list[str]) -> list[str]:
        """Extract domains, excluding those already in URLs."""
        if _HAS_IOCEXTRACT:
            try:
                domains = list(iocextract.extract_urls(text, refang=True))
                # iocextract has extract_domains too
                raw_domains = list(iocextract.extract_urls(text))
                # Use the dedicated function if available
                if hasattr(iocextract, "extract_domains"):
                    domains = list(iocextract.extract_domains(text, refang=True))
                else:
                    domains = _RE_DOMAIN.findall(text)
            except Exception as exc:
                _logger.debug("iocextract domain extraction failed: %s", exc)
                domains = _RE_DOMAIN.findall(text)
        else:
            domains = _RE_DOMAIN.findall(text)

        # Filter out onion addresses and domains already in URLs
        url_set = {u.lower() for u in urls}
        filtered: list[str] = []
        seen: set[str] = set()

        for d in domains:
            d_lower = d.lower()
            if d_lower in seen:
                continue
            if d_lower.endswith(".onion"):
                continue
            seen.add(d_lower)
            filtered.append(d)

        return filtered

    def _extract_hashes(self, text: str, algorithm: str) -> list[str]:
        """Extract hash values by algorithm type."""
        pattern_map = {
            "md5": _RE_MD5,
            "sha1": _RE_SHA1,
            "sha256": _RE_SHA256,
            "sha512": _RE_SHA512,
        }
        pattern = pattern_map.get(algorithm)
        if not pattern:
            return []

        if _HAS_IOCEXTRACT:
            try:
                hashes = list(iocextract.extract_hashes(text))
                # Filter by length to match algorithm
                length_map = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
                target_len = length_map[algorithm]
                filtered = [h for h in hashes if len(h) == target_len]
                if filtered:
                    return self._deduplicate(filtered)
            except Exception as exc:
                _logger.debug("iocextract hash extraction failed: %s", exc)

        return self._deduplicate(pattern.findall(text))

    def _extract_emails(self, text: str) -> list[str]:
        """Extract email addresses."""
        if _HAS_IOCEXTRACT:
            try:
                emails = list(iocextract.extract_emails(text, refang=True))
                if emails:
                    return self._deduplicate(emails, normalize_lowercase=True)
            except Exception as exc:
                _logger.debug("iocextract email extraction failed: %s", exc)

        return self._deduplicate(_RE_EMAIL.findall(text), normalize_lowercase=True)

    def _extract_cves(self, text: str) -> list[str]:
        """Extract CVE identifiers."""
        if _HAS_IOCEXTRACT:
            try:
                cves = list(iocextract.extract_cves(text))
                if cves:
                    return self._deduplicate(cves)
            except Exception as exc:
                _logger.debug("iocextract CVE extraction failed: %s", exc)

        return self._deduplicate(_RE_CVE.findall(text))

    def _extract_onion_v2(self, text: str) -> list[str]:
        """Extract v2 onion addresses (16-char)."""
        if _HAS_IOCEXTRACT:
            try:
                onions = list(iocextract.extract_iocs(text).get("onion_addresses", []))
                v2 = [o for o in onions if len(o.replace(".onion", "")) == 16]
                if v2:
                    return self._deduplicate(v2)
            except Exception:
                pass
        return self._deduplicate(_RE_ONION_V2.findall(text))

    def _extract_onion_v3(self, text: str) -> list[str]:
        """Extract v3 onion addresses (56-char)."""
        if _HAS_IOCEXTRACT:
            try:
                onions = list(iocextract.extract_iocs(text).get("onion_addresses", []))
                v3 = [o for o in onions if len(o.replace(".onion", "")) == 56]
                if v3:
                    return self._deduplicate(v3)
            except Exception:
                pass
        return self._deduplicate(_RE_ONION_V3.findall(text))

    def _extract_btc(self, text: str) -> list[str]:
        """Extract Bitcoin addresses."""
        return self._deduplicate(_RE_BTC.findall(text))

    def _extract_eth(self, text: str) -> list[str]:
        """Extract Ethereum addresses."""
        return self._deduplicate(_RE_ETH.findall(text))

    def _extract_pgp_keys(self, text: str) -> list[str]:
        """Extract PGP key fingerprints."""
        fingerprints = _RE_PGP_FINGERPRINT.findall(text)
        # Also look for long hex strings that could be key IDs
        long_keys = _RE_PGP_LONG_KEY.findall(text)
        # Filter out hashes already captured (MD5/SHA1 lengths)
        long_keys = [
            k for k in long_keys
            if len(k) == 40 and not _RE_SHA1.fullmatch(k)
        ]
        return self._deduplicate(fingerprints + long_keys)

    def _extract_ner_entities(self, text: str) -> list[dict[str, str]]:
        """Extract named entities using spaCy NER."""
        if not self.use_ner or self._nlp is None:
            return []

        try:
            doc = self._nlp(text[:100_000])  # Limit text length for performance
            entities: list[dict[str, str]] = []
            seen: set[tuple[str, str]] = set()

            for ent in doc.ents:
                if ent.label_ in ("PERSON", "ORG", "GPE", "LOC", "NORP", "FAC"):
                    key = (ent.text.lower(), ent.label_)
                    if key not in seen:
                        seen.add(key)
                        entities.append({
                            "text": ent.text,
                            "label": ent.label_,
                        })
            return entities
        except Exception as exc:
            _logger.debug("spaCy NER extraction failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate(items: list[str], normalize_lowercase: bool = False) -> list[str]:
        """Deduplicate items while preserving order."""
        seen: set[str] = set()
        result: list[str] = []
        for item in items:
            key = item.lower() if normalize_lowercase else item
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result

    @staticmethod
    def _empty_result() -> dict[str, list[str]]:
        """Return an empty result dictionary."""
        return {
            "urls": [],
            "ipv4": [],
            "ipv6": [],
            "domains": [],
            "md5": [],
            "sha1": [],
            "sha256": [],
            "sha512": [],
            "emails": [],
            "cves": [],
            "onion_v2": [],
            "onion_v3": [],
            "btc": [],
            "eth": [],
            "pgp_keys": [],
            "entities": [],
        }
