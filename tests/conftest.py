"""Shared fixtures for all test modules.

Provides common test data, mock objects, and setup/teardown
for unit, integration, e2e, security, eval, and performance tests.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# -- Path setup ----------------------------------------------------------


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Return the project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture(scope="session")
def argus_engine_root(project_root: Path) -> Path:
    """Return the ARGUS engine package root directory."""
    return project_root / "argus_engine"


# -- Sample data fixtures ------------------------------------------------


@pytest.fixture
def sample_text() -> str:
    """Sample text containing various IOC types for extraction tests."""
    return """
    Investigation Report #2024-001
    ================================

    Suspicious activity detected from IP 192.168.1.100 and 10.0.0.55.
    Also observed traffic from 172.16.0.1:8080.

    Malicious domains: evil-c2.example.com, malware-drop.xyz
    Onion address: abcdef1234567890.onion

    File hashes:
    - MD5: d41d8cd98f00b204e9800998ecf8427e
    - SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
    - SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

    Contact: attacker@evil-c2.example.com
    Backup: badactor@protonmail.com

    CVEs: CVE-2024-1234, CVE-2023-5678

    URLs: https://evil-c2.example.com/payload.exe
    http://malware-drop.xyz/download?file=bad

    BTC wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    ETH wallet: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28

    IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
    """


@pytest.fixture
def sample_text_minimal() -> str:
    """Minimal sample text with a single IOC."""
    return "Suspicious IP: 192.168.1.1 detected."


@pytest.fixture
def sample_text_no_iocs() -> str:
    """Text with no IOCs."""
    return "This is a completely benign text with no indicators of compromise."


@pytest.fixture
def mock_api_responses() -> dict:
    """Mock responses for external API calls."""
    return {
        "shodan": {
            "ip": "192.168.1.100",
            "ports": [80, 443, 8080],
            "hostnames": ["evil-c2.example.com"],
            "vulns": ["CVE-2024-1234"],
            "data": [],
        },
        "virustotal": {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 15,
                        "suspicious": 3,
                        "undetected": 50,
                        "harmless": 0,
                    },
                    "reputation": -100,
                }
            }
        },
        "greynoise": {
            "ip": "192.168.1.100",
            "noise": True,
            "riot": False,
            "classification": "malicious",
            "name": "unknown",
            "link": "https://www.greynoise.io/viz/ip/192.168.1.100",
        },
        "censys": {
            "result": {
                "services": [
                    {"port": 80, "service_name": "HTTP"},
                    {"port": 443, "service_name": "HTTPS"},
                ]
            }
        },
    }


# -- Directory fixtures --------------------------------------------------


@pytest.fixture
def temp_dir() -> Path:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


@pytest.fixture
def temp_file(temp_dir: Path) -> Path:
    """Create a temporary file with sample content."""
    f = temp_dir / "test_file.txt"
    f.write_text("Sample content for testing.")
    return f


# -- IOC Extractor fixtures ----------------------------------------------


@pytest.fixture
def ioc_extractor():
    """Create an IOCExtractor instance."""
    from argus_engine.intel.ioc_extractor import IOCExtractor

    return IOCExtractor()


@pytest.fixture
def ioc_extractor_with_ner():
    """Create an IOCExtractor instance with NER enabled."""
    from argus_engine.intel.ioc_extractor import IOCExtractor

    return IOCExtractor(use_ner=True)


# -- Browser Sanitizer fixtures ------------------------------------------


@pytest.fixture
def browser_sanitizer():
    """Create a browser Sanitizer instance."""
    from argus_engine.browser.sanitizer import Sanitizer

    return Sanitizer()


# -- Mock environment fixtures -------------------------------------------


@pytest.fixture
def mock_env_vars():
    """Set up mock environment variables for testing."""
    env_vars = {
        "VIRUSTOTAL_API_KEY": "test_vt_key_12345",
        "SHODAN_API_KEY": "test_shodan_key_12345",
        "GREYNOISE_API_KEY": "test_greynoise_key_12345",
        "CENSYS_API_ID": "test_censys_id",
        "CENSYS_API_SECRET": "test_censys_secret",
    }
    with patch.dict(os.environ, env_vars, clear=False):
        yield env_vars


# -- Hypothesis settings ------------------------------------------------


from hypothesis import settings, Verbosity

settings.register_profile("ci", max_examples=50, deadline=5000)
settings.register_profile("dev", max_examples=10, deadline=2000)
settings.register_profile("thorough", max_examples=200, deadline=10000)

# Use "dev" profile by default for speed
settings.load_profile("dev")
