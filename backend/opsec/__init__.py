"""ARGUS 2.0 — OPSEC & Operational Security Package.

This package provides the operational security layer for the ARGUS backend:

    - TorManager: Stem-based circuit rotation (NEWNYM) with cooldown
    - TimingRandomizer: Jitter + adaptive delays based on response codes
    - FingerprintRotator: User-Agent, canvas, WebGL fingerprint randomization
    - OPSECPreFlight: DNS leak test, Tor circuit validation, SOCKS5 proxy test
    - SupplyChainSecurity: Hash pinning for dependencies, SBOM generation
    - ChainOfVerification: Anti-hallucination verification for LLM outputs
    - SourceReliability: F6 NATO reporting standard (A-F reliability, 1-6 credibility)

All components expose async interfaces with graceful degradation when
optional dependencies (stem, aiohttp) are unavailable.
"""

from backend.opsec.tor_manager import TorManager, CircuitStatus
from backend.opsec.timing import TimingRandomizer, TimingProfile
from backend.opsec.fingerprint import FingerprintRotator, BrowserProfile
from backend.opsec.preflight import OPSECPreFlight, PreFlightResult
from backend.opsec.supply_chain import SupplyChainSecurity, SBOMResult
from backend.opsec.verification import ChainOfVerification, VerificationResult
from backend.opsec.reliability import SourceReliability, ReliabilityScore

__all__ = [
    "TorManager",
    "CircuitStatus",
    "TimingRandomizer",
    "TimingProfile",
    "FingerprintRotator",
    "BrowserProfile",
    "OPSECPreFlight",
    "PreFlightResult",
    "SupplyChainSecurity",
    "SBOMResult",
    "ChainOfVerification",
    "VerificationResult",
    "SourceReliability",
    "ReliabilityScore",
]
