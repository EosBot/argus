"""Unified security audit module.

Runs a comprehensive set of security checks and returns a scored report
with actionable recommendations.

Checks:
    1. DNS leak test       — reuses OPSECPreFlight.check_dns_leak()
    2. Tor circuit validation — reuses TorManager.validate_connection()
    3. JWT secret strength — detects default/weak JWT secrets
    4. CORS origins        — detects wildcard (*) CORS configuration
    5. Rate limiting       — verifies rate limiter is configured
    6. Dependency vulnerabilities — runs pip-audit or safety (30s timeout)
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from datetime import datetime, timezone
from typing import Any, Final

from backend.core.config import settings

logger = logging.getLogger(__name__)

# Default JWT secret that must be changed before production
_DEFAULT_JWT_SECRET: Final = "change-me-in-production-32-char-min"

# Minimum recommended JWT secret length (bytes)
_MIN_JWT_SECRET_LENGTH: Final = 32

# Score weights per check (must sum to 100)
_SCORE_WEIGHTS: Final = {
    "dns_leak": 15,
    "tor_circuit": 20,
    "jwt_secret": 20,
    "cors_origins": 15,
    "rate_limiting": 15,
    "dependencies": 15,
}


def _grade(score: int) -> str:
    """Map numeric score to letter grade."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


class SecurityAuditor:
    """Runs unified security checks and produces a scored audit report."""

    async def run_audit(self) -> dict[str, Any]:
        """Execute all security checks concurrently.

        Returns:
            dict with score, max_score, grade, checks[], recommendations[], timestamp.
        """
        checks: list[dict[str, Any]] = []
        recommendations: list[str] = []

        # Run all checks concurrently
        results = await asyncio.gather(
            self._check_dns_leak(),
            self._check_tor_circuit(),
            self._check_jwt_secret(),
            self._check_cors(),
            self._check_rate_limiting(),
            self._check_dependencies(),
        )

        for check in results:
            checks.append(check)
            rec = check.get("recommendation")
            if rec:
                recommendations.append(rec)

        # Calculate score
        score = 0
        for check in checks:
            name = check["name"]
            weight = _SCORE_WEIGHTS.get(name, 0)
            status = check["status"]
            if status == "pass":
                score += weight
            elif status == "warn":
                score += weight // 2
            # fail = 0

        return {
            "score": score,
            "max_score": 100,
            "grade": _grade(score),
            "checks": checks,
            "recommendations": recommendations,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def _check_dns_leak(self) -> dict[str, Any]:
        """Check for DNS leaks via OPSECPreFlight."""
        name = "dns_leak"
        try:
            from backend.opsec.preflight import OPSECPreFlight

            preflight = OPSECPreFlight()
            check_name, passed, details = await preflight.check_dns_leak()

            if passed:
                return {
                    "name": name,
                    "status": "pass",
                    "detail": f"DNS leak test passed (endpoint: {details.get('endpoint', 'unknown')})",
                }
            warning = details.get("warning")
            if warning:
                return {
                    "name": name,
                    "status": "warn",
                    "detail": warning,
                    "recommendation": "Install aiohttp to enable DNS leak verification",
                }
            return {
                "name": name,
                "status": "fail",
                "detail": details.get("error", "DNS leak test failed"),
                "recommendation": "Ensure Tor SOCKS proxy is running and DNS queries are routed through it",
            }
        except Exception as exc:
            logger.exception("DNS leak check failed")
            return {
                "name": name,
                "status": "warn",
                "detail": f"Check error: {exc}",
                "recommendation": "Verify OPSEC preflight module is available",
            }

    async def _check_tor_circuit(self) -> dict[str, Any]:
        """Validate Tor circuit via TorManager."""
        name = "tor_circuit"
        try:
            from backend.opsec.tor_manager import TorManager

            manager = TorManager()
            valid = await manager.validate_connection()

            if valid:
                return {
                    "name": name,
                    "status": "pass",
                    "detail": "Tor ControlPort connection validated successfully",
                }
            return {
                "name": name,
                "status": "warn",
                "detail": "Tor ControlPort not reachable or authentication failed",
                "recommendation": "Ensure Tor is running with ControlPort enabled and TOR_CONTROL_PASSWORD is set",
            }
        except Exception as exc:
            logger.exception("Tor circuit check failed")
            return {
                "name": name,
                "status": "warn",
                "detail": f"Check error: {exc}",
                "recommendation": "Verify Stem is installed and Tor ControlPort is accessible",
            }

    async def _check_jwt_secret(self) -> dict[str, Any]:
        """Check JWT secret strength — detect default or weak secrets."""
        name = "jwt_secret"
        secret = settings.jwt_secret_key

        if secret == _DEFAULT_JWT_SECRET:
            return {
                "name": name,
                "status": "fail",
                "detail": "JWT secret is set to the default value",
                "recommendation": "Set a strong JWT_SECRET_KEY via environment variable (at least 32 random characters)",
            }

        if len(secret) < _MIN_JWT_SECRET_LENGTH:
            return {
                "name": name,
                "status": "warn",
                "detail": f"JWT secret is only {len(secret)} characters (minimum {_MIN_JWT_SECRET_LENGTH} recommended)",
                "recommendation": "Use a JWT secret of at least 32 random characters",
            }

        return {
            "name": name,
            "status": "pass",
            "detail": f"JWT secret is {len(secret)} characters (not default)",
        }

    async def _check_cors(self) -> dict[str, Any]:
        """Check CORS origins for wildcard configuration."""
        name = "cors_origins"
        origins = settings.cors_origins

        if "*" in origins:
            return {
                "name": name,
                "status": "fail",
                "detail": "CORS allows wildcard (*) origins — any website can make requests",
                "recommendation": "Restrict CORS_ORIGINS to specific trusted domains (e.g., https://app.argus.local)",
            }

        if not origins:
            return {
                "name": name,
                "status": "warn",
                "detail": "No CORS origins configured",
                "recommendation": "Set CORS_ORIGINS to your frontend domain(s)",
            }

        return {
            "name": name,
            "status": "pass",
            "detail": f"CORS restricted to {len(origins)} origin(s): {', '.join(origins[:3])}",
        }

    async def _check_rate_limiting(self) -> dict[str, Any]:
        """Check if rate limiting is configured."""
        name = "rate_limiting"
        max_req = settings.rate_limit_default_max
        window = settings.rate_limit_default_window

        if max_req <= 0:
            return {
                "name": name,
                "status": "fail",
                "detail": "Rate limiting is disabled (max_requests <= 0)",
                "recommendation": "Set RATE_LIMIT_DEFAULT_MAX to a positive value (e.g., 100 requests per 60s)",
            }

        if max_req > 1000:
            return {
                "name": name,
                "status": "warn",
                "detail": f"Rate limit is very permissive ({max_req} requests per {window}s)",
                "recommendation": "Consider lowering RATE_LIMIT_DEFAULT_MAX to prevent abuse",
            }

        return {
            "name": name,
            "status": "pass",
            "detail": f"Rate limiting active: {max_req} requests per {window}s",
        }

    async def _check_dependencies(self) -> dict[str, Any]:
        """Check for known dependency vulnerabilities via pip-audit or safety."""
        name = "dependencies"

        # Try pip-audit first, then safety
        if shutil.which("pip-audit"):
            return await self._run_pip_audit()
        if shutil.which("safety"):
            return await self._run_safety()

        return {
            "name": name,
            "status": "warn",
            "detail": "Neither pip-audit nor safety is installed — cannot scan dependencies",
            "recommendation": "Install pip-audit (pip install pip-audit) to enable dependency vulnerability scanning",
        }

    async def _run_pip_audit(self) -> dict[str, Any]:
        """Run pip-audit with 30s timeout."""
        name = "dependencies"
        try:
            proc = await asyncio.create_subprocess_exec(
                "pip-audit", "--strict", "--short-report",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=30
            )
            output = (stdout + stderr).decode("utf-8", errors="replace").strip()

            # pip-audit returns 0 if no vulnerabilities found
            if proc.returncode == 0:
                return {
                    "name": name,
                    "status": "pass",
                    "detail": "pip-audit found no known vulnerabilities",
                }

            # Parse vulnerability count from output
            vuln_count = output.count("VULNERABLE")
            if vuln_count == 0:
                # Try another pattern
                for line in output.splitlines():
                    if "vulnerabilities" in line.lower():
                        vuln_count = max(vuln_count, 1)

            return {
                "name": name,
                "status": "fail",
                "detail": f"pip-audit found {vuln_count or 'unknown'} vulnerable package(s)",
                "recommendation": "Run 'pip-audit' directly for details and update affected packages",
            }
        except asyncio.TimeoutError:
            return {
                "name": name,
                "status": "warn",
                "detail": "pip-audit timed out after 30s",
                "recommendation": "Run 'pip-audit' manually in a terminal to check dependencies",
            }
        except Exception as exc:
            logger.exception("pip-audit check failed")
            return {
                "name": name,
                "status": "warn",
                "detail": f"pip-audit error: {exc}",
                "recommendation": "Ensure pip-audit is properly installed",
            }

    async def _run_safety(self) -> dict[str, Any]:
        """Run safety check with 30s timeout."""
        name = "dependencies"
        try:
            proc = await asyncio.create_subprocess_exec(
                "safety", "check", "--short-report",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=30
            )
            output = (stdout + stderr).decode("utf-8", errors="replace").strip()

            if proc.returncode == 0:
                return {
                    "name": name,
                    "status": "pass",
                    "detail": "safety found no known vulnerabilities",
                }

            return {
                "name": name,
                "status": "fail",
                "detail": "safety found vulnerable packages (see output)",
                "recommendation": "Run 'safety check' directly for details and update affected packages",
            }
        except asyncio.TimeoutError:
            return {
                "name": name,
                "status": "warn",
                "detail": "safety check timed out after 30s",
                "recommendation": "Run 'safety check' manually in a terminal",
            }
        except Exception as exc:
            logger.exception("safety check failed")
            return {
                "name": name,
                "status": "warn",
                "detail": f"safety error: {exc}",
                "recommendation": "Ensure safety is properly installed",
            }
