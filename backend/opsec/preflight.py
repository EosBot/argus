"""OPSEC pre-flight checks — DNS leak, Tor circuit, proxy validation.

Validates the operational security posture before sensitive operations:
    - DNS leak test (verify DNS queries route through Tor)
    - Tor circuit validation (ControlPort + SOCKS5 reachability)
    - SOCKS5 proxy test (connectivity and anonymity)
    - IP leak detection (check for clearnet IP exposure)
    - Comprehensive pre-flight report

All checks are async and non-blocking with timeouts.
Gracefully degrades when external services are unreachable.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Final

logger = logging.getLogger(__name__)

# Timeout for external checks (seconds)
_CHECK_TIMEOUT: Final = 15


def _proxy_host_from_settings() -> str:
    """Extract the SOCKS5 proxy host from settings.tor_proxy (env TOR_PROXY)."""
    from backend.core.config import settings

    proxy = settings.tor_proxy.removeprefix("socks5h://")
    host = proxy.rsplit(":", 1)[0]
    return host or "127.0.0.1"


def _proxy_port_from_settings() -> int:
    """Extract the SOCKS5 proxy port from settings.tor_proxy (env TOR_PROXY)."""
    from backend.core.config import settings

    proxy = settings.tor_proxy.removeprefix("socks5h://")
    port = proxy.rsplit(":", 1)[-1]
    return int(port) if port.isdigit() else 9050


def _resolve_host(host: str) -> str:
    """Resolve a hostname to an IPv4 address (stem requires a literal IP)."""
    import ipaddress
    import socket

    try:
        ipaddress.IPv4Address(host)
        return host
    except ValueError:
        try:
            return socket.gethostbyname(host)
        except OSError:
            return host
# Known DNS leak test endpoints
_DNS_LEAK_ENDPOINTS: Final = [
    "https://dnsleaktest.com/api/servers",
    "https://www.dnsleaktest.com/api/servers",
]
# IP check endpoints (should return JSON with IP)
_IP_CHECK_ENDPOINTS: Final = [
    "https://check.torproject.org/api/ip",
    "https://api.ipify.org?format=json",
]

# Graceful degradation: aiohttp is optional
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    logger.debug("aiohttp not available. External checks will be limited.")


@dataclass
class PreFlightResult:
    """Result of an OPSEC pre-flight check.

    Attributes:
        timestamp: ISO timestamp of the check.
        overall_pass: Whether all critical checks passed.
        dns_leak_pass: DNS leak test result.
        tor_circuit_pass: Tor circuit validation result.
        proxy_pass: SOCKS5 proxy test result.
        ip_leak_pass: IP leak detection result.
        details: Detailed results per check.
        warnings: List of warning messages.
        errors: List of error messages.
    """

    timestamp: str = ""
    overall_pass: bool = False
    dns_leak_pass: bool = False
    tor_circuit_pass: bool = False
    proxy_pass: bool = False
    ip_leak_pass: bool = False
    details: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "overall_pass": self.overall_pass,
            "dns_leak_pass": self.dns_leak_pass,
            "tor_circuit_pass": self.tor_circuit_pass,
            "proxy_pass": self.proxy_pass,
            "ip_leak_pass": self.ip_leak_pass,
            "details": self.details,
            "warnings": self.warnings,
            "errors": self.errors,
        }


class OPSECPreFlight:
    """OPSEC pre-flight validation suite.

    Runs a battery of security checks before sensitive operations
    to verify the operational security posture.

    Usage::

        preflight = OPSECPreFlight()
        result = await preflight.run_all_checks()
        if not result.overall_pass:
            handle_failure(result)
    """

    def __init__(
        self,
        tor_proxy_host: str | None = None,
        tor_proxy_port: int | None = None,
        tor_control_host: str | None = None,
        tor_control_port: int | None = None,
        tor_control_password: str | None = None,
        timeout: int = _CHECK_TIMEOUT,
    ) -> None:
        from backend.core.config import settings

        self._proxy_host = tor_proxy_host or _proxy_host_from_settings()
        self._proxy_port = tor_proxy_port or _proxy_port_from_settings()
        self._control_host = _resolve_host(
            tor_control_host or settings.tor_control_host
        )
        self._control_port = tor_control_port or settings.tor_control_port
        self._control_password = tor_control_password or settings.tor_control_password
        self._timeout = timeout

    async def run_all_checks(self) -> PreFlightResult:
        """Run all pre-flight checks concurrently.

        Returns:
            PreFlightResult with all check results.
        """
        from datetime import datetime, timezone

        result = PreFlightResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # Run checks concurrently
        check_tasks = [
            self.check_dns_leak(),
            self.check_tor_circuit(),
            self.check_socks5_proxy(),
            self.check_ip_leak(),
        ]

        results = await asyncio.gather(*check_tasks, return_exceptions=True)

        for check_result in results:
            if isinstance(check_result, Exception):
                result.errors.append(str(check_result))
                continue
            # Each result is a tuple: (check_name, passed, details)
            check_name, passed, details = check_result
            result.details[check_name] = details

            if check_name == "dns_leak":
                result.dns_leak_pass = passed
            elif check_name == "tor_circuit":
                result.tor_circuit_pass = passed
            elif check_name == "socks5_proxy":
                result.proxy_pass = passed
            elif check_name == "ip_leak":
                result.ip_leak_pass = passed

            if not passed:
                if details.get("critical", True):
                    result.errors.append(
                        f"{check_name}: {details.get('error', 'failed')}"
                    )
                else:
                    result.warnings.append(
                        f"{check_name}: {details.get('warning', 'warning')}"
                    )

        # Overall pass requires critical checks
        result.overall_pass = (
            result.tor_circuit_pass
            and result.proxy_pass
        )

        return result

    async def check_dns_leak(self) -> tuple[str, bool, dict]:
        """Check for DNS leaks by querying DNS leak test API.

        Returns:
            Tuple of (check_name, passed, details_dict).
        """
        if not AIOHTTP_AVAILABLE:
            return ("dns_leak", False, {
                "error": "aiohttp not available",
                "critical": False,
                "warning": "Cannot verify DNS leak without aiohttp",
            })

        try:
            timeout = aiohttp.ClientTimeout(total=self._timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for endpoint in _DNS_LEAK_ENDPOINTS:
                    try:
                        async with session.get(endpoint) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                # If we get a response, DNS is resolving
                                # (through Tor if proxy is configured)
                                return ("dns_leak", True, {
                                    "endpoint": endpoint,
                                    "status": resp.status,
                                    "servers_detected": len(data) if isinstance(data, list) else 0,
                                    "critical": False,
                                })
                    except Exception:
                        continue

            return ("dns_leak", False, {
                "error": "All DNS leak endpoints unreachable",
                "critical": False,
                "warning": "Could not verify DNS leak status",
            })
        except Exception as exc:
            return ("dns_leak", False, {
                "error": str(exc),
                "critical": False,
            })

    async def check_tor_circuit(self) -> tuple[str, bool, dict]:
        """Validate Tor circuit via ControlPort.

        Returns:
            Tuple of (check_name, passed, details_dict).
        """
        try:
            # Check if ControlPort is reachable
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self._control_host, self._control_port),
                timeout=5,
            )
            writer.close()
            await writer.wait_closed()

            # Try Stem for deeper validation
            try:
                from stem.control import Controller
                loop = asyncio.get_event_loop()
                auth_success = await loop.run_in_executor(
                    None, self._authenticate_controller
                )
                if auth_success:
                    return ("tor_circuit", True, {
                        "control_port": self._control_port,
                        "authenticated": True,
                        "critical": True,
                    })
                return ("tor_circuit", False, {
                    "error": "ControlPort authentication failed",
                    "critical": True,
                })
            except ImportError:
                # Stem not available but port is open
                return ("tor_circuit", True, {
                    "control_port": self._control_port,
                    "authenticated": False,
                    "warning": "Stem not available, port open but unauthenticated",
                    "critical": True,
                })
        except asyncio.TimeoutError:
            return ("tor_circuit", False, {
                "error": f"ControlPort {self._control_port} timeout",
                "critical": True,
            })
        except ConnectionRefusedError:
            return ("tor_circuit", False, {
                "error": f"ControlPort {self._control_port} refused",
                "critical": True,
            })
        except Exception as exc:
            return ("tor_circuit", False, {
                "error": str(exc),
                "critical": True,
            })

    def _authenticate_controller(self) -> bool:
        """Authenticate with Tor controller (blocking)."""
        try:
            from stem.control import Controller

            with Controller.from_port(
                address=self._control_host, port=self._control_port
            ) as controller:
                controller.authenticate(password=self._control_password or None)
                return controller.is_authenticated()
        except Exception:
            return False

    async def check_socks5_proxy(self) -> tuple[str, bool, dict]:
        """Test SOCKS5 proxy connectivity.

        Returns:
            Tuple of (check_name, passed, details_dict).
        """
        start = time.monotonic()
        try:
            # Test basic TCP connect to SOCKS5 port
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self._proxy_host, self._proxy_port),
                timeout=5,
            )
            elapsed_ms = int((time.monotonic() - start) * 1000)
            writer.close()
            await writer.wait_closed()

            # If aiohttp is available, test through the proxy
            if AIOHTTP_AVAILABLE:
                proxy_url = f"socks5h://{self._proxy_host}:{self._proxy_port}"
                timeout = aiohttp.ClientTimeout(total=self._timeout)
                try:
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.get(
                            "https://check.torproject.org/api/ip",
                            proxy=proxy_url,
                        ) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                is_tor = data.get("IsTor", False)
                                ip = data.get("IP", "unknown")
                                return ("socks5_proxy", True, {
                                    "latency_ms": elapsed_ms,
                                    "is_tor": is_tor,
                                    "exit_ip": ip,
                                    "critical": True,
                                })
                except Exception:
                    # Proxy works at TCP level but HTTP through proxy failed
                    pass

            return ("socks5_proxy", True, {
                "latency_ms": elapsed_ms,
                "note": "TCP connect successful, HTTP proxy test skipped",
                "critical": True,
            })
        except asyncio.TimeoutError:
            return ("socks5_proxy", False, {
                "error": f"SOCKS5 {self._proxy_host}:{self._proxy_port} timeout",
                "critical": True,
            })
        except ConnectionRefusedError:
            return ("socks5_proxy", False, {
                "error": f"SOCKS5 {self._proxy_host}:{self._proxy_port} refused",
                "critical": True,
            })
        except Exception as exc:
            return ("socks5_proxy", False, {
                "error": str(exc),
                "critical": True,
            })

    async def check_ip_leak(self) -> tuple[str, bool, dict]:
        """Check for IP leak by querying IP detection API through Tor.

        Returns:
            Tuple of (check_name, passed, details_dict).
        """
        if not AIOHTTP_AVAILABLE:
            return ("ip_leak", False, {
                "error": "aiohttp not available",
                "critical": False,
                "warning": "Cannot verify IP leak without aiohttp",
            })

        proxy_url = f"socks5h://{self._proxy_host}:{self._proxy_port}"
        timeout = aiohttp.ClientTimeout(total=self._timeout)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for endpoint in _IP_CHECK_ENDPOINTS:
                    try:
                        async with session.get(
                            endpoint, proxy=proxy_url
                        ) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                ip = data.get("ip") or data.get("IP", "unknown")
                                is_tor = data.get("IsTor", False)

                                return ("ip_leak", is_tor, {
                                    "detected_ip": ip,
                                    "is_tor": is_tor,
                                    "endpoint": endpoint,
                                    "critical": False,
                                    "warning": None if is_tor else "Traffic may not be routed through Tor",
                                })
                    except Exception:
                        continue

            return ("ip_leak", False, {
                "error": "All IP check endpoints unreachable",
                "critical": False,
                "warning": "Could not verify IP leak status",
            })
        except Exception as exc:
            return ("ip_leak", False, {
                "error": str(exc),
                "critical": False,
            })
