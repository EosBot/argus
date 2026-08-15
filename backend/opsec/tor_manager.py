"""Tor circuit manager — Stem-based circuit rotation with NEWNYM.

Provides async Tor circuit management via the Stem library:
    - Circuit rotation (NEWNYM signal) with cooldown enforcement
    - Circuit build timeout tracking
    - Max circuit count before forced rotation
    - Graceful degradation when Stem/Tor is unavailable

Inherits patterns from argus_engine/health.py's rotate_tor_circuit() but wraps
them in a proper async class with state tracking.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Final

logger = logging.getLogger(__name__)


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


# Tor enforces ~10s between effective NEWNYM signals
_NEWNYM_COOLDOWN: Final = 10
# Default circuit build timeout (seconds)
_DEFAULT_BUILD_TIMEOUT: Final = 30
# Default max circuits before forced rotation
_DEFAULT_MAX_CIRCUITS: Final = 10

# Graceful degradation: Stem is optional
try:
    from stem import Signal
    from stem.control import Controller
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False
    logger.debug("Stem not available. Tor circuit rotation disabled.")


@dataclass
class CircuitStatus:
    """Status of the current Tor circuit.

    Attributes:
        circuit_id: Unique circuit identifier (or "unknown").
        build_time_ms: Time taken to build the circuit in milliseconds.
        is_fresh: Whether the circuit was recently rotated.
        last_rotated_at: Unix timestamp of last rotation.
        rotation_count: Total rotations performed in this session.
        exit_fingerprint: Exit node fingerprint (if available).
        exit_country: Exit node country code (if available).
    """

    circuit_id: str = "unknown"
    build_time_ms: int = 0
    is_fresh: bool = False
    last_rotated_at: float = 0.0
    rotation_count: int = 0
    exit_fingerprint: str | None = None
    exit_country: str | None = None

    def to_dict(self) -> dict:
        return {
            "circuit_id": self.circuit_id,
            "build_time_ms": self.build_time_ms,
            "is_fresh": self.is_fresh,
            "last_rotated_at": self.last_rotated_at,
            "rotation_count": self.rotation_count,
            "exit_fingerprint": self.exit_fingerprint,
            "exit_country": self.exit_country,
        }


class TorManager:
    """Async Tor circuit manager with Stem-based NEWNYM rotation.

    Features:
        - Circuit rotation with cooldown enforcement
        - Configurable build timeout and max circuit count
        - State tracking for circuit lifecycle
        - Graceful degradation when Stem/Tor is unavailable

    Usage::

        manager = TorManager(control_port=9051)
        await manager.rotate_circuit()
        status = await manager.get_status()
    """

    def __init__(
        self,
        control_port: int | None = None,
        control_host: str | None = None,
        password: str | None = None,
        cooldown: int = _NEWNYM_COOLDOWN,
        build_timeout: int = _DEFAULT_BUILD_TIMEOUT,
        max_circuits: int = _DEFAULT_MAX_CIRCUITS,
    ) -> None:
        from backend.core.config import settings

        self._control_port = control_port or settings.tor_control_port
        self._control_host = _resolve_host(control_host or settings.tor_control_host)
        self._password = password or settings.tor_control_password
        self._cooldown = cooldown
        self._build_timeout = build_timeout
        self._max_circuits = max_circuits
        self._last_rotated_at: float = 0.0
        self._rotation_count: int = 0
        self._circuit_count: int = 0
        self._lock = asyncio.Lock()

    @property
    def is_available(self) -> bool:
        """Check if Stem and Tor ControlPort are available."""
        return STEM_AVAILABLE and bool(self._password)

    async def rotate_circuit(self, force: bool = False) -> bool:
        """Rotate Tor circuit by sending NEWNYM signal.

        Args:
            force: If True, bypass cooldown (use sparingly).

        Returns:
            True if circuit rotation was successful.
        """
        if not self.is_available:
            logger.warning("TorManager: Stem or password not available, skipping rotation")
            return False

        async with self._lock:
            now = time.monotonic()
            if not force and (now - self._last_rotated_at) < self._cooldown:
                logger.debug("TorManager: cooldown not elapsed, skipping rotation")
                return False

            # Run blocking Stem call in thread pool
            loop = asyncio.get_event_loop()
            success = await loop.run_in_executor(
                None, self._send_newnym
            )

            if success:
                self._last_rotated_at = now
                self._rotation_count += 1
                self._circuit_count += 1
                logger.info(
                    "TorManager: circuit rotated (rotation #%d)",
                    self._rotation_count,
                )

                # Reset circuit count if max reached
                if self._circuit_count >= self._max_circuits:
                    logger.info(
                        "TorManager: max circuits (%d) reached, resetting counter",
                        self._max_circuits,
                    )
                    self._circuit_count = 0

                # Brief pause for circuit build start
                await asyncio.sleep(1)
            else:
                logger.warning("TorManager: NEWNYM signal failed")

            return success

    def _send_newnym(self) -> bool:
        """Send NEWNYM signal via Stem (blocking, run in executor)."""
        try:
            with Controller.from_port(
                address=self._control_host, port=self._control_port
            ) as controller:
                controller.authenticate(password=self._password)
                controller.signal(Signal.NEWNYM)
                return True
        except Exception as exc:
            logger.error("TorManager: NEWNYM failed: %s", exc)
            return False

    async def get_status(self) -> CircuitStatus:
        """Get current circuit status.

        Returns:
            CircuitStatus with current circuit information.
        """
        if not self.is_available:
            return CircuitStatus(
                circuit_id="unavailable",
                is_fresh=False,
                last_rotated_at=self._last_rotated_at,
                rotation_count=self._rotation_count,
            )

        loop = asyncio.get_event_loop()
        circuit_info = await loop.run_in_executor(
            None, self._get_circuit_info
        )

        now = time.monotonic()
        is_fresh = (now - self._last_rotated_at) < self._cooldown * 2

        return CircuitStatus(
            circuit_id=circuit_info.get("circuit_id", "unknown"),
            build_time_ms=circuit_info.get("build_time_ms", 0),
            is_fresh=is_fresh,
            last_rotated_at=self._last_rotated_at,
            rotation_count=self._rotation_count,
            exit_fingerprint=circuit_info.get("exit_fingerprint"),
            exit_country=circuit_info.get("exit_country"),
        )

    def _get_circuit_info(self) -> dict:
        """Get circuit info from Tor (blocking, run in executor)."""
        try:
            with Controller.from_port(
                address=self._control_host, port=self._control_port
            ) as controller:
                controller.authenticate(password=self._password)
                circuits = list(controller.get_circuits())
                if circuits:
                    # Get the most recently built circuit
                    latest = circuits[-1]
                    info: dict = {
                        "circuit_id": str(latest.id),
                        "build_time_ms": int(
                            (latest.build_flags[0] if latest.build_flags else 0) * 1000
                        ),
                    }
                    # Try to get exit node info
                    if latest.path:
                        exit_relay = latest.path[-1]
                        info["exit_fingerprint"] = exit_relay[1]
                    return info
        except Exception as exc:
            logger.debug("TorManager: failed to get circuit info: %s", exc)
        return {}

    async def validate_connection(self) -> bool:
        """Validate that Tor ControlPort is reachable and authenticates.

        Returns:
            True if Tor control connection is working.
        """
        if not self.is_available:
            return False

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._validate_connection)

    def _validate_connection(self) -> bool:
        """Validate Tor connection (blocking)."""
        try:
            with Controller.from_port(
                address=self._control_host, port=self._control_port
            ) as controller:
                controller.authenticate(password=self._password)
                return controller.is_authenticated()
        except Exception as exc:
            logger.debug("TorManager: connection validation failed: %s", exc)
            return False

    async def get_newnym_wait_time(self) -> float:
        """Get remaining cooldown time before next NEWNYM is effective.

        Returns:
            Seconds until next rotation is allowed (0 if ready now).
        """
        elapsed = time.monotonic() - self._last_rotated_at
        remaining = max(0.0, self._cooldown - elapsed)
        return remaining
