"""Timing randomization — jitter + adaptive delays for request patterns.

Provides unpredictable request timing to avoid pattern detection:
    - Uniform jitter (±20% by default) on base delays
    - Adaptive backoff on 429/5xx responses
    - Per-domain tracking with independent delay states
    - Configurable profiles for different operational contexts

Inherits the jitter philosophy from argus.opsec.rate_limiter but extends it
with domain-aware tracking and adaptive profiles.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Final

logger = logging.getLogger(__name__)

# Jitter range as proportion of current delay
_DEFAULT_JITTER_RANGE: Final = 0.2
# Backoff factor for 429/5xx errors
_BACKOFF_FACTOR: Final = 2.0
# Success factor (delay reduction)
_SUCCESS_FACTOR: Final = 0.7
# Maximum delay cap (seconds)
_MAX_DELAY: Final = 120.0
# Minimum delay floor (seconds)
_MIN_DELAY: Final = 0.1


@dataclass
class TimingProfile:
    """Configuration for a timing randomization profile.

    Attributes:
        name: Profile identifier (e.g., "stealth", "normal", "aggressive").
        base_delay: Base delay between requests in seconds.
        max_delay: Maximum delay after backoff.
        min_delay: Minimum delay floor.
        jitter_range: Jitter range as proportion of delay (0.0-1.0).
        backoff_factor: Multiplier for backoff on errors.
        success_factor: Multiplier for delay reduction on success.
        description: Human-readable description.
    """

    name: str = "normal"
    base_delay: float = 2.0
    max_delay: float = 60.0
    min_delay: float = 0.5
    jitter_range: float = _DEFAULT_JITTER_RANGE
    backoff_factor: float = _BACKOFF_FACTOR
    success_factor: float = _SUCCESS_FACTOR
    description: str = "Default timing profile"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "base_delay": self.base_delay,
            "max_delay": self.max_delay,
            "min_delay": self.min_delay,
            "jitter_range": self.jitter_range,
            "backoff_factor": self.backoff_factor,
            "success_factor": self.success_factor,
            "description": self.description,
        }


# Predefined profiles for common operational contexts
PROFILE_STEALTH = TimingProfile(
    name="stealth",
    base_delay=5.0,
    max_delay=120.0,
    min_delay=1.0,
    jitter_range=0.3,
    backoff_factor=2.5,
    success_factor=0.8,
    description="High-latency stealth profile for sensitive operations",
)

PROFILE_NORMAL = TimingProfile(
    name="normal",
    base_delay=2.0,
    max_delay=60.0,
    min_delay=0.5,
    jitter_range=0.2,
    backoff_factor=2.0,
    success_factor=0.7,
    description="Balanced profile for routine operations",
)

PROFILE_AGGRESSIVE = TimingProfile(
    name="aggressive",
    base_delay=0.5,
    max_delay=30.0,
    min_delay=0.1,
    jitter_range=0.15,
    backoff_factor=1.8,
    success_factor=0.5,
    description="Low-latency profile for time-sensitive operations",
)


@dataclass
class _DomainState:
    """Internal state tracking for a single domain."""

    current_delay: float = 2.0
    last_request_at: float = 0.0
    request_count: int = 0
    error_count: int = 0
    consecutive_errors: int = 0


class TimingRandomizer:
    """Async timing randomization with adaptive delays and jitter.

    Features:
        - Per-domain delay tracking with independent states
        - Uniform jitter to prevent pattern detection
        - Adaptive backoff on 429/5xx responses
        - Configurable profiles for different contexts

    Usage::

        timing = TimingRandomizer(profile=PROFILE_STEALTH)
        await timing.wait("example.com")
        # ... make request ...
        timing.report_success("example.com")
    """

    def __init__(
        self,
        profile: TimingProfile | None = None,
        global_mode: bool = False,
    ) -> None:
        """
        Args:
            profile: Timing profile to use. Defaults to PROFILE_NORMAL.
            global_mode: If True, track all requests under a single state
                         instead of per-domain.
        """
        self._profile = profile or PROFILE_NORMAL
        self._global_mode = global_mode
        self._domains: dict[str, _DomainState] = {}
        self._global_state = _DomainState(
            current_delay=self._profile.base_delay
        )
        self._lock = asyncio.Lock()

    @property
    def profile(self) -> TimingProfile:
        """Current timing profile."""
        return self._profile

    def set_profile(self, profile: TimingProfile) -> None:
        """Switch to a different timing profile.

        Args:
            profile: New profile to apply.
        """
        self._profile = profile
        # Reset delays to match new profile
        self._global_state.current_delay = profile.base_delay
        for state in self._domains.values():
            state.current_delay = profile.base_delay

    def _get_state(self, domain: str) -> _DomainState:
        """Get or create state for a domain."""
        if self._global_mode:
            return self._global_state
        if domain not in self._domains:
            self._domains[domain] = _DomainState(
                current_delay=self._profile.base_delay
            )
        return self._domains[domain]

    async def wait(self, domain: str = "global") -> float:
        """Wait for the randomized delay before making a request.

        Args:
            domain: Target domain for per-domain tracking.

        Returns:
            The actual delay that was slept (seconds).
        """
        state = self._get_state(domain)
        delay = self._apply_jitter(state.current_delay)

        # Ensure minimum time between requests
        now = time.monotonic()
        elapsed = now - state.last_request_at
        if elapsed < delay:
            sleep_time = delay - elapsed
            logger.debug(
                "TimingRandomizer: waiting %.2fs for %s", sleep_time, domain
            )
            await asyncio.sleep(sleep_time)
            actual_delay = sleep_time
        else:
            actual_delay = 0.0

        state.last_request_at = time.monotonic()
        state.request_count += 1
        return actual_delay

    def report_success(self, domain: str = "global") -> None:
        """Report a successful request — reduces delay.

        Args:
            domain: Target domain.
        """
        state = self._get_state(domain)
        state.consecutive_errors = 0
        state.current_delay = max(
            self._profile.min_delay,
            state.current_delay * self._profile.success_factor,
        )

    def report_error(self, domain: str = "global", status_code: int = 0) -> None:
        """Report a failed request — increases delay (backoff).

        Only 429 and 5xx status codes trigger backoff. Other errors
        (e.g., 400 Bad Request) don't penalize the timing.

        Args:
            domain: Target domain.
            status_code: HTTP status code of the failed request.
        """
        state = self._get_state(domain)

        if status_code == 429 or status_code >= 500:
            state.error_count += 1
            state.consecutive_errors += 1
            state.current_delay = min(
                self._profile.max_delay,
                state.current_delay * self._profile.backoff_factor,
            )
            logger.debug(
                "TimingRandomizer: backoff for %s (status %d) -> %.2fs",
                domain,
                status_code,
                state.current_delay,
            )
        elif status_code == 403:
            # Forbidden — moderate backoff, might be rate limiting
            state.current_delay = min(
                self._profile.max_delay,
                state.current_delay * 1.5,
            )

    def reset(self, domain: str | None = None) -> None:
        """Reset delay state.

        Args:
            domain: Specific domain to reset, or None to reset all.
        """
        if domain is None:
            self._global_state = _DomainState(
                current_delay=self._profile.base_delay
            )
            self._domains.clear()
        else:
            self._domains.pop(domain, None)

    def get_current_delay(self, domain: str = "global") -> float:
        """Get the current base delay (without jitter) for a domain.

        Args:
            domain: Target domain.

        Returns:
            Current delay in seconds.
        """
        state = self._get_state(domain)
        return state.current_delay

    def get_stats(self, domain: str | None = None) -> dict:
        """Get timing statistics.

        Args:
            domain: Specific domain, or None for all domains.

        Returns:
            Dict with timing statistics.
        """
        if domain:
            state = self._get_state(domain)
            return {
                "domain": domain,
                "current_delay": state.current_delay,
                "request_count": state.request_count,
                "error_count": state.error_count,
                "consecutive_errors": state.consecutive_errors,
            }

        # Aggregate stats
        all_states = list(self._domains.values())
        total_requests = sum(s.request_count for s in all_states)
        total_errors = sum(s.error_count for s in all_states)
        return {
            "domains_tracked": len(self._domains),
            "total_requests": total_requests,
            "total_errors": total_errors,
            "global_delay": self._global_state.current_delay,
            "profile": self._profile.name,
        }

    def _apply_jitter(self, delay: float) -> float:
        """Apply uniform jitter to a delay.

        Jitter is uniform in [delay * (1 - range), delay * (1 + range)].

        Args:
            delay: Base delay in seconds.

        Returns:
            Delay with jitter applied.
        """
        jitter_range = self._profile.jitter_range
        low = delay * (1.0 - jitter_range)
        high = delay * (1.0 + jitter_range)
        return random.uniform(low, high)
