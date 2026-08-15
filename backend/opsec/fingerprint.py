"""Fingerprint rotation — User-Agent, canvas, WebGL randomization.

Provides browser fingerprint diversity to prevent tracking:
    - Rotating User-Agent pool (desktop, mobile, browser variants)
    - Canvas fingerprint randomization (noise injection config)
    - WebGL fingerprint randomization (vendor/renderer spoofing config)
    - Consistent profile generation per-session or per-request
    - Font list and screen resolution rotation

Designed to be used with Playwright/browser automation to configure
anti-detection measures. Generates configuration dicts that can be
injected into browser contexts via init scripts.
"""

from __future__ import annotations

import hashlib
import logging
import random
import uuid
from dataclasses import dataclass, field
from typing import Final

logger = logging.getLogger(__name__)


@dataclass
class BrowserProfile:
    """A complete browser fingerprint profile.

    Attributes:
        profile_id: Unique identifier for this profile.
        user_agent: Full User-Agent string.
        browser: Browser family (chrome, firefox, safari, edge).
        os: Operating system family.
        platform: Platform string.
        screen_resolution: Screen resolution tuple (width, height).
        color_depth: Color depth in bits.
        timezone: IANA timezone string.
        language: Accept-Language header value.
        fonts: List of available fonts.
        canvas_noise: Canvas fingerprint noise seed.
        webgl_vendor: WebGL vendor string.
        webgl_renderer: WebGL renderer string.
        hardware_concurrency: Number of logical CPU cores.
        device_memory: Device memory in GB.
        touch_support: Whether touch events are supported.
        do_not_track: DNT header value.
    """

    profile_id: str = ""
    user_agent: str = ""
    browser: str = "chrome"
    os: str = "windows"
    platform: str = "Win32"
    screen_resolution: tuple[int, int] = (1920, 1080)
    color_depth: int = 24
    timezone: str = "America/New_York"
    language: str = "en-US,en;q=0.9"
    fonts: list[str] = field(default_factory=list)
    canvas_noise: float = 0.0
    webgl_vendor: str = "Google Inc. (NVIDIA)"
    webgl_renderer: str = "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER"
    hardware_concurrency: int = 8
    device_memory: int = 8
    touch_support: bool = False
    do_not_track: str | None = None

    def to_dict(self) -> dict:
        return {
            "profile_id": self.profile_id,
            "user_agent": self.user_agent,
            "browser": self.browser,
            "os": self.os,
            "platform": self.platform,
            "screen_resolution": list(self.screen_resolution),
            "color_depth": self.color_depth,
            "timezone": self.timezone,
            "language": self.language,
            "fonts": self.fonts,
            "canvas_noise": self.canvas_noise,
            "webgl_vendor": self.webgl_vendor,
            "webgl_renderer": self.webgl_renderer,
            "hardware_concurrency": self.hardware_concurrency,
            "device_memory": self.device_memory,
            "touch_support": self.touch_support,
            "do_not_track": self.do_not_track,
        }


# User-Agent pool — organized by browser and OS
_USER_AGENTS: Final = {
    "chrome_windows": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    ],
    "chrome_mac": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    ],
    "firefox_windows": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    ],
    "firefox_mac": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
    ],
    "safari_mac": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    ],
    "edge_windows": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    ],
    "chrome_linux": [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    ],
}

# Screen resolutions pool
_SCREEN_RESOLUTIONS: Final = [
    (1920, 1080),
    (2560, 1440),
    (1366, 768),
    (1536, 864),
    (1440, 900),
    (3840, 2160),
    (1280, 720),
    (1680, 1050),
]

# WebGL vendor/renderer pairs
_WEBGL_VENDORS: Final = [
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3070"),
    ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 580"),
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel UHD Graphics 630)"),
    ("Apple", "Apple M1"),
    ("Apple", "Apple M2"),
]

# Common font lists by OS
_FONTS: Final = {
    "windows": [
        "Arial", "Calibri", "Cambria", "Consolas", "Georgia",
        "Segoe UI", "Tahoma", "Times New Roman", "Trebuchet MS", "Verdana",
    ],
    "mac": [
        "Helvetica Neue", "Lucida Grande", "Geneva", "Monaco",
        "Courier New", "Times", "Arial", "Georgia", "Verdana",
    ],
    "linux": [
        "DejaVu Sans", "Liberation Sans", "Noto Sans", "Ubuntu",
        "FreeSans", "Cantarell", "Droid Sans", "Liberation Serif",
    ],
}

# Timezone pool
_TIMEZONES: Final = [
    "America/New_York", "America/Chicago", "America/Los_Angeles",
    "America/Sao_Paulo", "Europe/London", "Europe/Berlin",
    "Europe/Moscow", "Asia/Tokyo", "Asia/Shanghai",
    "Australia/Sydney", "Asia/Kolkata",
]

# Language pool
_LANGUAGES: Final = [
    "en-US,en;q=0.9", "en-GB,en;q=0.9", "pt-BR,pt;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8", "fr-FR,fr;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8", "ja-JP,ja;q=0.9,en;q=0.8",
]


class FingerprintRotator:
    """Browser fingerprint rotation for anti-tracking.

    Generates randomized browser profiles with consistent attributes
    to prevent fingerprint-based tracking across sessions.

    Usage::

        rotator = FingerprintRotator()
        profile = rotator.generate_profile()
        # Use profile.user_agent, profile.webgl_vendor, etc.
    """

    def __init__(
        self,
        seed: int | None = None,
        consistent_per_session: bool = True,
    ) -> None:
        """
        Args:
            seed: Random seed for reproducible profiles.
            consistent_per_session: If True, generates a base profile
                                     that persists across generate_profile() calls.
        """
        self._rng = random.Random(seed)
        self._consistent = consistent_per_session
        self._session_profile: BrowserProfile | None = None

    def generate_profile(self) -> BrowserProfile:
        """Generate a randomized browser profile.

        Returns:
            BrowserProfile with randomized but internally consistent attributes.
        """
        if self._consistent and self._session_profile is not None:
            return self._session_profile

        # Pick a random UA category
        ua_category = self._rng.choice(list(_USER_AGENTS.keys()))
        user_agent = self._rng.choice(_USER_AGENTS[ua_category])

        # Determine OS from category
        os_family = "windows"
        if "_mac" in ua_category:
            os_family = "mac"
        elif "_linux" in ua_category:
            os_family = "linux"

        # Determine browser from category
        browser = "chrome"
        if "firefox" in ua_category:
            browser = "firefox"
        elif "safari" in ua_category:
            browser = "safari"
        elif "edge" in ua_category:
            browser = "edge"

        # Platform string
        platform = "Win32"
        if os_family == "mac":
            platform = "MacIntel"
        elif os_family == "linux":
            platform = "Linux x86_64"

        # Screen resolution
        resolution = self._rng.choice(_SCREEN_RESOLUTIONS)

        # WebGL
        webgl_vendor, webgl_renderer = self._rng.choice(_WEBGL_VENDORS)

        # Fonts (subset of OS-appropriate fonts)
        available_fonts = _FONTS.get(os_family, _FONTS["windows"])
        font_count = self._rng.randint(4, len(available_fonts))
        fonts = sorted(self._rng.sample(available_fonts, font_count))

        # Hardware specs
        hw_cores = self._rng.choice([4, 6, 8, 12, 16])
        memory = self._rng.choice([4, 8, 16, 32])

        # Canvas noise seed
        canvas_noise = self._rng.uniform(0.0001, 0.001)

        # Profile ID (deterministic hash of key attributes)
        profile_hash = hashlib.sha256(
            f"{user_agent}:{resolution}:{webgl_renderer}".encode()
        ).hexdigest()[:12]

        profile = BrowserProfile(
            profile_id=profile_hash,
            user_agent=user_agent,
            browser=browser,
            os=os_family,
            platform=platform,
            screen_resolution=resolution,
            color_depth=24,
            timezone=self._rng.choice(_TIMEZONES),
            language=self._rng.choice(_LANGUAGES),
            fonts=fonts,
            canvas_noise=canvas_noise,
            webgl_vendor=webgl_vendor,
            webgl_renderer=webgl_renderer,
            hardware_concurrency=hw_cores,
            device_memory=memory,
            touch_support=(os_family == "mac" and self._rng.random() > 0.5),
            do_not_track="1" if self._rng.random() > 0.7 else None,
        )

        if self._consistent:
            self._session_profile = profile

        logger.debug(
            "FingerprintRotator: generated profile %s (%s/%s)",
            profile.profile_id, browser, os_family,
        )
        return profile

    def get_canvas_injection_script(self, profile: BrowserProfile) -> str:
        """Generate a Playwright init script for canvas fingerprint noise.

        Injects subtle noise into canvas rendering to produce a unique
        fingerprint that changes per profile.

        Args:
            profile: BrowserProfile with canvas_noise seed.

        Returns:
            JavaScript code string to pass as init_script to Playwright.
        """
        noise = profile.canvas_noise
        return f"""
        (() => {{
            const noise = {noise};
            const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
            const originalToBlob = HTMLCanvasElement.prototype.toBlob;
            const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;

            function addNoise(imageData) {{
                const data = imageData.data;
                for (let i = 0; i < data.length; i += 4) {{
                    data[i] += (Math.random() - 0.5) * noise * 255;
                    data[i+1] += (Math.random() - 0.5) * noise * 255;
                    data[i+2] += (Math.random() - 0.5) * noise * 255;
                }}
                return imageData;
            }}

            HTMLCanvasElement.prototype.toDataURL = function(...args) {{
                const ctx = this.getContext('2d');
                if (ctx) {{
                    const imageData = ctx.getImageData(0, 0, this.width, this.height);
                    addNoise(imageData);
                    ctx.putImageData(imageData, 0, 0);
                }}
                return originalToDataURL.apply(this, args);
            }};

            CanvasRenderingContext2D.prototype.getImageData = function(...args) {{
                const imageData = originalGetImageData.apply(this, args);
                return addNoise(imageData);
            }};
        }})();
        """

    def get_webgl_injection_script(self, profile: BrowserProfile) -> str:
        """Generate a Playwright init script for WebGL fingerprint spoofing.

        Overrides WebGL parameter reporting to match the profile's
        vendor/renderer strings.

        Args:
            profile: BrowserProfile with webgl_vendor and webgl_renderer.

        Returns:
            JavaScript code string for Playwright init_script.
        """
        vendor = profile.webgl_vendor
        renderer = profile.webgl_renderer
        return f"""
        (() => {{
            const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
            const originalGetExtension = WebGLRenderingContext.prototype.getExtension;

            const UNMASKED_VENDOR_WEBGL = 0x9245;
            const UNMASKED_RENDERER_WEBGL = 0x9246;

            WebGLRenderingContext.prototype.getParameter = function(param) {{
                if (param === UNMASKED_VENDOR_WEBGL) return '{vendor}';
                if (param === UNMASKED_RENDERER_WEBGL) return '{renderer}';
                return originalGetParameter.call(this, param);
            }};
        }})();
        """

    def rotate(self) -> BrowserProfile:
        """Force rotation to a new profile (invalidates cached session profile).

        Returns:
            New BrowserProfile.
        """
        self._session_profile = None
        return self.generate_profile()

    @staticmethod
    def get_user_agent_pool() -> list[str]:
        """Get the full User-Agent pool.

        Returns:
            List of all User-Agent strings.
        """
        pool: list[str] = []
        for agents in _USER_AGENTS.values():
            pool.extend(agents)
        return pool
