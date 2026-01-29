"""
Tweek Licensing - Feature gating and license validation.

License tiers:
    - FREE: Basic pattern matching and logging
    - PRO: LLM review, session analysis, rate limiting
    - ENTERPRISE: Custom patterns, SSO, audit API, SLA

License keys are stored in ~/.tweek/license.key
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import Callable, Optional, List

# License key secret - in production, this would be more secure
# This is used to validate license keys were issued by Tweek
LICENSE_SECRET = os.environ.get("TWEEK_LICENSE_SECRET", "tweek-2025-license-secret")

LICENSE_FILE = Path.home() / ".tweek" / "license.key"


class Tier(Enum):
    """License tiers."""
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class LicenseError(Exception):
    """Raised when a feature requires a higher license tier."""
    pass


@dataclass
class LicenseInfo:
    """License information."""
    tier: Tier
    email: str
    issued_at: int  # Unix timestamp
    expires_at: Optional[int]  # Unix timestamp, None = never
    features: List[str]  # Additional feature flags

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    @property
    def is_valid(self) -> bool:
        return not self.is_expired


# Feature definitions by tier
TIER_FEATURES = {
    Tier.FREE: [
        "pattern_matching",
        "basic_logging",
        "vault_storage",
        "cli_commands",
        "global_install",
        "project_install",
    ],
    Tier.PRO: [
        "llm_review",
        "session_analysis",
        "rate_limiting",
        "advanced_logging",
        "log_export",
        "custom_tiers",
        "priority_support",
    ],
    Tier.ENTERPRISE: [
        "custom_patterns",
        "pattern_api",
        "sso_integration",
        "audit_api",
        "webhook_alerts",
        "sla_guarantee",
        "dedicated_support",
        "on_premise",
    ],
}


class License:
    """License manager for Tweek."""

    _instance: Optional["License"] = None

    def __init__(self):
        self._info: Optional[LicenseInfo] = None
        self._load_license()

    @classmethod
    def get_instance(cls) -> "License":
        """Get singleton license instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_license(self) -> None:
        """Load license from file."""
        if not LICENSE_FILE.exists():
            self._info = None
            return

        try:
            content = LICENSE_FILE.read_text().strip()
            self._info = self._validate_license_key(content)
        except Exception:
            self._info = None

    def _validate_license_key(self, key: str) -> Optional[LicenseInfo]:
        """
        Validate a license key and return license info.

        License key format: base64(json_payload).signature
        """
        try:
            import base64

            if "." not in key:
                return None

            payload_b64, signature = key.rsplit(".", 1)

            # Verify signature
            expected_sig = hmac.new(
                LICENSE_SECRET.encode(),
                payload_b64.encode(),
                hashlib.sha256
            ).hexdigest()[:32]

            if not hmac.compare_digest(signature, expected_sig):
                return None

            # Decode payload
            payload = json.loads(base64.b64decode(payload_b64))

            return LicenseInfo(
                tier=Tier(payload["tier"]),
                email=payload["email"],
                issued_at=payload["issued_at"],
                expires_at=payload.get("expires_at"),
                features=payload.get("features", []),
            )
        except Exception:
            return None

    @property
    def tier(self) -> Tier:
        """Get current license tier."""
        if self._info is None or not self._info.is_valid:
            return Tier.FREE
        return self._info.tier

    @property
    def info(self) -> Optional[LicenseInfo]:
        """Get full license info."""
        return self._info

    @property
    def is_pro(self) -> bool:
        """Check if license is Pro or higher."""
        return self.tier in [Tier.PRO, Tier.ENTERPRISE]

    @property
    def is_enterprise(self) -> bool:
        """Check if license is Enterprise."""
        return self.tier == Tier.ENTERPRISE

    def has_feature(self, feature: str) -> bool:
        """Check if current license includes a feature."""
        # Check tier features (cumulative)
        tier_order = [Tier.FREE, Tier.PRO, Tier.ENTERPRISE]
        current_idx = tier_order.index(self.tier)

        for i in range(current_idx + 1):
            if feature in TIER_FEATURES.get(tier_order[i], []):
                return True

        # Check additional feature flags
        if self._info and feature in self._info.features:
            return True

        return False

    def get_available_features(self) -> List[str]:
        """Get list of all available features for current tier."""
        features = []
        tier_order = [Tier.FREE, Tier.PRO, Tier.ENTERPRISE]
        current_idx = tier_order.index(self.tier)

        for i in range(current_idx + 1):
            features.extend(TIER_FEATURES.get(tier_order[i], []))

        if self._info:
            features.extend(self._info.features)

        return list(set(features))

    def activate(self, license_key: str) -> tuple[bool, str]:
        """
        Activate a license key.

        Returns:
            (success, message)
        """
        info = self._validate_license_key(license_key)

        if info is None:
            return False, "Invalid license key"

        if info.is_expired:
            return False, "License key has expired"

        # Save license
        LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
        LICENSE_FILE.write_text(license_key)

        self._info = info

        return True, f"License activated: {info.tier.value.upper()} tier"

    def deactivate(self) -> tuple[bool, str]:
        """Remove current license."""
        if LICENSE_FILE.exists():
            LICENSE_FILE.unlink()
        self._info = None
        return True, "License deactivated, reverted to FREE tier"


def get_license() -> License:
    """Get the license manager instance."""
    return License.get_instance()


def require_tier(min_tier: Tier) -> Callable:
    """
    Decorator to require a minimum license tier.

    Usage:
        @require_tier(Tier.PRO)
        def my_pro_feature():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            license = get_license()
            tier_order = [Tier.FREE, Tier.PRO, Tier.ENTERPRISE]

            if tier_order.index(license.tier) < tier_order.index(min_tier):
                raise LicenseError(
                    f"This feature requires Tweek {min_tier.value.upper()}. "
                    f"Visit https://gettweek.com/pricing to upgrade."
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_pro(func: Callable) -> Callable:
    """Decorator to require Pro license."""
    return require_tier(Tier.PRO)(func)


def require_enterprise(func: Callable) -> Callable:
    """Decorator to require Enterprise license."""
    return require_tier(Tier.ENTERPRISE)(func)


def require_feature(feature: str) -> Callable:
    """
    Decorator to require a specific feature.

    Usage:
        @require_feature("llm_review")
        def semantic_analysis():
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            license = get_license()
            if not license.has_feature(feature):
                raise LicenseError(
                    f"This feature ({feature}) requires a higher license tier. "
                    f"Visit https://gettweek.com/pricing to upgrade."
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ============================================================
# License Key Generation (for internal/admin use)
# ============================================================

def generate_license_key(
    tier: Tier,
    email: str,
    expires_at: Optional[int] = None,
    features: Optional[List[str]] = None,
) -> str:
    """
    Generate a license key.

    This is an admin function - in production, this would be
    on a separate license server, not in the client code.

    Args:
        tier: License tier
        email: Customer email
        expires_at: Expiration timestamp (None = never)
        features: Additional feature flags

    Returns:
        License key string
    """
    import base64

    payload = {
        "tier": tier.value,
        "email": email,
        "issued_at": int(time.time()),
        "expires_at": expires_at,
        "features": features or [],
    }

    payload_json = json.dumps(payload, separators=(",", ":"))
    payload_b64 = base64.b64encode(payload_json.encode()).decode()

    signature = hmac.new(
        LICENSE_SECRET.encode(),
        payload_b64.encode(),
        hashlib.sha256
    ).hexdigest()[:32]

    return f"{payload_b64}.{signature}"
