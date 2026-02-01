#!/usr/bin/env python3
"""
Tweek Plugin Registry Client

Manages the curated plugin registry:
- Fetches registry from remote URL
- Caches locally with configurable TTL
- Verifies registry HMAC signature
- Searches available plugins
- Falls back to local cache when offline

Registry Format:
{
    "schema_version": 1,
    "updated_at": "2026-01-29T00:00:00Z",
    "registry_signature": "<hmac>",
    "plugins": [
        {
            "name": "tweek-plugin-cursor-detector",
            "category": "detectors",
            "repo_url": "https://github.com/gettweek/tweek-plugin-cursor-detector.git",
            "latest_version": "1.2.0",
            "requires_license_tier": "free",
            "verified": true,
            "deprecated": false,
            "versions": {
                "1.2.0": {"git_ref": "v1.2.0", "checksums": {"plugin.py": "sha256:..."}}
            }
        }
    ]
}
"""

import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen

from tweek.plugins.git_security import TWEEK_SIGNING_KEY

logger = logging.getLogger(__name__)

# Default registry URL
DEFAULT_REGISTRY_URL = "https://registry.gettweek.com/v1/plugins.json"

# Default cache TTL: 1 hour
DEFAULT_CACHE_TTL_SECONDS = 3600

# Current schema version this client understands
SUPPORTED_SCHEMA_VERSIONS = {1}

# Tweek plugins directory
TWEEK_HOME = Path.home() / ".tweek"
PLUGINS_DIR = TWEEK_HOME / "plugins"
REGISTRY_CACHE_PATH = TWEEK_HOME / "registry.json"
REGISTRY_META_PATH = TWEEK_HOME / "registry_meta.json"


class RegistryError(Exception):
    """Raised when registry operations fail."""
    pass


class RegistryEntry:
    """Represents a single plugin entry in the registry."""

    def __init__(self, data: dict):
        self._data = data

    @property
    def name(self) -> str:
        return self._data.get("name", "")

    @property
    def category(self) -> str:
        return self._data.get("category", "")

    @property
    def repo_url(self) -> str:
        return self._data.get("repo_url", "")

    @property
    def latest_version(self) -> str:
        return self._data.get("latest_version", "")

    @property
    def requires_license_tier(self) -> str:
        return self._data.get("requires_license_tier", "free")

    @property
    def verified(self) -> bool:
        return self._data.get("verified", False)

    @property
    def deprecated(self) -> bool:
        return self._data.get("deprecated", False)

    @property
    def description(self) -> str:
        return self._data.get("description", "")

    @property
    def author(self) -> str:
        return self._data.get("author", "Tweek")

    @property
    def tags(self) -> List[str]:
        return self._data.get("tags", [])

    @property
    def versions(self) -> Dict[str, dict]:
        return self._data.get("versions", {})

    def get_version_info(self, version: str) -> Optional[dict]:
        """Get info for a specific version."""
        return self.versions.get(version)

    def get_git_ref(self, version: Optional[str] = None) -> str:
        """Get the git ref (tag/branch) for a version."""
        ver = version or self.latest_version
        version_info = self.versions.get(ver, {})
        return version_info.get("git_ref", f"v{ver}")

    def get_checksums(self, version: Optional[str] = None) -> Dict[str, str]:
        """Get checksums for a specific version."""
        ver = version or self.latest_version
        version_info = self.versions.get(ver, {})
        return version_info.get("checksums", {})

    def to_dict(self) -> dict:
        return dict(self._data)

    def __repr__(self) -> str:
        return f"RegistryEntry(name={self.name!r}, version={self.latest_version!r})"


class PluginRegistryClient:
    """
    Client for the Tweek plugin registry.

    Fetches, caches, and searches the curated plugin registry.
    Verifies registry signature before trusting data.
    Falls back to local cache when network is unavailable.
    """

    def __init__(
        self,
        registry_url: Optional[str] = None,
        cache_ttl: int = DEFAULT_CACHE_TTL_SECONDS,
        cache_path: Optional[Path] = None,
        signing_key: Optional[str] = None,
    ):
        self._registry_url = registry_url or os.environ.get(
            "TWEEK_REGISTRY_URL", DEFAULT_REGISTRY_URL
        )
        self._cache_ttl = cache_ttl
        self._cache_path = cache_path or REGISTRY_CACHE_PATH
        self._meta_path = self._cache_path.parent / "registry_meta.json"
        self._signing_key = signing_key or TWEEK_SIGNING_KEY
        self._registry_data: Optional[dict] = None
        self._entries: Optional[Dict[str, RegistryEntry]] = None
        self._last_fetch_time: Optional[float] = None

    @property
    def registry_url(self) -> str:
        return self._registry_url

    def fetch(self, force_refresh: bool = False) -> Dict[str, RegistryEntry]:
        """
        Fetch the plugin registry.

        Uses cached data if available and not expired, unless force_refresh=True.
        Falls back to local cache if network is unavailable.

        Args:
            force_refresh: If True, bypass cache TTL and fetch from network

        Returns:
            Dict mapping plugin name to RegistryEntry

        Raises:
            RegistryError: If no registry data is available (no network + no cache)
        """
        # Check if cached data is still valid
        if not force_refresh and self._is_cache_valid():
            if self._entries is not None:
                return self._entries

            # Try loading from disk cache
            cached = self._load_cache()
            if cached is not None:
                self._registry_data = cached
                self._entries = self._parse_entries(cached)
                return self._entries

        # Try fetching from network
        try:
            raw_data = self._fetch_remote()
            registry = json.loads(raw_data)

            # Verify schema version
            schema_version = registry.get("schema_version", 0)
            if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
                raise RegistryError(
                    f"Unsupported registry schema version {schema_version}. "
                    f"Supported: {SUPPORTED_SCHEMA_VERSIONS}. "
                    f"Please update Tweek."
                )

            # Verify signature
            if not self._verify_registry_signature(registry):
                raise RegistryError("Registry signature verification failed")

            # Cache to disk
            self._save_cache(raw_data)

            self._registry_data = registry
            self._entries = self._parse_entries(registry)
            self._last_fetch_time = time.time()

            logger.info(f"Fetched registry: {len(self._entries)} plugins available")
            return self._entries

        except (URLError, OSError, json.JSONDecodeError) as e:
            logger.warning(f"Failed to fetch registry from network: {e}")

            # Fall back to local cache
            cached = self._load_cache()
            if cached is not None:
                logger.info("Using cached registry (network unavailable)")
                self._registry_data = cached
                self._entries = self._parse_entries(cached)
                return self._entries

            raise RegistryError(
                "No registry data available. Network is unavailable and no local cache exists. "
                "Connect to the internet and run 'tweek plugins registry --refresh'."
            ) from e

    def search(
        self,
        query: Optional[str] = None,
        category: Optional[str] = None,
        tier: Optional[str] = None,
        include_deprecated: bool = False,
    ) -> List[RegistryEntry]:
        """
        Search the plugin registry.

        Args:
            query: Text search (matches name, description, tags)
            category: Filter by category
            tier: Filter by license tier
            include_deprecated: Include deprecated plugins

        Returns:
            List of matching RegistryEntry objects
        """
        entries = self.fetch()
        results = []

        for entry in entries.values():
            # Skip unverified plugins
            if not entry.verified:
                continue

            # Skip deprecated unless requested
            if entry.deprecated and not include_deprecated:
                continue

            # Filter by category
            if category and entry.category != category:
                continue

            # Filter by tier
            if tier and entry.requires_license_tier != tier:
                continue

            # Text search
            if query:
                query_lower = query.lower()
                searchable = (
                    entry.name.lower() + " " +
                    entry.description.lower() + " " +
                    " ".join(t.lower() for t in entry.tags)
                )
                if query_lower not in searchable:
                    continue

            results.append(entry)

        return results

    def get_plugin(self, name: str) -> Optional[RegistryEntry]:
        """
        Get a specific plugin entry by name.

        Args:
            name: Plugin name (e.g., "tweek-plugin-cursor-detector")

        Returns:
            RegistryEntry if found, None otherwise
        """
        entries = self.fetch()
        entry = entries.get(name)

        if entry and not entry.verified:
            logger.warning(f"Plugin {name} exists but is not verified - refusing to load")
            return None

        return entry

    def is_plugin_available(self, name: str) -> bool:
        """Check if a plugin is available in the registry."""
        entry = self.get_plugin(name)
        return entry is not None and entry.verified and not entry.deprecated

    def get_update_available(
        self,
        name: str,
        current_version: str,
    ) -> Optional[str]:
        """
        Check if an update is available for a plugin.

        Args:
            name: Plugin name
            current_version: Currently installed version

        Returns:
            New version string if update available, None otherwise
        """
        entry = self.get_plugin(name)
        if entry is None:
            return None

        latest = entry.latest_version
        if latest and latest != current_version:
            # Simple version comparison
            if self._version_gt(latest, current_version):
                return latest

        return None

    def _fetch_remote(self) -> bytes:
        """Fetch registry from remote URL."""
        req = Request(
            self._registry_url,
            headers={
                "User-Agent": "Tweek-Plugin-Client/1.0",
                "Accept": "application/json",
            },
        )
        with urlopen(req, timeout=15) as response:
            return response.read()

    def _verify_registry_signature(self, registry: dict) -> bool:
        """Verify the HMAC signature of the registry."""
        signature = registry.get("registry_signature", "")
        if not signature:
            if not self._signing_key:
                logger.warning("Registry has no signature and no signing key configured — allowing in dev mode")
                return True
            logger.warning("Registry has no signature but signing key is configured — rejecting")
            return False

        # Sign the plugins array (the payload)
        plugins_json = json.dumps(
            registry.get("plugins", []),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

        if not self._signing_key:
            logger.warning("Registry has signature but no signing key configured — cannot verify, rejecting")
            return False
        key = self._signing_key.encode()
        expected_sig = hmac.new(key, plugins_json, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig, signature)

    def _is_cache_valid(self) -> bool:
        """Check if in-memory or disk cache is still within TTL."""
        # Check in-memory cache
        if self._last_fetch_time is not None:
            elapsed = time.time() - self._last_fetch_time
            return elapsed < self._cache_ttl

        # Check disk cache metadata
        if self._meta_path.exists():
            try:
                with open(self._meta_path) as f:
                    meta = json.load(f)
                fetched_at = meta.get("fetched_at", 0)
                elapsed = time.time() - fetched_at
                return elapsed < self._cache_ttl
            except (json.JSONDecodeError, IOError):
                pass

        return False

    def _load_cache(self) -> Optional[dict]:
        """Load registry from disk cache."""
        if not self._cache_path.exists():
            return None

        try:
            with open(self._cache_path) as f:
                data = json.load(f)

            # Verify cached registry signature
            if not self._verify_registry_signature(data):
                logger.warning("Cached registry signature invalid - ignoring cache")
                return None

            return data
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load registry cache: {e}")
            return None

    def _save_cache(self, raw_data: bytes) -> None:
        """Save registry data to disk cache."""
        try:
            # Ensure directory exists
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)

            # Write registry data
            with open(self._cache_path, "wb") as f:
                f.write(raw_data)

            # Write metadata
            meta = {
                "fetched_at": time.time(),
                "fetched_from": self._registry_url,
                "fetched_at_iso": datetime.now(timezone.utc).isoformat(),
            }
            with open(self._meta_path, "w") as f:
                json.dump(meta, f, indent=2)

        except IOError as e:
            logger.warning(f"Failed to save registry cache: {e}")

    def _parse_entries(self, registry: dict) -> Dict[str, RegistryEntry]:
        """Parse registry data into RegistryEntry objects."""
        entries = {}
        for plugin_data in registry.get("plugins", []):
            name = plugin_data.get("name", "")
            if name:
                entries[name] = RegistryEntry(plugin_data)
        return entries

    @staticmethod
    def _version_gt(v1: str, v2: str) -> bool:
        """Check if version v1 is greater than v2 (simple semver comparison)."""
        try:
            parts1 = [int(p) for p in v1.split(".")]
            parts2 = [int(p) for p in v2.split(".")]
            # Pad shorter version with zeros
            while len(parts1) < 3:
                parts1.append(0)
            while len(parts2) < 3:
                parts2.append(0)
            return tuple(parts1) > tuple(parts2)
        except (ValueError, AttributeError):
            return False

    def clear_cache(self) -> None:
        """Clear both in-memory and disk caches."""
        self._registry_data = None
        self._entries = None
        self._last_fetch_time = None

        for path in (self._cache_path, self._meta_path):
            if path.exists():
                try:
                    path.unlink()
                except IOError:
                    pass

    def get_registry_info(self) -> Dict[str, Any]:
        """Get metadata about the registry state."""
        info = {
            "url": self._registry_url,
            "cache_path": str(self._cache_path),
            "cache_ttl_seconds": self._cache_ttl,
            "cache_valid": self._is_cache_valid(),
            "last_fetch_time": self._last_fetch_time,
        }

        if self._registry_data:
            info["schema_version"] = self._registry_data.get("schema_version")
            info["updated_at"] = self._registry_data.get("updated_at")
            info["total_plugins"] = len(self._registry_data.get("plugins", []))

        if self._meta_path.exists():
            try:
                with open(self._meta_path) as f:
                    meta = json.load(f)
                info["cache_fetched_at"] = meta.get("fetched_at_iso")
            except (json.JSONDecodeError, IOError):
                pass

        return info
