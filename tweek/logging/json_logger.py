#!/usr/bin/env python3
"""
Tweek JSON Event Logger

Structured NDJSON (newline-delimited JSON) logging for security events.
Writes to ~/.tweek/security_events.jsonl with automatic rotation.

This supplements the primary SQLite logger with a format suitable for
ingestion into log aggregation systems (ELK, Splunk, Datadog, etc.).

Enable via config: logging.json_events: true
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Defaults
DEFAULT_LOG_PATH = Path.home() / ".tweek" / "security_events.jsonl"
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_ROTATED_FILES = 5


class JsonEventLogger:
    """
    Writes SecurityEvents as newline-delimited JSON (NDJSON).

    Each line is a self-contained JSON object with:
    - ISO 8601 timestamp
    - All SecurityEvent fields
    - Correlation ID for linking related events
    - Source (hooks/mcp/mcp_proxy/http_proxy)
    """

    def __init__(
        self,
        log_path: Optional[Path] = None,
        enabled: bool = False,
        max_size_bytes: int = MAX_FILE_SIZE_BYTES,
        max_rotated: int = MAX_ROTATED_FILES,
    ):
        self.log_path = log_path or DEFAULT_LOG_PATH
        self.enabled = enabled
        self.max_size_bytes = max_size_bytes
        self.max_rotated = max_rotated

    def write_event(
        self,
        event: "SecurityEvent",
        redacted_command: Optional[str] = None,
        redacted_reason: Optional[str] = None,
        redacted_metadata: Optional[Dict[str, Any]] = None,
    ):
        """Write a single event as a JSON line.

        Uses pre-redacted values from the SecurityLogger to avoid
        double-redaction overhead.
        """
        if not self.enabled:
            return

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event.event_type.value,
            "tool_name": event.tool_name,
            "command": redacted_command,
            "tier": event.tier,
            "pattern_name": event.pattern_name,
            "pattern_severity": event.pattern_severity,
            "decision": event.decision,
            "decision_reason": redacted_reason,
            "user_response": event.user_response,
            "session_id": event.session_id,
            "working_directory": event.working_directory,
            "correlation_id": event.correlation_id,
            "source": event.source,
            "metadata": redacted_metadata,
        }

        # Strip None values for cleaner output
        record = {k: v for k, v in record.items() if v is not None}

        try:
            self._rotate_if_needed()
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_path, "a") as f:
                f.write(json.dumps(record, default=str) + "\n")
        except Exception as e:
            logger.debug(f"Failed to write JSON event: {e}")

    def _rotate_if_needed(self):
        """Rotate log file if it exceeds the maximum size."""
        if not self.log_path.exists():
            return

        try:
            size = self.log_path.stat().st_size
        except OSError:
            return

        if size < self.max_size_bytes:
            return

        # Rotate: .jsonl -> .jsonl.1, .jsonl.1 -> .jsonl.2, etc.
        for i in range(self.max_rotated, 0, -1):
            src = Path(f"{self.log_path}.{i}")
            dst = Path(f"{self.log_path}.{i + 1}")
            if i == self.max_rotated and src.exists():
                src.unlink()  # Delete oldest
            elif src.exists():
                src.rename(dst)

        # Move current to .1
        self.log_path.rename(Path(f"{self.log_path}.1"))


# Singleton instance
_json_logger: Optional[JsonEventLogger] = None


def get_json_logger() -> Optional[JsonEventLogger]:
    """Get the singleton JSON event logger.

    Reads the enabled flag from Tweek config on first access.
    Returns None if JSON logging is not configured.
    """
    global _json_logger
    if _json_logger is None:
        enabled = _read_json_logging_config()
        _json_logger = JsonEventLogger(enabled=enabled)
    return _json_logger


def _read_json_logging_config() -> bool:
    """Check if JSON event logging is enabled in config."""
    try:
        import yaml
        config_path = Path.home() / ".tweek" / "config.yaml"
        if config_path.exists():
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
            return config.get("logging", {}).get("json_events", False)
    except Exception:
        pass
    return False
