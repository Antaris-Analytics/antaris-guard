"""
Shared utilities for antaris-guard.

Atomic file writes, logging helpers, and common patterns
used across multiple modules.
"""

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


def atomic_write_json(path: str, data: Any, indent: int = 2) -> None:
    """
    Write JSON data to a file atomically.

    Uses temp file + fsync + os.replace to prevent partial writes.
    Creates parent directories if needed. Logs errors instead of
    silently swallowing them — callers can catch if needed.

    Args:
        path: Destination file path
        data: JSON-serializable data
        indent: JSON indentation (use None for compact)

    Raises:
        OSError: If the write fails after best-effort attempt
    """
    temp_path = path + '.tmp'
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)

    try:
        with open(temp_path, 'w') as f:
            json.dump(data, f, indent=indent)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
    except (OSError, IOError) as e:
        logger.error("Failed to write %s: %s", path, e)
        # Clean up temp file if it exists
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise
