"""
Shared utilities for antaris-guard.

Atomic file writes, logging helpers, and common patterns
used across multiple modules.
"""

import json
import logging
import os
import tempfile
from typing import Any

logger = logging.getLogger(__name__)


def atomic_write_json(path: str, data: Any, indent: int = 2) -> None:
    """
    Write JSON data to a file atomically.

    Uses mkstemp + fsync + os.replace to prevent partial writes and
    avoid temp file collisions between concurrent writers. Creates
    parent directories if needed. Logs errors instead of silently
    swallowing them — callers can catch if needed.

    Note: This is safe against concurrent writers within a single
    filesystem but does NOT provide multi-process locking. For
    multi-process safety, use external file locking.

    Args:
        path: Destination file path
        data: JSON-serializable data
        indent: JSON indentation (use None for compact)

    Raises:
        OSError: If the write fails after best-effort attempt
    """
    dir_path = os.path.dirname(os.path.abspath(path))
    os.makedirs(dir_path, exist_ok=True)

    fd = None
    temp_path = None
    try:
        fd, temp_path = tempfile.mkstemp(dir=dir_path, suffix='.tmp')
        with os.fdopen(fd, 'w') as f:
            fd = None  # os.fdopen takes ownership
            json.dump(data, f, indent=indent)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
        temp_path = None  # replaced successfully
    except (OSError, IOError) as e:
        logger.error("Failed to write %s: %s", path, e)
        raise
    finally:
        if fd is not None:
            os.close(fd)
        if temp_path is not None:
            try:
                os.remove(temp_path)
            except OSError:
                pass
