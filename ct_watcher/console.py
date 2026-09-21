"""Thread-safe console output for CT Watcher."""

from __future__ import annotations

import sys
import threading

_lock = threading.Lock()


def log(message: str) -> None:
    """Write one line to stdout atomically across threads."""
    with _lock:
        sys.stdout.write(message + "\n")
        sys.stdout.flush()
