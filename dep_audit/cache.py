"""Simple TTL cache for PyPI and OSV responses to reduce redundant network calls."""
from __future__ import annotations

import time
from typing import Any, Dict, Optional, Tuple

_DEFAULT_TTL = 300  # seconds


class TTLCache:
    """In-memory key/value cache with per-entry TTL."""

    def __init__(self, ttl: int = _DEFAULT_TTL) -> None:
        self.ttl = ttl
        self._store: Dict[str, Tuple[Any, float]] = {}

    def get(self, key: str) -> Optional[Any]:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.monotonic() > expires_at:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        self._store[key] = (value, time.monotonic() + self.ttl)

    def invalidate(self, key: str) -> None:
        self._store.pop(key, None)

    def clear(self) -> None:
        self._store.clear()

    def __len__(self) -> int:
        now = time.monotonic()
        return sum(1 for _, (_, exp) in self._store.items() if exp > now)


# Module-level shared caches
pypi_cache: TTLCache = TTLCache(ttl=300)
osv_cache: TTLCache = TTLCache(ttl=600)
