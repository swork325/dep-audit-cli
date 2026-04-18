"""Tests for dep_audit.cache."""
from __future__ import annotations

import time
import pytest

from dep_audit.cache import TTLCache


def test_set_and_get():
    cache = TTLCache(ttl=60)
    cache.set("key", "value")
    assert cache.get("key") == "value"


def test_get_missing_returns_none():
    cache = TTLCache(ttl=60)
    assert cache.get("missing") is None


def test_expired_entry_returns_none(monkeypatch):
    cache = TTLCache(ttl=1)
    cache.set("k", "v")
    monkeypatch.setattr("dep_audit.cache.time.monotonic", lambda: time.monotonic() + 10)
    assert cache.get("k") is None


def test_invalidate_removes_entry():
    cache = TTLCache(ttl=60)
    cache.set("x", 42)
    cache.invalidate("x")
    assert cache.get("x") is None


def test_clear_empties_cache():
    cache = TTLCache(ttl=60)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.clear()
    assert len(cache) == 0


def test_len_counts_live_entries():
    cache = TTLCache(ttl=60)
    cache.set("a", 1)
    cache.set("b", 2)
    assert len(cache) == 2


def test_len_excludes_expired(monkeypatch):
    cache = TTLCache(ttl=1)
    cache.set("a", 1)
    cache.set("b", 2)
    monkeypatch.setattr("dep_audit.cache.time.monotonic", lambda: time.monotonic() + 10)
    assert len(cache) == 0


def test_overwrite_entry():
    cache = TTLCache(ttl=60)
    cache.set("key", "old")
    cache.set("key", "new")
    assert cache.get("key") == "new"
