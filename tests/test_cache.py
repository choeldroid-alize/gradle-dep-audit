"""Tests for gradle_dep_audit.cache."""

import json
import time
from pathlib import Path

import pytest

from gradle_dep_audit.cache import VulnerabilityCache


@pytest.fixture()
def cache(tmp_path):
    return VulnerabilityCache(cache_dir=tmp_path, ttl=60)


def test_get_returns_none_for_missing_entry(cache):
    assert cache.get("pkg:maven/com.example/foo@1.0") is None


def test_set_and_get_roundtrip(cache):
    purl = "pkg:maven/com.example/bar@2.3"
    payload = {"vulnerabilities": [], "coordinates": purl}
    cache.set(purl, payload)
    result = cache.get(purl)
    assert result == payload


def test_get_returns_none_after_ttl_expired(tmp_path):
    cache = VulnerabilityCache(cache_dir=tmp_path, ttl=1)
    purl = "pkg:maven/org.test/lib@0.1"
    payload = {"vulnerabilities": []}
    cache.set(purl, payload)
    # Manually backdate the cached_at timestamp
    path = cache._cache_path(purl)
    data = json.loads(path.read_text())
    data["cached_at"] = time.time() - 10
    path.write_text(json.dumps(data))
    assert cache.get(purl) is None


def test_invalidate_removes_entry(cache):
    purl = "pkg:maven/org.foo/baz@3.0"
    cache.set(purl, {"vulnerabilities": []})
    cache.invalidate(purl)
    assert cache.get(purl) is None


def test_clear_removes_all_entries(cache):
    purls = [
        "pkg:maven/a/b@1.0",
        "pkg:maven/c/d@2.0",
        "pkg:maven/e/f@3.0",
    ]
    for p in purls:
        cache.set(p, {"vulnerabilities": []})
    removed = cache.clear()
    assert removed == len(purls)
    for p in purls:
        assert cache.get(p) is None


def test_get_handles_corrupt_cache_file(cache, tmp_path):
    purl = "pkg:maven/bad/data@1.0"
    path = cache._cache_path(purl)
    path.write_text("not valid json", encoding="utf-8")
    assert cache.get(purl) is None


def test_cache_dir_created_if_missing(tmp_path):
    new_dir = tmp_path / "nested" / "cache"
    cache = VulnerabilityCache(cache_dir=new_dir)
    assert new_dir.exists()
