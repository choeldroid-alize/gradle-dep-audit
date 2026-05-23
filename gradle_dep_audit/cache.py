"""Simple file-based cache for vulnerability query results."""

import json
import os
import time
from pathlib import Path
from typing import Optional

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "gradle-dep-audit"
DEFAULT_TTL_SECONDS = 60 * 60 * 24  # 24 hours


class VulnerabilityCache:
    """Disk-backed cache for OSS Index vulnerability responses."""

    def __init__(self, cache_dir: Path = DEFAULT_CACHE_DIR, ttl: int = DEFAULT_TTL_SECONDS):
        self.cache_dir = cache_dir
        self.ttl = ttl
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, purl: str) -> Path:
        safe_name = purl.replace("/", "_").replace(":", "_").replace("@", "_")
        return self.cache_dir / f"{safe_name}.json"

    def get(self, purl: str) -> Optional[dict]:
        """Return cached entry for purl if present and not expired, else None."""
        path = self._cache_path(purl)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if time.time() - data.get("cached_at", 0) > self.ttl:
                path.unlink(missing_ok=True)
                return None
            return data.get("payload")
        except (json.JSONDecodeError, KeyError, OSError):
            return None

    def set(self, purl: str, payload: dict) -> None:
        """Persist payload for purl to disk."""
        path = self._cache_path(purl)
        entry = {"cached_at": time.time(), "payload": payload}
        try:
            path.write_text(json.dumps(entry), encoding="utf-8")
        except OSError:
            pass  # cache write failure is non-fatal

    def invalidate(self, purl: str) -> None:
        """Remove a single cached entry."""
        self._cache_path(purl).unlink(missing_ok=True)

    def clear(self) -> int:
        """Remove all cached entries. Returns count of removed files."""
        removed = 0
        for f in self.cache_dir.glob("*.json"):
            f.unlink(missing_ok=True)
            removed += 1
        return removed
