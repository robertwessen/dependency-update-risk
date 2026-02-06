"""Configuration management for dependency risk analyzer."""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from platformdirs import user_cache_dir

from .models import CacheEntry


@dataclass
class Config:
    """Application configuration."""

    api_url: str = ""
    api_key: str = ""
    model: str = "gpt-4"
    cache_ttl_hours: int = 24
    use_cache: bool = True
    verbose: bool = False
    debug: bool = False
    max_context_tokens: int = 8192
    github_token: Optional[str] = None

    @classmethod
    def from_env(cls) -> "Config":
        """Create config from environment variables."""
        return cls(
            api_url=os.environ.get("DEP_RISK_API_URL", ""),
            api_key=os.environ.get("DEP_RISK_API_KEY", ""),
            model=os.environ.get("DEP_RISK_MODEL", "gpt-4"),
            github_token=os.environ.get("GITHUB_TOKEN"),
        )

    def with_overrides(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        cache_ttl: Optional[int] = None,
        no_cache: bool = False,
        verbose: bool = False,
        debug: bool = False,
        max_context_tokens: Optional[int] = None,
    ) -> "Config":
        """Return a new config with CLI overrides applied."""
        return Config(
            api_url=api_url or self.api_url,
            api_key=api_key or self.api_key,
            model=model or self.model,
            cache_ttl_hours=cache_ttl if cache_ttl is not None else self.cache_ttl_hours,
            use_cache=not no_cache and self.use_cache,
            verbose=verbose or self.verbose,
            debug=debug or self.debug,
            max_context_tokens=max_context_tokens if max_context_tokens is not None else self.max_context_tokens,
            github_token=self.github_token,
        )


@dataclass
class Cache:
    """Simple JSON file-based cache."""

    cache_dir: Path = field(default_factory=lambda: Path(user_cache_dir("dep-risk")))
    ttl_hours: int = 24

    def __post_init__(self) -> None:
        """Ensure cache directory exists."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_path(self, namespace: str, key: str) -> Path:
        """Get the cache file path for a given namespace and key."""
        safe_key = key.replace("/", "_").replace(":", "_")
        namespace_dir = self.cache_dir / namespace
        namespace_dir.mkdir(exist_ok=True)
        return namespace_dir / f"{safe_key}.json"

    def get(self, namespace: str, key: str) -> Optional[Any]:
        """Retrieve a cached value if it exists and is not expired."""
        cache_path = self._get_cache_path(namespace, key)
        if not cache_path.exists():
            return None

        try:
            with open(cache_path) as f:
                entry_data = json.load(f)
            entry = CacheEntry(
                data=entry_data["data"],
                timestamp=datetime.fromisoformat(entry_data["timestamp"]),
                ttl_hours=entry_data.get("ttl_hours", self.ttl_hours),
            )
            if entry.is_expired():
                cache_path.unlink(missing_ok=True)
                return None
            return entry.data
        except (json.JSONDecodeError, KeyError, ValueError):
            cache_path.unlink(missing_ok=True)
            return None

    def set(self, namespace: str, key: str, data: Any) -> None:
        """Store a value in the cache."""
        cache_path = self._get_cache_path(namespace, key)
        entry = CacheEntry(data=data, ttl_hours=self.ttl_hours)
        with open(cache_path, "w") as f:
            json.dump(
                {
                    "data": entry.data,
                    "timestamp": entry.timestamp.isoformat(),
                    "ttl_hours": entry.ttl_hours,
                },
                f,
            )

    def clear(self, namespace: Optional[str] = None) -> int:
        """Clear cache entries. Returns number of entries cleared."""
        count = 0
        if namespace:
            namespace_dir = self.cache_dir / namespace
            if namespace_dir.exists():
                for cache_file in namespace_dir.glob("*.json"):
                    cache_file.unlink()
                    count += 1
        else:
            for namespace_dir in self.cache_dir.iterdir():
                if namespace_dir.is_dir():
                    for cache_file in namespace_dir.glob("*.json"):
                        cache_file.unlink()
                        count += 1
        return count
