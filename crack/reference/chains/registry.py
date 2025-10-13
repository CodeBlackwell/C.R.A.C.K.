"""In-memory registry for attack chain definitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Tuple


@dataclass(frozen=True)
class _CacheKey:
    """Immutable cache key derived from filter criteria."""

    items: Tuple[Tuple[str, Any], ...]

    @classmethod
    def from_kwargs(cls, **criteria: Any) -> "_CacheKey":
        return cls(tuple(sorted(criteria.items())))


class ChainRegistry:
    """Registry that stores chains and provides lookup helpers."""

    _instance: Optional["ChainRegistry"] = None

    def __new__(cls, *args: Any, **kwargs: Any) -> "ChainRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        # Only skip if both flag AND dicts exist (prevents empty registry bug)
        if hasattr(self, "_initialised") and self._initialised:
            if hasattr(self, "_chains") and hasattr(self, "_filter_cache"):
                return  # Already initialized with data structures

        # Initialize (or re-initialize if missing)
        self._chains: Dict[str, Dict[str, Any]] = {}
        self._filter_cache: Dict[_CacheKey, Tuple[str, ...]] = {}
        self._initialised = True

    def register_chain(self, chain_id: str, chain: Dict[str, Any]) -> None:
        """Register ``chain`` using ``chain_id``.

        Raises
        ------
        ValueError
            If ``chain_id`` is empty or already registered.
        """

        if not chain_id:
            raise ValueError("Chain identifier must be a non-empty string")
        if chain_id in self._chains:
            raise ValueError(f"Chain '{chain_id}' is already registered")

        # Defensive copy ensures registry data cannot be mutated externally.
        self._chains[chain_id] = dict(chain)
        self._filter_cache.clear()

    def get_chain(self, chain_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a registered chain by ``chain_id``."""

        chain = self._chains.get(chain_id)
        return dict(chain) if chain is not None else None

    def filter_chains(self, **criteria: Any) -> Iterable[Dict[str, Any]]:
        """Yield chains that match the supplied ``criteria``.

        Criteria keys may reference top-level fields (e.g. ``difficulty``) or
        metadata fields using dotted paths such as ``metadata.category``.
        """

        if not criteria:
            for chain in self._chains.values():
                yield dict(chain)
            return

        cache_key = _CacheKey.from_kwargs(**criteria)
        cached = self._filter_cache.get(cache_key)
        if cached is not None:
            for chain_id in cached:
                yield dict(self._chains[chain_id])
            return

        matched_ids = []
        for chain_id, chain in self._chains.items():
            if self._matches(chain, criteria):
                matched_ids.append(chain_id)
                yield dict(chain)

        self._filter_cache[cache_key] = tuple(matched_ids)

    @staticmethod
    def _matches(chain: Dict[str, Any], criteria: Dict[str, Any]) -> bool:
        for key, expected in criteria.items():
            value = ChainRegistry._resolve_field(chain, key)
            if isinstance(expected, (list, tuple, set)):
                if value not in expected:
                    return False
            else:
                if value != expected:
                    return False
        return True

    @staticmethod
    def _resolve_field(chain: Dict[str, Any], dotted_key: str) -> Any:
        value: Any = chain
        for part in dotted_key.split("."):
            if not isinstance(value, dict) or part not in value:
                return None
            value = value[part]
        return value
