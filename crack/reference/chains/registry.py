"""Registry stubs for attack chain definitions.

The registry will provide caching and lookup utilities in later phases.
The current implementation keeps the API stable for downstream imports
while signalling that additional work is pending.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional


class ChainRegistry:
    """Placeholder registry for loaded attack chain documents."""

    def __init__(self) -> None:
        self._chains: Dict[str, Dict[str, Any]] = {}

    def register_chain(self, chain_id: str, chain: Dict[str, Any]) -> None:
        """Register a chain under ``chain_id``.

        Duplicate handling and validation will be implemented in Phase 3.
        """

        raise NotImplementedError("Phase 3 implements register_chain")

    def get_chain(self, chain_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a chain if it has been registered."""

        raise NotImplementedError("Phase 3 implements get_chain")

    def filter_chains(self, **criteria: Any) -> Iterable[Dict[str, Any]]:
        """Yield chains that match the supplied ``criteria``.

        Filtering logic will be provided in Phase 3.
        """

        raise NotImplementedError("Phase 3 implements filter_chains")
