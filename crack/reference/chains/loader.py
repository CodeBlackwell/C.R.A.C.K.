"""Loader stubs for attack chain definitions.

The concrete implementation will arrive in Phase 3 of the checklist. For
now, the class exists so import paths are stable and documentation can
reference the upcoming API.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable


class ChainLoader:
    """Placeholder loader for attack chain definition files."""

    def load_chain(self, filepath: Path) -> Dict[str, Any]:
        """Load a single attack chain from ``filepath``.

        Phase 2 only defines the interface. The method will be implemented
        during Phase 3.
        """

        raise NotImplementedError("Phase 3 implements load_chain")

    def load_all_chains(self, roots: Iterable[Path]) -> Dict[str, Dict[str, Any]]:
        """Load all attack chains found beneath the provided ``roots``.

        The aggregation and validation logic will be delivered in Phase 3.
        """

        raise NotImplementedError("Phase 3 implements load_all_chains")
