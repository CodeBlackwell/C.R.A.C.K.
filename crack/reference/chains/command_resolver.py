"""Utilities for resolving command references used by attack chains."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - imported for type checking only
    from crack.reference.core.registry import Command, HybridCommandRegistry


class CommandResolver:
    """Resolve command references against the reference command registry."""

    def __init__(
        self,
        registry: Optional["HybridCommandRegistry"] = None,
        *,
        commands: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Initialise the resolver with an optional registry or command mapping.

        Parameters
        ----------
        registry:
            Instance of :class:`~crack.reference.core.registry.HybridCommandRegistry`
            to source command definitions from. If omitted, the resolver will
            lazily instantiate a registry when first required unless an explicit
            ``commands`` mapping is provided.
        commands:
            Explicit mapping of command identifiers to command objects. When
            supplied, the resolver will rely on this mapping and will not create
            a registry automatically.
        """

        self._registry: Optional["HybridCommandRegistry"] = registry
        self._explicit_commands = commands is not None
        if commands is not None:
            # Make a shallow copy to avoid external mutations impacting lookups.
            self._commands: Dict[str, Any] = dict(commands)
        elif registry is not None:
            # ``HybridCommandRegistry.commands`` behaves like a mapping and is
            # populated during initialisation, so we can reference it directly.
            self._commands = registry.commands  # type: ignore[assignment]
        else:
            self._commands = {}

        # Cache lookup results so repeated resolutions remain inexpensive.
        self._cache: Dict[str, Optional[Any]] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _ensure_registry(self) -> None:
        """Instantiate a command registry if none is currently available."""

        if self._registry is None:
            from crack.reference.core.registry import HybridCommandRegistry

            self._registry = HybridCommandRegistry()
            self._commands = self._registry.commands  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def resolve_command_ref(self, ref_id: str) -> Optional[Any]:
        """Return the command associated with ``ref_id`` if it exists."""

        if not ref_id:
            return None

        if ref_id in self._cache:
            return self._cache[ref_id]

        if ref_id in self._commands:
            command = self._commands[ref_id]
            self._cache[ref_id] = command
            return command

        if self._registry is None and not self._commands and not self._explicit_commands:
            self._ensure_registry()

        if self._registry is not None:
            command = self._registry.get_command(ref_id)
            self._cache[ref_id] = command
            if command is not None and ref_id not in self._commands:
                self._commands[ref_id] = command
            return command

        self._cache[ref_id] = None
        return None

    def extract_command_refs(self, chain: Mapping[str, Any]) -> List[str]:
        """Return all ``command_ref`` values declared within ``chain``."""

        steps = chain.get("steps", []) or []
        references: List[str] = []
        for step in steps:
            if not isinstance(step, Mapping):
                continue
            command_ref = step.get("command_ref")
            if isinstance(command_ref, str) and command_ref:
                references.append(command_ref)
        return references

    def validate_references(self, references: Iterable[str]) -> Dict[str, str]:
        """Validate that each ``references`` entry resolves to a known command."""

        missing: Dict[str, str] = {}
        seen: Set[str] = set()
        for ref_id in references:
            if not ref_id or ref_id in seen:
                continue
            seen.add(ref_id)
            if self.resolve_command_ref(ref_id) is None:
                missing[ref_id] = f"Command reference '{ref_id}' could not be resolved"
        return missing

