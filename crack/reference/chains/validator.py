"""Validation stubs for attack chain definitions.

Real validation logic, including schema enforcement and command
cross-referencing, is scheduled for Phase 3. This scaffold allows other
modules to import the validator without circular dependencies once
functionality is added.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List


class ChainValidator:
    """Placeholder validator that will check attack chain structures."""

    def validate_schema(self, chain: Dict[str, Any]) -> List[str]:
        """Validate a parsed chain against the JSON schema."""

        raise NotImplementedError("Phase 3 implements validate_schema")

    def validate_command_refs(self, chain: Dict[str, Any], known_commands: Iterable[str]) -> List[str]:
        """Ensure each command reference exists in ``known_commands``."""

        raise NotImplementedError("Phase 3 implements validate_command_refs")

    def check_circular_dependencies(self, chain: Dict[str, Any]) -> List[str]:
        """Detect circular references once relationships are modeled."""

        raise NotImplementedError("Phase 3 implements check_circular_dependencies")
