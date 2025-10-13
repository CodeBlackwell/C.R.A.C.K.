"""Validation utilities for attack chain definitions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from jsonschema import Draft202012Validator


class ChainValidator:
    """Validate the structure and relationships within attack chains."""

    def __init__(self, schema_path: Optional[Path] = None) -> None:
        if schema_path is None:
            schema_path = Path(__file__).parent.parent / "schemas" / "attack_chain.schema.json"
        self._schema = self._load_schema(schema_path)
        self._validator = Draft202012Validator(self._schema) if self._schema else None

    @staticmethod
    def _load_schema(schema_path: Path) -> Dict[str, Any]:
        if not schema_path.is_file():
            raise FileNotFoundError(f"Attack chain schema not found at {schema_path}")
        try:
            return json.loads(schema_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            message = f"Invalid JSON in attack chain schema {schema_path}: {exc.msg}"
            raise ValueError(message) from exc

    def validate_schema(self, chain: Dict[str, Any]) -> List[str]:
        """Validate a parsed chain against the JSON schema.

        Returns a list of human-friendly error messages. The list will be
        empty if the chain conforms to the schema.
        """

        if self._validator is None:
            return ["Schema validator unavailable; schema file failed to load"]

        errors: List[str] = []
        for error in sorted(self._validator.iter_errors(chain), key=lambda e: e.path):
            location = "/".join(str(segment) for segment in error.path) or "<root>"
            context = f" (validator: {error.validator})" if error.validator else ""
            errors.append(f"{location}: {error.message}{context}")
        return errors

    def validate_command_refs(self, chain: Dict[str, Any], known_commands: Iterable[str]) -> List[str]:
        """Ensure each command reference exists in ``known_commands``."""

        known = set(known_commands)
        errors: List[str] = []
        for index, step in enumerate(chain.get("steps", [])):
            command_ref = step.get("command_ref")
            if not command_ref:
                errors.append(f"steps/{index}: missing required command_ref")
                continue
            if command_ref not in known:
                label = step.get("id") or step.get("name") or f"index {index}"
                errors.append(
                    f"steps/{index}: command_ref '{command_ref}' referenced by step '{label}' not found in known commands"
                )
        return errors

    def check_circular_dependencies(self, chain: Dict[str, Any]) -> List[str]:
        """Detect circular step dependencies and report issues."""

        steps = chain.get("steps", []) or []
        id_to_dependencies: Dict[str, List[str]] = {}
        defined_ids: Set[str] = set()

        for index, step in enumerate(steps):
            step_id = step.get("id")
            if step_id:
                defined_ids.add(step_id)
            deps = [dep for dep in step.get("dependencies", []) or []]
            if step_id:
                id_to_dependencies[step_id] = deps
            elif deps:
                # Steps without IDs cannot be dependencies for others; flag usage for clarity.
                id_to_dependencies[f"<index:{index}>"] = deps

        errors: List[str] = []

        # Detect references to unknown steps.
        for step_id, deps in id_to_dependencies.items():
            for dependency in deps:
                if dependency not in defined_ids:
                    errors.append(
                        f"step '{step_id}' depends on undefined step '{dependency}'"
                    )

        # Perform cycle detection using depth-first search.
        visiting: Set[str] = set()
        visited: Set[str] = set()

        def visit(node: str, path: List[str]) -> None:
            if node in visited or node.startswith("<index:"):
                return
            if node in visiting:
                cycle_path = " -> ".join(path + [node])
                errors.append(f"Circular dependency detected: {cycle_path}")
                return

            visiting.add(node)
            path.append(node)
            for dep in id_to_dependencies.get(node, []):
                visit(dep, path)
            path.pop()
            visiting.remove(node)
            visited.add(node)

        for node in list(id_to_dependencies.keys()):
            visit(node, [])

        return errors
