"""Data model representing a single step within an attack chain."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
import re

_STEP_ID_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


@dataclass(frozen=True)
class ChainStep:
    """Immutable representation of a chain step."""

    name: str
    objective: str
    command_ref: str
    id: Optional[str] = None
    description: Optional[str] = None
    evidence: Tuple[str, ...] = field(default_factory=tuple)
    dependencies: Tuple[str, ...] = field(default_factory=tuple)
    repeatable: Optional[bool] = None
    success_criteria: Tuple[str, ...] = field(default_factory=tuple)
    failure_conditions: Tuple[str, ...] = field(default_factory=tuple)
    next_steps: Tuple[str, ...] = field(default_factory=tuple)

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------
    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | Sequence[Tuple[str, Any]]) -> "ChainStep":
        mapping: Dict[str, Any] = dict(data)
        evidence = cls._coerce_iterable(mapping.get("evidence"))
        dependencies = cls._coerce_iterable(mapping.get("dependencies"))
        success = cls._coerce_iterable(mapping.get("success_criteria"))
        failure = cls._coerce_iterable(mapping.get("failure_conditions"))
        next_steps = cls._coerce_iterable(mapping.get("next_steps"))

        step = cls(
            name=str(mapping.get("name", "")).strip(),
            objective=str(mapping.get("objective", "")).strip(),
            command_ref=str(mapping.get("command_ref", "")).strip(),
            id=(str(mapping["id"]).strip() if mapping.get("id") else None),
            description=(str(mapping["description"]).strip() if mapping.get("description") else None),
            evidence=evidence,
            dependencies=dependencies,
            repeatable=bool(mapping["repeatable"]) if "repeatable" in mapping else None,
            success_criteria=success,
            failure_conditions=failure,
            next_steps=next_steps,
        )

        errors = step.validate()
        if errors:
            raise ValueError("Invalid chain step:\n" + "\n".join(errors))
        return step

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "name": self.name,
            "objective": self.objective,
            "command_ref": self.command_ref,
        }
        if self.id:
            payload["id"] = self.id
        if self.description:
            payload["description"] = self.description
        if self.evidence:
            payload["evidence"] = list(self.evidence)
        if self.dependencies:
            payload["dependencies"] = list(self.dependencies)
        if self.repeatable is not None:
            payload["repeatable"] = self.repeatable
        if self.success_criteria:
            payload["success_criteria"] = list(self.success_criteria)
        if self.failure_conditions:
            payload["failure_conditions"] = list(self.failure_conditions)
        if self.next_steps:
            payload["next_steps"] = list(self.next_steps)
        return payload

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------
    def validate(self) -> List[str]:
        errors: List[str] = []
        if not self.name:
            errors.append("name must be provided")
        if not self.objective:
            errors.append("objective must be provided")
        if not self.command_ref:
            errors.append("command_ref must be provided")
        if self.id and not _STEP_ID_PATTERN.fullmatch(self.id):
            errors.append(f"id '{self.id}' must match pattern {_STEP_ID_PATTERN.pattern}")
        if not _STEP_ID_PATTERN.fullmatch(self.command_ref):
            errors.append(
                f"command_ref '{self.command_ref}' must match pattern {_STEP_ID_PATTERN.pattern}"
            )
        for dependency in self.dependencies:
            if not _STEP_ID_PATTERN.fullmatch(dependency):
                errors.append(
                    f"dependency '{dependency}' must match pattern {_STEP_ID_PATTERN.pattern}"
                )
        for next_step in self.next_steps:
            if not _STEP_ID_PATTERN.fullmatch(next_step):
                errors.append(
                    f"next_steps entry '{next_step}' must match pattern {_STEP_ID_PATTERN.pattern}"
                )
        return errors

    @staticmethod
    def _coerce_iterable(value: Optional[Iterable[Any]]) -> Tuple[str, ...]:
        if not value:
            return tuple()
        if isinstance(value, str):
            return (value.strip(),) if value.strip() else tuple()
        items = [str(item).strip() for item in value]
        return tuple(item for item in items if item)
