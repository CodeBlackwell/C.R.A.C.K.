"""High-level data model representing an attack chain."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .chain_metadata import ChainMetadata
from .chain_step import ChainStep

_CHAIN_ID_PATTERN = re.compile(r"^[a-z0-9]+-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+$")
_SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")
_TIME_ESTIMATE_PATTERN = re.compile(r"^\d+\s*(?:minutes?|hours?|days?)$", re.IGNORECASE)
_ALLOWED_DIFFICULTIES = {"beginner", "intermediate", "advanced", "expert"}


@dataclass(frozen=True)
class AttackChain:
    """Rich representation of an attack chain and its relationships."""

    id: str
    name: str
    description: str
    version: str
    metadata: ChainMetadata
    difficulty: str
    time_estimate: str
    oscp_relevant: bool
    steps: Tuple[ChainStep, ...]
    prerequisites: Tuple[str, ...] = field(default_factory=tuple)
    notes: Optional[str] = None

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------
    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | Sequence[Tuple[str, Any]]) -> "AttackChain":
        mapping: Dict[str, Any] = dict(data)
        metadata_raw = mapping.get("metadata")
        steps_raw = mapping.get("steps", [])
        if not isinstance(metadata_raw, Mapping):
            raise ValueError("metadata must be provided as a mapping")
        if not isinstance(steps_raw, Iterable):
            raise ValueError("steps must be provided as an iterable")

        metadata = ChainMetadata.from_dict(metadata_raw)
        steps = tuple(ChainStep.from_dict(step) for step in steps_raw)
        prerequisites = cls._coerce_iterable(mapping.get("prerequisites"))

        chain = cls(
            id=str(mapping.get("id", "")).strip(),
            name=str(mapping.get("name", "")).strip(),
            description=str(mapping.get("description", "")).strip(),
            version=str(mapping.get("version", "")).strip(),
            metadata=metadata,
            difficulty=str(mapping.get("difficulty", "")).strip(),
            time_estimate=str(mapping.get("time_estimate", "")).strip(),
            oscp_relevant=bool(mapping.get("oscp_relevant", False)),
            steps=steps,
            prerequisites=prerequisites,
            notes=(str(mapping["notes"]).strip() if mapping.get("notes") else None),
        )

        errors = chain.validate()
        if errors:
            raise ValueError("Invalid attack chain:\n" + "\n".join(errors))
        return chain

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "metadata": self.metadata.to_dict(),
            "difficulty": self.difficulty,
            "time_estimate": self.time_estimate,
            "oscp_relevant": self.oscp_relevant,
            "steps": [step.to_dict() for step in self.steps],
        }
        if self.prerequisites:
            payload["prerequisites"] = list(self.prerequisites)
        if self.notes:
            payload["notes"] = self.notes
        return payload

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------
    def validate(self) -> List[str]:
        errors: List[str] = []
        if not self.id:
            errors.append("id must be provided")
        elif not _CHAIN_ID_PATTERN.fullmatch(self.id):
            errors.append(f"id '{self.id}' must match pattern {_CHAIN_ID_PATTERN.pattern}")
        if not self.name:
            errors.append("name must be provided")
        if not self.description:
            errors.append("description must be provided")
        if not self.version:
            errors.append("version must be provided")
        elif not _SEMVER_PATTERN.fullmatch(self.version):
            errors.append(
                f"version '{self.version}' must follow semantic versioning (major.minor.patch)"
            )
        if self.difficulty.lower() not in _ALLOWED_DIFFICULTIES:
            errors.append(
                "difficulty must be one of 'beginner', 'intermediate', 'advanced', or 'expert'"
            )
        if not self.time_estimate:
            errors.append("time_estimate must be provided")
        elif not _TIME_ESTIMATE_PATTERN.fullmatch(self.time_estimate):
            errors.append(
                "time_estimate must match '<number> <unit>' where unit is minutes, hours, or days"
            )
        if not isinstance(self.oscp_relevant, bool):
            errors.append("oscp_relevant must be a boolean value")
        if not self.steps:
            errors.append("at least one step must be defined")

        # Validate metadata and steps individually.
        errors.extend(f"metadata.{err}" for err in self.metadata.validate())
        step_ids: Dict[str, int] = {}
        for index, step in enumerate(self.steps):
            step_errors = step.validate()
            errors.extend(f"steps[{index}].{err}" for err in step_errors)
            if step.id:
                if step.id in step_ids:
                    errors.append(f"duplicate step id '{step.id}' encountered")
                else:
                    step_ids[step.id] = index

        # Dependency checks ensure referential integrity.
        valid_step_ids = set(step_ids)
        for index, step in enumerate(self.steps):
            for dependency in step.dependencies:
                if dependency not in valid_step_ids:
                    errors.append(
                        f"steps[{index}].dependencies references unknown step '{dependency}'"
                    )
            for next_step in step.next_steps:
                if next_step not in valid_step_ids:
                    errors.append(
                        f"steps[{index}].next_steps references unknown step '{next_step}'"
                    )

        for prereq in self.prerequisites:
            if not prereq:
                errors.append("prerequisites cannot contain empty strings")

        return errors

    @staticmethod
    def _coerce_iterable(value: Optional[Iterable[Any]]) -> Tuple[str, ...]:
        if not value:
            return tuple()
        if isinstance(value, str):
            return (value.strip(),) if value.strip() else tuple()
        return tuple(str(item).strip() for item in value if str(item).strip())
