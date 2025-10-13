"""Data model for attack chain metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlparse

_DATE_FORMAT = "%Y-%m-%d"


def _to_date(value: str, *, field_name: str) -> date:
    """Parse ``value`` into a :class:`datetime.date` instance."""

    try:
        return datetime.strptime(value, _DATE_FORMAT).date()
    except (TypeError, ValueError) as exc:  # pragma: no cover - defensive guard
        raise ValueError(f"{field_name} must be a date in {_DATE_FORMAT} format") from exc


@dataclass(frozen=True)
class ChainMetadata:
    """Authoring and classification metadata for an attack chain."""

    author: str
    created: date
    updated: date
    tags: Tuple[str, ...]
    category: str
    platform: Optional[str] = None
    references: Tuple[str, ...] = field(default_factory=tuple)

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------
    @classmethod
    def from_dict(
        cls, data: Mapping[str, Any] | Sequence[Tuple[str, Any]]
    ) -> "ChainMetadata":
        """Construct an instance from a mapping representation."""

        mapping = dict(data)
        author = str(mapping.get("author", ""))
        created_raw = mapping.get("created")
        updated_raw = mapping.get("updated")
        if not isinstance(created_raw, str):
            raise ValueError("created must be provided as a string")
        if not isinstance(updated_raw, str):
            raise ValueError("updated must be provided as a string")

        tags_value = mapping.get("tags", [])
        if not isinstance(tags_value, Iterable):
            raise ValueError("tags must be an iterable of strings")
        tags = tuple(str(tag).strip() for tag in tags_value if str(tag).strip())

        references_value = mapping.get("references", [])
        if references_value is None:
            references: Tuple[str, ...] = tuple()
        else:
            if not isinstance(references_value, Iterable):
                raise ValueError("references must be an iterable of strings")
            references = tuple(str(ref).strip() for ref in references_value if str(ref).strip())

        metadata = cls(
            author=author.strip(),
            created=_to_date(created_raw, field_name="created"),
            updated=_to_date(updated_raw, field_name="updated"),
            tags=tags,
            category=str(mapping.get("category", "")).strip(),
            platform=(str(mapping["platform"]).strip() if mapping.get("platform") else None),
            references=references,
        )

        errors = metadata.validate()
        if errors:
            raise ValueError("Invalid chain metadata:\n" + "\n".join(errors))
        return metadata

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        """Serialise the metadata into a JSON-compatible dictionary."""

        payload = {
            "author": self.author,
            "created": self.created.strftime(_DATE_FORMAT),
            "updated": self.updated.strftime(_DATE_FORMAT),
            "tags": list(self.tags),
            "category": self.category,
        }
        if self.platform:
            payload["platform"] = self.platform
        if self.references:
            payload["references"] = list(self.references)
        return payload

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------
    def validate(self) -> List[str]:
        """Return a list of validation error messages."""

        errors: List[str] = []
        if not self.author:
            errors.append("author must be provided")
        if not self.category:
            errors.append("category must be provided")
        if not self.tags:
            errors.append("tags must contain at least one entry")
        if self.created > self.updated:
            errors.append("created date cannot be later than updated date")
        for reference in self.references:
            parsed = urlparse(reference)
            if not (parsed.scheme and parsed.netloc):
                errors.append(f"invalid reference URL: {reference}")
        return errors
