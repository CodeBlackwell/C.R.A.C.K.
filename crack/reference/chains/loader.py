"""Utilities for loading attack chain definitions from disk."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from .validator import ChainValidator


class ChainLoader:
    """Load attack chain definition files with validation."""

    def __init__(
        self,
        validator: Optional[ChainValidator] = None,
        *,
        encoding: str = "utf-8",
    ) -> None:
        self._validator = validator or ChainValidator()
        self._encoding = encoding

    def load_chain(self, filepath: Path) -> Dict[str, Any]:
        """Load and validate a single attack chain JSON document.

        Parameters
        ----------
        filepath:
            Location of the JSON document to load.

        Returns
        -------
        dict
            Parsed chain document.

        Raises
        ------
        FileNotFoundError
            If ``filepath`` does not exist.
        ValueError
            If the file cannot be decoded or fails validation.
        """

        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"Attack chain file not found: {path}")

        try:
            raw_text = path.read_text(encoding=self._encoding)
        except OSError as exc:
            raise ValueError(f"Failed to read attack chain file {path}: {exc}") from exc

        try:
            chain: Dict[str, Any] = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            message = f"Invalid JSON in attack chain file {path}: {exc.msg} (line {exc.lineno}, column {exc.colno})"
            raise ValueError(message) from exc

        schema_errors = self._validator.validate_schema(chain)
        if schema_errors:
            formatted = "\n".join(schema_errors)
            raise ValueError(f"Schema validation failed for {path}:\n{formatted}")

        circular_errors = self._validator.check_circular_dependencies(chain)
        if circular_errors:
            formatted = "\n".join(circular_errors)
            raise ValueError(f"Dependency validation failed for {path}:\n{formatted}")

        return chain

    def load_all_chains(self, roots: Iterable[Path]) -> Dict[str, Dict[str, Any]]:
        """Load every attack chain discovered beneath ``roots``.

        Parameters
        ----------
        roots:
            Iterable of directories or files to scan for attack chain
            definitions. JSON files named ``metadata.json`` are ignored as
            they describe directory contents rather than individual chains.

        Returns
        -------
        dict
            Mapping of chain IDs to their parsed definitions.

        Raises
        ------
        ValueError
            If one or more chains fail to load or duplicate IDs are
            encountered.
        """

        loaded: Dict[str, Dict[str, Any]] = {}
        errors: Dict[Path, str] = {}

        for root in roots:
            path = Path(root)
            candidates: Iterable[Path]
            if path.is_dir():
                candidates = (p for p in path.rglob("*.json") if p.name != "metadata.json")
            elif path.suffix.lower() == ".json" and path.name != "metadata.json":
                candidates = [path]
            else:
                continue

            for candidate in candidates:
                try:
                    chain = self.load_chain(candidate)
                except (FileNotFoundError, ValueError) as exc:
                    errors[Path(candidate)] = str(exc)
                    continue

                chain_id = chain.get("id")
                if not chain_id:
                    errors[Path(candidate)] = "Loaded chain is missing required 'id' field"
                    continue

                if chain_id in loaded:
                    errors[Path(candidate)] = (
                        f"Duplicate chain identifier '{chain_id}' encountered; first defined in {loaded[chain_id].get('__source__')}"
                    )
                    continue

                # Preserve origin path for debugging and duplicate detection.
                chain_with_source = dict(chain)
                chain_with_source["__source__"] = str(candidate)
                loaded[chain_id] = chain_with_source

        if errors:
            messages = [f"{path}: {message}" for path, message in sorted(errors.items())]
            raise ValueError("Failed to load one or more attack chains:\n" + "\n".join(messages))

        # Remove helper keys before returning results.
        for chain in loaded.values():
            chain.pop("__source__", None)

        return loaded
