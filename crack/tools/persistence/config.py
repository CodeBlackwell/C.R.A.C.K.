"""
Configuration for the persistence layer.

Supports --no-prism flag for standalone tool usage.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class PersistenceConfig:
    """
    Central configuration for the persistence layer.

    Respects --no-prism flag for standalone tool usage where
    no SQLite/Neo4j writes should occur.
    """
    # Paths
    sqlite_path: str = field(
        default_factory=lambda: os.path.expanduser("~/.crack/persistence.db")
    )
    raw_output_dir: str = field(
        default_factory=lambda: os.path.expanduser("~/.crack/raw_outputs")
    )

    # Neo4j settings (inherited from db/config.py pattern)
    neo4j_uri: str = field(
        default_factory=lambda: os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    )
    neo4j_user: str = field(
        default_factory=lambda: os.environ.get("NEO4J_USER", "neo4j")
    )
    neo4j_password: str = field(
        default_factory=lambda: os.environ.get("NEO4J_PASSWORD", "")
    )

    # Feature flags
    neo4j_enabled: bool = True
    store_raw_in_files: bool = False  # If True, store large blobs as files

    # Blob size threshold (store in file if larger)
    max_inline_blob_size: int = 1_000_000  # 1MB

    # Class-level runtime state
    _runtime_disabled: bool = False
    _instance: Optional["PersistenceConfig"] = None

    @classmethod
    def get(cls) -> "PersistenceConfig":
        """Get singleton config instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def is_enabled(cls) -> bool:
        """
        Check if persistence is enabled.

        Returns False if:
        - --no-prism flag was passed (calls disable())
        - CRACK_NO_PRISM environment variable is set
        """
        if os.environ.get("CRACK_NO_PRISM", "").lower() in ("1", "true", "yes"):
            return False
        return not cls._runtime_disabled

    @classmethod
    def disable(cls):
        """
        Disable persistence at runtime.

        Called by --no-prism flag handler.
        """
        cls._runtime_disabled = True

    @classmethod
    def enable(cls):
        """Re-enable persistence."""
        cls._runtime_disabled = False

    @classmethod
    def reset(cls):
        """Reset to defaults (for testing)."""
        cls._runtime_disabled = False
        cls._instance = None

    def ensure_directories(self):
        """Create necessary directories if they don't exist."""
        Path(self.sqlite_path).parent.mkdir(parents=True, exist_ok=True)
        if self.store_raw_in_files:
            Path(self.raw_output_dir).mkdir(parents=True, exist_ok=True)

    def get_raw_output_path(self, raw_input_id: str, stream: str = "stdout") -> Path:
        """
        Get path for storing raw output as file.

        Args:
            raw_input_id: UUID of the RawInput
            stream: 'stdout' or 'stderr'

        Returns:
            Path to the output file
        """
        return Path(self.raw_output_dir) / f"{raw_input_id}_{stream}.bin"
