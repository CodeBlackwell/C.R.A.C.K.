"""
CRACK Unified Data Persistence Layer.

Provides centralized storage for all pentest data:
- RawInput: Every command execution with stdout/stderr
- Finding: Extracted information with provenance to source
- Credential: Discovered credentials with validation status

Storage:
- SQLite: Raw blobs (stdout/stderr, file contents)
- Neo4j: Relationships and queryable metadata

Usage:
    from crack.tools.persistence import captured_run, PersistenceConfig

    # Execute command with automatic persistence
    result = captured_run(
        ["nmap", "-sV", target],
        source_tool="bloodtrail",
        target_ip=target,
    )

    # Access raw_input for provenance
    raw_input_id = result.raw_input.id

    # Disable persistence (--no-prism mode)
    PersistenceConfig.disable()
"""

from .config import PersistenceConfig
from .models.raw_input import RawInput, FileInput
from .models.finding import UnifiedFinding, FindingType, FindingPriority
from .capture.subprocess_wrapper import captured_run, CapturedResult, CapturedRunner
from .storage.dual_store import DualStore, get_store, reset_store

__all__ = [
    # Config
    "PersistenceConfig",
    # Models
    "RawInput",
    "FileInput",
    "UnifiedFinding",
    "FindingType",
    "FindingPriority",
    # Capture
    "captured_run",
    "CapturedResult",
    "CapturedRunner",
    # Storage
    "DualStore",
    "get_store",
    "reset_store",
]
