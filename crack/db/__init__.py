"""
CRACK Database Module

SQLite-based storage for commands, services, attack chains, and target sessions.
Replaces JSON-based storage with normalized relational schema.

Key Components:
- schema.sql: 17-table normalized schema
- repositories/: Data access layer (CommandRepository, ServiceRepository, etc.)
- migrations/: Schema version migrations
- migrate.py: JSON → SQL migration script

Integration Points:
- reference/core/registry.py → db/repositories/command_repository.py
- track/services/ → db/repositories/service_repository.py
- track/core/state.py → db/repositories/session_repository.py
- reference/chains/ → db/repositories/attack_chain_repository.py

Database Location: ~/.crack/crack.db (SQLite)
"""

__version__ = '1.0.0'

__all__ = [
    'CommandRepository',
    'ServiceRepository',
    'AttackChainRepository',
    'SessionRepository',
    'FindingRepository',
    'CRACKMigration'
]
