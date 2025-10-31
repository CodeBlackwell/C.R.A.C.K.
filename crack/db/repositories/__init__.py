"""
CRACK Database Repositories

Data access layer for SQL database operations.
Provides clean API for querying commands, services, chains, and sessions.

Repository Pattern Benefits:
- Abstracts SQL queries from business logic
- Enables easy mocking for tests
- Centralizes database access
- Consistent error handling
"""

from .command_repository import CommandRepository
from .service_repository import ServiceRepository
from .attack_chain_repository import AttackChainRepository
from .session_repository import SessionRepository
from .finding_repository import FindingRepository
from .plugin_repository import PluginRepository

__all__ = [
    'CommandRepository',
    'ServiceRepository',
    'AttackChainRepository',
    'SessionRepository',
    'FindingRepository',
    'PluginRepository'
]
