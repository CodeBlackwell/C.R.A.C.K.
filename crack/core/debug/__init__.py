"""
CRACK Debug Logger - Shared debugging helper for all modules.

Debug logging is OFF by default. Enable via --debug flag on CLI commands.

Usage:
    # At CLI entry point (once):
    from crack.core.debug import init_debug
    init_debug(args.debug)  # Pass --debug flag value

    # In modules:
    from crack.core.debug import DebugLogger, Component, StepType

    logger = DebugLogger(component=Component.BLOODTRAIL)
    logger.info("Processing data", StepType.IMPORT, files=5)
    logger.warning("Issue found", StepType.VALIDATION, user="mike")
    logger.error("Failed", StepType.CONNECTION, error=str(e))

--debug flag options:
    --debug              Enable all debug output
    --debug all          Enable all debug output
    --debug bloodtrail   Filter to bloodtrail component
    --debug bt_neo4j,querying   Filter to specific component + step
"""

from .enums import Component, StepType, LogLevel
from .logger import DebugLogger, init_debug, is_debug_enabled, get_debug_filters
from .compat import LogCategory, LegacyLogLevel, LegacyDebugLogger

__all__ = [
    # Core classes
    "DebugLogger",
    "Component",
    "StepType",
    "LogLevel",
    # Initialization
    "init_debug",
    "is_debug_enabled",
    "get_debug_filters",
    # Backward compatibility
    "LogCategory",
    "LegacyLogLevel",
    "LegacyDebugLogger",
]
