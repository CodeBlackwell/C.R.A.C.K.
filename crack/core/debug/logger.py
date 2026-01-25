"""
DebugLogger - Shared debugging helper for CRACK toolkit.

Features:
- OFF by default, activated via --debug flag
- Dual output: JSON lines to file, colored plaintext to console
- Filtering via --debug flag: --debug, --debug=bloodtrail, --debug=bt_neo4j,querying
- Component and step type filtering

Usage:
    from crack.core.debug import DebugLogger, Component, StepType, LogLevel, init_debug

    # Initialize from CLI --debug flag (call once at CLI entry)
    init_debug("bloodtrail,querying")  # or None for all, or "" for disabled

    # Create logger for your component
    logger = DebugLogger(component=Component.BLOODTRAIL)

    # Log with context
    logger.info("Processing data", StepType.IMPORT, files=5)
    logger.warning("Stale credential", StepType.VALIDATION, user="mike@corp.com")
"""

import sys
from pathlib import Path
from datetime import datetime
from typing import Optional, Set, Any, IO

from .enums import Component, StepType, LogLevel
from .formatters import ConsoleFormatter, JsonFormatter
from .rotation import LogRotation


class _DebugState:
    """Global debug state - controlled by --debug flag."""

    def __init__(self):
        self.enabled: bool = False
        self.min_level: LogLevel = LogLevel.VERBOSE
        self.allowed_components: Optional[Set[str]] = None  # None = all
        self.allowed_steps: Optional[Set[str]] = None  # None = all
        self.console_output: bool = True  # Console ON when debug enabled
        self.file_output: bool = True     # File ON when debug enabled
        self.log_dir: Path = Path.home() / ".crack" / "logs"
        self._log_file: Optional[IO] = None
        self._current_log_date: Optional[str] = None
        self._rotation: Optional[LogRotation] = None

    def configure(self, debug_filter: Optional[str] = None):
        """
        Configure debug state from --debug flag value.

        Args:
            debug_filter: Filter string from --debug flag
                - None or "": Debug disabled
                - "all" or just --debug with no value: Enable all
                - "bloodtrail": Filter to bloodtrail component
                - "bloodtrail,bt_neo4j": Multiple components
                - "querying,connection": Step types
                - "bloodtrail,querying": Mix of components and steps
        """
        if debug_filter is None or debug_filter == "":
            self.enabled = False
            return

        self.enabled = True

        # Parse filter
        if debug_filter.lower() == "all":
            self.allowed_components = None
            self.allowed_steps = None
            return

        # Build component and step filters
        components = set()
        steps = set()

        # Get valid values
        valid_components = {c.value.lower() for c in Component}
        valid_steps = {s.value.lower() for s in StepType}

        for item in debug_filter.split(","):
            item = item.strip().lower()
            if not item:
                continue

            if item in valid_components:
                components.add(item)
            elif item in valid_steps:
                steps.add(item)
            else:
                # Try to match partial (e.g., "neo4j" matches "bt_neo4j")
                for comp in valid_components:
                    if item in comp:
                        components.add(comp)
                        break

        self.allowed_components = components if components else None
        self.allowed_steps = steps if steps else None

    def should_log(self, component: Component, step: StepType, level: LogLevel) -> bool:
        """Check if this log entry should be recorded."""
        if not self.enabled:
            return False

        if level.value < self.min_level.value:
            return False

        # Component filter
        if self.allowed_components is not None:
            if component.value.lower() not in self.allowed_components:
                return False

        # Step filter
        if self.allowed_steps is not None:
            if step.value.lower() not in self.allowed_steps:
                return False

        return True

    def get_log_file(self) -> Optional[IO]:
        """Get current log file handle, rotating if needed."""
        if not self.file_output or not self.enabled:
            return None

        today = datetime.now().strftime("%Y-%m-%d")

        if self._current_log_date != today:
            if self._log_file:
                self._log_file.close()

            self.log_dir.mkdir(parents=True, exist_ok=True)
            log_path = self.log_dir / f"crack-{today}.jsonl"
            self._log_file = open(log_path, "a")
            self._current_log_date = today

            # Run cleanup
            if self._rotation is None:
                self._rotation = LogRotation(self.log_dir)
            self._rotation.cleanup_old_logs()

        return self._log_file

    def close(self):
        """Close log file."""
        if self._log_file:
            self._log_file.close()
            self._log_file = None


# Global state
_state = _DebugState()


def init_debug(debug_filter: Optional[str] = None):
    """
    Initialize debug logging from --debug flag.

    Call this once at CLI entry point.

    Args:
        debug_filter: Value from --debug flag
            - None: Debug disabled (default)
            - "": Debug disabled
            - "all": Enable all debug output
            - "bloodtrail": Filter to component
            - "bloodtrail,querying": Multiple filters
    """
    _state.configure(debug_filter)


def is_debug_enabled() -> bool:
    """Check if debug logging is enabled."""
    return _state.enabled


def get_debug_filters() -> tuple:
    """Get current debug filters (for display)."""
    return (_state.allowed_components, _state.allowed_steps)


class DebugLogger:
    """
    Debug logger for CRACK toolkit modules.

    Only logs when debug is enabled via init_debug().
    """

    def __init__(self, component: Component):
        """
        Initialize debug logger.

        Args:
            component: Primary component this logger represents
        """
        self.component = component
        self._console_formatter = ConsoleFormatter()
        self._json_formatter = JsonFormatter()

    def log(
        self,
        message: str,
        step: StepType = StepType.PROCESSING,
        level: LogLevel = LogLevel.NORMAL,
        component: Optional[Component] = None,
        **context
    ):
        """
        Log a message with context.

        Args:
            message: Human-readable message
            step: Step type for filtering
            level: Log severity level
            component: Override component (default: self.component)
            **context: Additional key-value context data
        """
        comp = component or self.component

        if not _state.should_log(comp, step, level):
            return

        timestamp = datetime.now().isoformat()

        entry = {
            "timestamp": timestamp,
            "component": comp.value,
            "step": step.value,
            "level": level.name.lower(),
            "message": message,
            **context
        }

        # Console output
        if _state.console_output:
            formatted = self._console_formatter.format(entry)
            print(formatted, file=sys.stderr)

        # File output
        log_file = _state.get_log_file()
        if log_file:
            json_line = self._json_formatter.format(entry)
            log_file.write(json_line + "\n")
            log_file.flush()

    def verbose(self, message: str, step: StepType = StepType.PROCESSING, **context):
        """Log verbose message."""
        self.log(message, step, LogLevel.VERBOSE, **context)

    def info(self, message: str, step: StepType = StepType.PROCESSING, **context):
        """Log normal/info message."""
        self.log(message, step, LogLevel.NORMAL, **context)

    def warning(self, message: str, step: StepType = StepType.PROCESSING, **context):
        """Log warning message."""
        self.log(message, step, LogLevel.WARNING, **context)

    def error(self, message: str, step: StepType = StepType.PROCESSING, **context):
        """Log error message."""
        self.log(message, step, LogLevel.ERROR, **context)
