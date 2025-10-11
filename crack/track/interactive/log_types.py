"""
Log Types - Category and Level definitions for precision debug logging

Provides hierarchical log categories and verbosity levels for granular control
over debug logging in TUI, GUI, and CLI development.
"""

from enum import Enum, auto
from typing import Set, Optional


class LogLevel(Enum):
    """Verbosity levels for debug logging"""
    MINIMAL = 1   # Only critical information
    NORMAL = 2    # Standard debug information
    VERBOSE = 3   # Detailed debug information
    TRACE = 4     # Everything including internal details

    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


class LogCategory(Enum):
    """
    Hierarchical log categories for precision filtering

    Categories use dot notation for hierarchy:
    - UI.RENDER: Screen updates, Live displays
    - UI.INPUT: User input, key handling
    - UI.MENU: Menu generation, navigation
    - UI.EDITOR: Command editor operations
    - UI.EDITOR.TIER: Editor tier routing and escalation
    - UI.EDITOR.SCHEMA: Schema loading and validation
    - STATE.TRANSITION: State machine changes
    - STATE.CHECKPOINT: Save/load operations
    - EXECUTION.START: Task/command execution start
    - EXECUTION.OUTPUT: Command output streaming
    - EXECUTION.END: Task completion
    - DATA.PARSE: Parser operations
    - DATA.VALIDATION: Input validation
    - NETWORK.REQUEST: HTTP/network operations
    - NETWORK.RESPONSE: Response handling
    - PERFORMANCE.TIMING: Function execution times
    - PERFORMANCE.MEMORY: Memory usage tracking
    """

    # UI Categories
    UI = "UI"
    UI_RENDER = "UI.RENDER"
    UI_INPUT = "UI.INPUT"
    UI_MENU = "UI.MENU"
    UI_PANEL = "UI.PANEL"
    UI_FORM = "UI.FORM"
    UI_LIVE = "UI.LIVE"

    # UI Editor Categories (Command Editor Component)
    UI_EDITOR = "UI.EDITOR"
    UI_EDITOR_TIER = "UI.EDITOR.TIER"
    UI_EDITOR_PARSE = "UI.EDITOR.PARSE"
    UI_EDITOR_SCHEMA = "UI.EDITOR.SCHEMA"

    # State Categories
    STATE = "STATE"
    STATE_TRANSITION = "STATE.TRANSITION"
    STATE_CHECKPOINT = "STATE.CHECKPOINT"
    STATE_LOAD = "STATE.LOAD"
    STATE_SAVE = "STATE.SAVE"

    # Execution Categories
    EXECUTION = "EXECUTION"
    EXECUTION_START = "EXECUTION.START"
    EXECUTION_OUTPUT = "EXECUTION.OUTPUT"
    EXECUTION_END = "EXECUTION.END"
    EXECUTION_ERROR = "EXECUTION.ERROR"

    # Data Categories
    DATA = "DATA"
    DATA_PARSE = "DATA.PARSE"
    DATA_VALIDATION = "DATA.VALIDATION"
    DATA_TRANSFORMATION = "DATA.TRANSFORMATION"
    DATA_WRITE = "DATA.WRITE"
    DATA_READ = "DATA.READ"

    # History Categories
    HISTORY = "HISTORY"
    HISTORY_ADD = "HISTORY.ADD"
    HISTORY_SEARCH = "HISTORY.SEARCH"
    HISTORY_FILTER = "HISTORY.FILTER"
    HISTORY_EXPORT = "HISTORY.EXPORT"

    # Network Categories
    NETWORK = "NETWORK"
    NETWORK_REQUEST = "NETWORK.REQUEST"
    NETWORK_RESPONSE = "NETWORK.RESPONSE"
    NETWORK_ERROR = "NETWORK.ERROR"

    # Performance Categories
    PERFORMANCE = "PERFORMANCE"
    PERFORMANCE_TIMING = "PERFORMANCE.TIMING"
    PERFORMANCE_MEMORY = "PERFORMANCE.MEMORY"

    # System Categories
    SYSTEM = "SYSTEM"
    SYSTEM_INIT = "SYSTEM.INIT"
    SYSTEM_SHUTDOWN = "SYSTEM.SHUTDOWN"
    SYSTEM_ERROR = "SYSTEM.ERROR"

    def matches(self, pattern: str) -> bool:
        """
        Check if this category matches a pattern

        Patterns support:
        - Exact match: "UI.INPUT"
        - Parent match: "UI" matches "UI.INPUT", "UI.RENDER", etc.
        - Wildcard: "UI.*" matches all UI subcategories

        Args:
            pattern: Pattern to match against

        Returns:
            True if category matches pattern
        """
        category_parts = self.value.split('.')
        pattern_parts = pattern.split('.')

        # Exact match
        if self.value == pattern:
            return True

        # Parent match: "UI" matches "UI.INPUT"
        if len(pattern_parts) < len(category_parts):
            return category_parts[:len(pattern_parts)] == pattern_parts

        # Wildcard match: "UI.*" matches "UI.INPUT"
        if pattern.endswith('.*'):
            prefix = pattern[:-2]
            return self.value.startswith(prefix + '.')

        return False

    def get_parent(self) -> Optional['LogCategory']:
        """Get parent category (e.g., UI.INPUT -> UI)"""
        parts = self.value.split('.')
        if len(parts) == 1:
            return None

        parent_value = '.'.join(parts[:-1])
        for cat in LogCategory:
            if cat.value == parent_value:
                return cat
        return None

    def get_children(self) -> Set['LogCategory']:
        """Get all child categories"""
        prefix = self.value + '.'
        return {cat for cat in LogCategory if cat.value.startswith(prefix)}

    def is_parent_of(self, other: 'LogCategory') -> bool:
        """Check if this category is a parent of another"""
        return other.value.startswith(self.value + '.')

    def is_child_of(self, other: 'LogCategory') -> bool:
        """Check if this category is a child of another"""
        return self.value.startswith(other.value + '.')


class OutputTarget(Enum):
    """Output targets for log messages"""
    FILE = "file"           # Write to timestamped log file
    CONSOLE = "console"     # Write to stderr
    BOTH = "both"           # Write to both file and console
    JSON_FILE = "json"      # Write structured JSON to file


class LogFormat(Enum):
    """Log message formats"""
    TEXT = "text"           # Human-readable text format
    JSON = "json"           # Structured JSON format
    COMPACT = "compact"     # Minimal compact format


def parse_category_spec(spec: str) -> tuple[LogCategory, Optional[LogLevel]]:
    """
    Parse category specification string

    Formats:
    - "UI.INPUT" -> (UI.INPUT, None)
    - "UI.INPUT:VERBOSE" -> (UI.INPUT, VERBOSE)
    - "UI" -> (UI, None)

    Args:
        spec: Category specification string

    Returns:
        Tuple of (category, level) where level may be None

    Raises:
        ValueError: If spec is invalid
    """
    parts = spec.split(':')
    category_str = parts[0].strip()
    level_str = parts[1].strip().upper() if len(parts) > 1 else None

    # Find matching category
    category = None
    for cat in LogCategory:
        if cat.value == category_str or cat.name == category_str:
            category = cat
            break

    if category is None:
        raise ValueError(f"Invalid category: {category_str}")

    # Parse level if provided
    level = None
    if level_str:
        try:
            level = LogLevel[level_str]
        except KeyError:
            raise ValueError(f"Invalid log level: {level_str}")

    return category, level
