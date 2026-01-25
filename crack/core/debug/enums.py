"""Debug logger enums for CRACK toolkit."""

from enum import Enum


class LogLevel(Enum):
    """Log severity levels."""
    VERBOSE = 1      # Detailed trace info
    NORMAL = 2       # Standard operational messages
    WARNING = 3      # Potential issues
    ERROR = 4        # Errors that need attention

    def __ge__(self, other):
        if not isinstance(other, LogLevel):
            return NotImplemented
        return self.value >= other.value

    def __gt__(self, other):
        if not isinstance(other, LogLevel):
            return NotImplemented
        return self.value > other.value

    def __le__(self, other):
        if not isinstance(other, LogLevel):
            return NotImplemented
        return self.value <= other.value

    def __lt__(self, other):
        if not isinstance(other, LogLevel):
            return NotImplemented
        return self.value < other.value


class Component(Enum):
    """CRACK toolkit components for log filtering."""
    # Core modules
    CORE = "core"
    THEMES = "themes"
    CONFIG = "config"

    # Post-exploitation tools
    BLOODTRAIL = "bloodtrail"
    PRISM = "prism"
    SESSION = "session"

    # GUI applications
    BREACH = "breach"
    CRACKPEDIA = "crackpedia"

    # Data management
    ENGAGEMENT = "engagement"
    REFERENCE = "reference"
    DB = "db"

    # Bloodtrail sub-components (for granular filtering)
    BT_NEO4J = "bt_neo4j"
    BT_PARSER = "bt_parser"
    BT_IMPORT = "bt_import"
    BT_SPRAY = "bt_spray"
    BT_PWNED = "bt_pwned"
    BT_RECOMMEND = "bt_recommend"
    BT_QUERY = "bt_query"
    BT_CREDS = "bt_creds"


class StepType(Enum):
    """Operation step types for log filtering."""
    # Data operations
    PROCESSING = "processing"
    PARSING = "parsing"
    VALIDATION = "validation"

    # External operations
    QUERYING = "querying"
    CONNECTION = "connection"
    TOOL_CALL = "tool_call"

    # I/O operations
    IMPORT = "import"
    EXPORT = "export"

    # System operations
    INIT = "init"
    CLEANUP = "cleanup"
    CONFIG_LOAD = "config_load"

    # Bloodtrail-specific
    RECOMMENDATION = "recommendation"
    CREDENTIAL = "credential"
    ENUMERATION = "enumeration"


# Backward compatibility aliases for ThemeManager
CATEGORY_ALIASES = {
    "SYSTEM_INIT": (Component.CORE, StepType.INIT),
    "CONFIG_LOAD": (Component.CONFIG, StepType.CONFIG_LOAD),
    "CONFIG_SAVE": (Component.CONFIG, StepType.EXPORT),
    "CONFIG_ERROR": (Component.CONFIG, StepType.VALIDATION),
    "THEME_LOAD": (Component.THEMES, StepType.CONFIG_LOAD),
    "THEME_SWITCH": (Component.THEMES, StepType.PROCESSING),
}
