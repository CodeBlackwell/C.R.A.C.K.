"""Backward compatibility layer for ThemeManager integration."""

from .enums import Component, StepType, LogLevel, CATEGORY_ALIASES
from .logger import DebugLogger


class LogCategory:
    """
    Backward-compatible LogCategory enum for ThemeManager.

    Maps old category names to new (Component, StepType) pairs.
    """
    SYSTEM_INIT = "SYSTEM_INIT"
    CONFIG_LOAD = "CONFIG_LOAD"
    CONFIG_SAVE = "CONFIG_SAVE"
    CONFIG_ERROR = "CONFIG_ERROR"
    THEME_LOAD = "THEME_LOAD"
    THEME_SWITCH = "THEME_SWITCH"


class LegacyLogLevel:
    """Backward-compatible LogLevel for ThemeManager."""
    VERBOSE = LogLevel.VERBOSE
    NORMAL = LogLevel.NORMAL
    WARNING = LogLevel.WARNING
    ERROR = LogLevel.ERROR


class LegacyDebugLogger:
    """
    Wrapper providing old-style log() interface for ThemeManager.

    ThemeManager calls:
        logger.log("message", category=LogCategory.THEME_LOAD, level=LogLevel.NORMAL, **kwargs)

    This translates to:
        logger.log("message", step=StepType.CONFIG_LOAD, level=LogLevel.NORMAL,
                  component=Component.THEMES, **kwargs)
    """

    def __init__(self, component: Component = Component.CORE):
        self._logger = DebugLogger(component=component)

    def log(self, message: str, category=None, level=None, **context):
        """Log with backward-compatible category parameter."""
        # Map category to (component, step)
        if category:
            cat_name = category if isinstance(category, str) else str(category)
            component, step = CATEGORY_ALIASES.get(cat_name, (Component.CORE, StepType.PROCESSING))
        else:
            component = Component.CORE
            step = StepType.PROCESSING

        # Map level
        if isinstance(level, LogLevel):
            log_level = level
        elif hasattr(level, 'value'):
            log_level = level
        else:
            log_level = LogLevel.NORMAL

        self._logger.log(message, step, log_level, component, **context)
