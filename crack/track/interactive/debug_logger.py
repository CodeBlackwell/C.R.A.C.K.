"""
Debug Logger - Precision debug logging for TUI/GUI/CLI development

Enhanced logging system with:
- Hierarchical category filtering (UI, STATE, EXECUTION, etc.)
- Module-level filtering
- Per-category verbosity levels
- Multiple output targets (file, console, JSON)
- Performance tracking
- Backward compatible API
"""

import inspect
import json
import logging
import os
import sys
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, Callable

from .log_types import LogCategory, LogLevel, OutputTarget, LogFormat
from .log_config import LogConfig


class TUIDebugLogger:
    """
    Enhanced debug logger with precision filtering

    Features:
    - Category-aware logging (UI, STATE, EXECUTION, etc.)
    - Module/source filtering
    - Per-category verbosity levels
    - Multiple output targets
    - Performance tracking
    - Backward compatible with old API
    """

    _instance: Optional['TUIDebugLogger'] = None
    _initialized: bool = False

    def __init__(
        self,
        config: Optional[LogConfig] = None,
        debug_enabled: bool = False,
        target: str = "unknown"
    ):
        """
        Initialize debug logger

        Args:
            config: LogConfig instance (if None, created from debug_enabled)
            debug_enabled: Enable debug logging (legacy parameter)
            target: Target IP for log filename
        """
        self.target = target
        self.config = config or LogConfig(enabled=debug_enabled)
        self.logger: Optional[logging.Logger] = None
        self.console_logger: Optional[logging.Logger] = None
        self.log_file: Optional[Path] = None
        self.json_log_file: Optional[Path] = None
        self._message_buffer: list = []
        self._perf_timers: Dict[str, float] = {}

        # Legacy compatibility
        self.debug_enabled = self.config.enabled

        if self.config.enabled:
            self._setup_logger()

    @classmethod
    def get_instance(cls) -> 'TUIDebugLogger':
        """Get singleton instance"""
        if cls._instance is None:
            cls._instance = cls(debug_enabled=False)
        return cls._instance

    @classmethod
    def initialize(
        cls,
        config: Optional[LogConfig] = None,
        debug_enabled: bool = False,
        target: str = "unknown"
    ) -> 'TUIDebugLogger':
        """
        Initialize singleton instance

        Args:
            config: LogConfig instance
            debug_enabled: Enable debug logging (legacy)
            target: Target IP

        Returns:
            TUIDebugLogger instance
        """
        if not cls._initialized:
            cls._instance = cls(config=config, debug_enabled=debug_enabled, target=target)
            cls._initialized = True
        return cls._instance

    def _setup_logger(self):
        """Setup loggers based on output target configuration"""
        # Create .debug_logs directory
        log_dir = Path.cwd() / ".debug_logs"
        log_dir.mkdir(exist_ok=True)

        # Create timestamped filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = self.target.replace(".", "_").replace(":", "_")

        # Setup file logger if needed
        if self.config.output_target in (OutputTarget.FILE, OutputTarget.BOTH):
            log_filename = f"tui_debug_{safe_target}_{timestamp}.log"
            self.log_file = log_dir / log_filename

            self.logger = logging.getLogger(f"CRACK.TUI.Debug.{id(self)}")
            self.logger.setLevel(logging.DEBUG)
            self.logger.propagate = False
            self.logger.handlers.clear()

            file_handler = logging.FileHandler(self.log_file, mode='w')
            file_handler.setLevel(logging.DEBUG)

            if self.config.log_format == LogFormat.COMPACT:
                formatter = logging.Formatter('%(asctime)s [%(levelname).1s] %(message)s', datefmt='%H:%M:%S')
            else:
                formatter = logging.Formatter(
                    fmt='%(asctime)s.%(msecs)03d [%(levelname)s] %(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%H:%M:%S'
                )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

            # Log startup
            self._log_startup()

            # Notify user with visible message (uses stderr to avoid TUI conflicts)
            import sys
            sys.stderr.write(f"\n[DEBUG] Precision logging enabled: {self.log_file}\n")
            sys.stderr.flush()

        # Setup console logger if needed
        if self.config.output_target in (OutputTarget.CONSOLE, OutputTarget.BOTH):
            self.console_logger = logging.getLogger(f"CRACK.TUI.Console.{id(self)}")
            self.console_logger.setLevel(logging.DEBUG)
            self.console_logger.propagate = False
            self.console_logger.handlers.clear()

            console_handler = logging.StreamHandler(sys.stderr)
            console_handler.setLevel(logging.DEBUG)

            formatter = logging.Formatter('[%(levelname).1s] %(message)s')
            console_handler.setFormatter(formatter)
            self.console_logger.addHandler(console_handler)

        # Setup JSON logger if needed
        if self.config.output_target == OutputTarget.JSON_FILE or self.config.log_format == LogFormat.JSON:
            json_filename = f"tui_debug_{safe_target}_{timestamp}.json"
            self.json_log_file = log_dir / json_filename

    def _log_startup(self):
        """Log startup information"""
        if self.logger:
            self.logger.info("=" * 80)
            self.logger.info("PRECISION DEBUG LOG STARTED")
            self.logger.info(f"Target: {self.target}")
            self.logger.info(f"Timestamp: {datetime.now().isoformat()}")
            self.logger.info(f"Python: {sys.version}")
            self.logger.info("=" * 80)
            self.logger.info(f"Configuration: {self.config}")

    def _should_log(
        self,
        category: Optional[LogCategory] = None,
        level: LogLevel = LogLevel.NORMAL
    ) -> bool:
        """Check if message should be logged based on filters"""
        if not self.config.enabled:
            return False

        # Get caller information for module filtering
        frame = inspect.currentframe()
        if frame and frame.f_back and frame.f_back.f_back:
            caller_frame = frame.f_back.f_back
            module = inspect.getmodule(caller_frame)
            module_name = module.__name__ if module else None
        else:
            module_name = None

        return self.config.should_log(
            category=category,
            level=level,
            module=module_name
        )

    def _write_log(self, log_level: int, message: str, category: Optional[LogCategory] = None):
        """Write log message to configured outputs"""
        # Add category prefix if specified
        if category:
            message = f"[{category.value}] {message}"

        # Write to file logger
        if self.logger:
            self.logger.log(log_level, message)

        # Write to console logger
        if self.console_logger:
            self.console_logger.log(log_level, message)

        # Write to JSON log
        if self.json_log_file and self.config.log_format == LogFormat.JSON:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'level': logging.getLevelName(log_level),
                'category': category.value if category else None,
                'message': message
            }
            with open(self.json_log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')

    def log(
        self,
        message: str,
        category: Optional[LogCategory] = None,
        level: LogLevel = LogLevel.NORMAL,
        **kwargs
    ):
        """
        Primary logging method with category and level support

        Args:
            message: Log message
            category: Log category for filtering
            level: Verbosity level
            **kwargs: Additional key-value pairs to include
        """
        if not self._should_log(category, level):
            return

        extra_info = " | ".join(f"{k}={v}" for k, v in kwargs.items())
        full_message = f"{message} | {extra_info}" if extra_info else message

        # Map LogLevel to logging level
        log_level_map = {
            LogLevel.MINIMAL: logging.WARNING,
            LogLevel.NORMAL: logging.INFO,
            LogLevel.VERBOSE: logging.DEBUG,
            LogLevel.TRACE: logging.DEBUG
        }
        log_level = log_level_map.get(level, logging.INFO)

        self._write_log(log_level, full_message, category)

    # Backward compatible methods
    def debug(self, message: str, category: Optional[LogCategory] = None, **kwargs):
        """Log debug message (backward compatible)"""
        self.log(message, category=category, level=LogLevel.VERBOSE, **kwargs)

    def info(self, message: str, category: Optional[LogCategory] = None, **kwargs):
        """Log info message (backward compatible)"""
        self.log(message, category=category, level=LogLevel.NORMAL, **kwargs)

    def warning(self, message: str, category: Optional[LogCategory] = None, **kwargs):
        """Log warning message (backward compatible)"""
        self.log(message, category=category, level=LogLevel.MINIMAL, **kwargs)

    def error(self, message: str, category: Optional[LogCategory] = None, **kwargs):
        """Log error message (backward compatible)"""
        if self._should_log(category, LogLevel.MINIMAL):
            full_message = f"{message} | " + " | ".join(f"{k}={v}" for k, v in kwargs.items()) if kwargs else message
            self._write_log(logging.ERROR, full_message, category)

    def exception(self, message: str, category: Optional[LogCategory] = None):
        """Log exception with traceback (backward compatible)"""
        if self._should_log(category, LogLevel.MINIMAL):
            if self.logger:
                self.logger.exception(f"[{category.value if category else 'EXCEPTION'}] {message}")
            if self.console_logger:
                self.console_logger.exception(f"[{category.value if category else 'EXCEPTION'}] {message}")

    def section(self, title: str, category: Optional[LogCategory] = None):
        """Log section header (backward compatible)"""
        if self._should_log(category, LogLevel.NORMAL):
            self._write_log(logging.INFO, "", category)
            self._write_log(logging.INFO, "=" * 60, category)
            self._write_log(logging.INFO, f"  {title}", category)
            self._write_log(logging.INFO, "=" * 60, category)

    # Enhanced category-aware methods
    def log_state_transition(self, from_state: str, to_state: str, reason: str = ""):
        """Log state transition"""
        msg = f"STATE TRANSITION: {from_state} → {to_state}"
        if reason:
            msg += f" | reason={reason}"
        self.info(msg, category=LogCategory.STATE_TRANSITION)

    def log_live_action(self, action: str, details: str = ""):
        """Log Live display action"""
        msg = f"LIVE DISPLAY: {action}"
        if details:
            msg += f" | {details}"
        self.debug(msg, category=LogCategory.UI_LIVE)

    def log_user_input(self, input_value: str, context: str = ""):
        """Log user input"""
        msg = f"USER INPUT: '{input_value}'"
        if context:
            msg += f" | context={context}"
        self.info(msg, category=LogCategory.UI_INPUT)

    def log_execution_start(self, task_name: str, task_id: str = ""):
        """Log task execution start"""
        self.section(f"TASK EXECUTION START: {task_name}", category=LogCategory.EXECUTION_START)
        if task_id:
            self.info(f"Task ID: {task_id}", category=LogCategory.EXECUTION_START)

    def log_execution_end(self, task_name: str, success: bool, exit_code: Optional[int] = None):
        """Log task execution end"""
        status = "SUCCESS" if success else "FAILED"
        msg = f"TASK EXECUTION END: {task_name} | status={status}"
        if exit_code is not None:
            msg += f" | exit_code={exit_code}"
        self.info(msg, category=LogCategory.EXECUTION_END)

    def log_render(self, component: str, details: str = ""):
        """Log UI rendering"""
        msg = f"RENDER: {component}"
        if details:
            msg += f" | {details}"
        self.debug(msg, category=LogCategory.UI_RENDER)

    def log_menu(self, menu_type: str, choices: int, details: str = ""):
        """Log menu generation"""
        msg = f"MENU: {menu_type} | choices={choices}"
        if details:
            msg += f" | {details}"
        self.debug(msg, category=LogCategory.UI_MENU)

    def log_checkpoint(self, action: str, details: str = ""):
        """Log checkpoint save/load"""
        msg = f"CHECKPOINT: {action}"
        if details:
            msg += f" | {details}"
        self.info(msg, category=LogCategory.STATE_CHECKPOINT)

    def log_parse(self, parser: str, items: int, details: str = ""):
        """Log data parsing"""
        msg = f"PARSE: {parser} | items={items}"
        if details:
            msg += f" | {details}"
        self.debug(msg, category=LogCategory.DATA_PARSE)

    def log_validation(self, field: str, valid: bool, reason: str = ""):
        """Log input validation"""
        status = "VALID" if valid else "INVALID"
        msg = f"VALIDATION: {field} | status={status}"
        if reason:
            msg += f" | reason={reason}"
        self.debug(msg, category=LogCategory.DATA_VALIDATION)

    # Performance tracking methods
    def start_timer(self, timer_name: str):
        """Start a performance timer"""
        if self.config.include_timing:
            self._perf_timers[timer_name] = time.time()
            self.debug(f"TIMER START: {timer_name}", category=LogCategory.PERFORMANCE_TIMING)

    def end_timer(self, timer_name: str) -> Optional[float]:
        """End a performance timer and return duration"""
        if not self.config.include_timing or timer_name not in self._perf_timers:
            return None

        duration = time.time() - self._perf_timers[timer_name]
        del self._perf_timers[timer_name]
        self.debug(f"TIMER END: {timer_name} | duration={duration:.3f}s", category=LogCategory.PERFORMANCE_TIMING)
        return duration

    @contextmanager
    def timer(self, timer_name: str):
        """Context manager for timing code blocks"""
        self.start_timer(timer_name)
        try:
            yield
        finally:
            self.end_timer(timer_name)

    # Configuration management
    def update_config(self, config: LogConfig):
        """Update logger configuration at runtime"""
        self.config = config
        self.debug_enabled = config.enabled

    def enable_category(self, category: LogCategory, level: Optional[LogLevel] = None):
        """Enable a category at runtime"""
        self.config.enable_category(category, level)

    def disable_category(self, category: LogCategory):
        """Disable a category at runtime"""
        self.config.disable_category(category)

    def set_category_level(self, category: LogCategory, level: LogLevel):
        """Set category verbosity level at runtime"""
        self.config.set_category_level(category, level)

    # Utility methods
    def get_log_path(self) -> Optional[str]:
        """Get path to current log file"""
        return str(self.log_file) if self.log_file else None

    def get_config(self) -> LogConfig:
        """Get current configuration"""
        return self.config

    def flush(self):
        """Flush buffered log messages"""
        if self.logger:
            for handler in self.logger.handlers:
                handler.flush()
        if self.console_logger:
            for handler in self.console_logger.handlers:
                handler.flush()


# Convenience functions for global access
def init_debug_logger(
    config: Optional[LogConfig] = None,
    debug_enabled: bool = False,
    target: str = "unknown"
) -> TUIDebugLogger:
    """
    Initialize global debug logger

    Args:
        config: LogConfig instance (if None, uses debug_enabled)
        debug_enabled: Enable debug logging (legacy)
        target: Target IP

    Returns:
        TUIDebugLogger instance
    """
    return TUIDebugLogger.initialize(config=config, debug_enabled=debug_enabled, target=target)


def get_debug_logger() -> TUIDebugLogger:
    """Get global debug logger instance"""
    return TUIDebugLogger.get_instance()


# Convenience logging functions
def log(message: str, category: Optional[LogCategory] = None, level: LogLevel = LogLevel.NORMAL, **kwargs):
    """Log message with category and level"""
    get_debug_logger().log(message, category=category, level=level, **kwargs)


def log_debug(message: str, category: Optional[LogCategory] = None, **kwargs):
    """Log debug message to global logger"""
    get_debug_logger().debug(message, category=category, **kwargs)


def log_info(message: str, category: Optional[LogCategory] = None, **kwargs):
    """Log info message to global logger"""
    get_debug_logger().info(message, category=category, **kwargs)


def log_error(message: str, category: Optional[LogCategory] = None, **kwargs):
    """Log error message to global logger"""
    get_debug_logger().error(message, category=category, **kwargs)


def log_section(title: str, category: Optional[LogCategory] = None):
    """Log section header to global logger"""
    get_debug_logger().section(title, category=category)


def log_if(condition: bool, message: str, category: Optional[LogCategory] = None, **kwargs):
    """Log message only if condition is True"""
    if condition:
        get_debug_logger().info(message, category=category, **kwargs)


def log_dict(data: Dict[str, Any], title: str = "Data", category: Optional[LogCategory] = None):
    """Log dictionary contents"""
    logger = get_debug_logger()
    logger.section(title, category=category)
    for key, value in data.items():
        logger.info(f"  {key}: {value}", category=category)


# Decorators
def log_function(
    category: Optional[LogCategory] = None,
    level: LogLevel = LogLevel.VERBOSE,
    log_args: bool = False,
    log_result: bool = False,
    log_timing: bool = False
):
    """
    Decorator to log function entry/exit

    Args:
        category: Log category
        level: Verbosity level
        log_args: Log function arguments
        log_result: Log function return value
        log_timing: Log execution time

    Example:
        @log_function(category=LogCategory.UI_RENDER, log_timing=True)
        def render_menu():
            pass
    """
    def decorator(func: Callable):
        def wrapper(*args, **kwargs):
            logger = get_debug_logger()
            func_name = func.__name__

            # Log entry
            msg = f"ENTER: {func_name}()"
            if log_args and (args or kwargs):
                arg_str = ", ".join([repr(a) for a in args] + [f"{k}={repr(v)}" for k, v in kwargs.items()])
                msg += f" | args=({arg_str})"
            logger.log(msg, category=category, level=level)

            # Execute function
            start_time = time.time() if log_timing else None
            try:
                result = func(*args, **kwargs)

                # Log exit
                exit_msg = f"EXIT: {func_name}()"
                if log_result:
                    exit_msg += f" | result={repr(result)}"
                if log_timing and start_time:
                    duration = time.time() - start_time
                    exit_msg += f" | duration={duration:.3f}s"
                logger.log(exit_msg, category=category, level=level)

                return result
            except Exception as e:
                # Log exception
                logger.error(f"EXCEPTION in {func_name}(): {e}", category=category)
                raise

        return wrapper
    return decorator


# Context Managers
@contextmanager
def log_context(
    title: str,
    category: Optional[LogCategory] = None,
    level: LogLevel = LogLevel.NORMAL
):
    """
    Context manager for scoped logging

    Example:
        with log_context("Task Execution", category=LogCategory.EXECUTION):
            execute_task()
    """
    logger = get_debug_logger()
    logger.section(title, category=category)
    logger.log(f"BEGIN: {title}", category=category, level=level)
    try:
        yield logger
    finally:
        logger.log(f"END: {title}", category=category, level=level)


@contextmanager
def log_timing(
    operation: str,
    category: Optional[LogCategory] = LogCategory.PERFORMANCE_TIMING
):
    """
    Context manager for timing operations

    Example:
        with log_timing("Nmap Parse"):
            parse_nmap_file()
    """
    logger = get_debug_logger()
    start_time = time.time()
    logger.debug(f"TIMING START: {operation}", category=category)
    try:
        yield
    finally:
        duration = time.time() - start_time
        logger.debug(f"TIMING END: {operation} | duration={duration:.3f}s", category=category)


def log_exception_context(func: Callable):
    """
    Decorator to log exceptions with full context

    Example:
        @log_exception_context
        def risky_operation():
            pass
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger = get_debug_logger()
            logger.exception(f"Exception in {func.__name__}", category=LogCategory.SYSTEM_ERROR)
            raise
    return wrapper
