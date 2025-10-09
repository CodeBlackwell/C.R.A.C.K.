"""
Debug Logger - Timestamped debug logging for TUI troubleshooting

Creates timestamped log files in .debug_logs/ directory when debug mode is enabled.
Captures all TUI state transitions, execution flow, and errors.
"""

import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class TUIDebugLogger:
    """Debug logger for TUI session troubleshooting"""

    _instance: Optional['TUIDebugLogger'] = None
    _initialized: bool = False

    def __init__(self, debug_enabled: bool = False, target: str = "unknown"):
        """
        Initialize debug logger

        Args:
            debug_enabled: Enable debug logging to file
            target: Target IP for log filename
        """
        self.debug_enabled = debug_enabled
        self.target = target
        self.logger: Optional[logging.Logger] = None
        self.log_file: Optional[str] = None

        if self.debug_enabled:
            self._setup_logger()

    @classmethod
    def get_instance(cls) -> 'TUIDebugLogger':
        """Get singleton instance"""
        if cls._instance is None:
            cls._instance = cls(debug_enabled=False)
        return cls._instance

    @classmethod
    def initialize(cls, debug_enabled: bool = False, target: str = "unknown") -> 'TUIDebugLogger':
        """
        Initialize singleton instance

        Args:
            debug_enabled: Enable debug logging
            target: Target IP

        Returns:
            TUIDebugLogger instance
        """
        if not cls._initialized:
            cls._instance = cls(debug_enabled=debug_enabled, target=target)
            cls._initialized = True
        return cls._instance

    def _setup_logger(self):
        """Setup file logger with timestamped filename"""
        # Create .debug_logs directory
        log_dir = Path.cwd() / ".debug_logs"
        log_dir.mkdir(exist_ok=True)

        # Create timestamped filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = self.target.replace(".", "_").replace(":", "_")
        log_filename = f"tui_debug_{safe_target}_{timestamp}.log"
        self.log_file = log_dir / log_filename

        # Create logger
        self.logger = logging.getLogger("CRACK.TUI.Debug")
        self.logger.setLevel(logging.DEBUG)

        # Remove existing handlers
        self.logger.handlers.clear()

        # File handler
        file_handler = logging.FileHandler(self.log_file, mode='w')
        file_handler.setLevel(logging.DEBUG)

        # Formatter with timestamp and context
        formatter = logging.Formatter(
            fmt='%(asctime)s.%(msecs)03d [%(levelname)s] %(funcName)s:%(lineno)d - %(message)s',
            datefmt='%H:%M:%S'
        )
        file_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)

        # Log startup
        self.logger.info("=" * 80)
        self.logger.info("TUI DEBUG LOG STARTED")
        self.logger.info(f"Target: {self.target}")
        self.logger.info(f"Timestamp: {datetime.now().isoformat()}")
        self.logger.info(f"Python: {sys.version}")
        self.logger.info("=" * 80)

        print(f"[DEBUG] Logging to: {self.log_file}")

    def debug(self, message: str, **kwargs):
        """Log debug message"""
        if self.logger:
            extra_info = " | ".join(f"{k}={v}" for k, v in kwargs.items())
            full_message = f"{message} | {extra_info}" if extra_info else message
            self.logger.debug(full_message)

    def info(self, message: str, **kwargs):
        """Log info message"""
        if self.logger:
            extra_info = " | ".join(f"{k}={v}" for k, v in kwargs.items())
            full_message = f"{message} | {extra_info}" if extra_info else message
            self.logger.info(full_message)

    def warning(self, message: str, **kwargs):
        """Log warning message"""
        if self.logger:
            extra_info = " | ".join(f"{k}={v}" for k, v in kwargs.items())
            full_message = f"{message} | {extra_info}" if extra_info else message
            self.logger.warning(full_message)

    def error(self, message: str, **kwargs):
        """Log error message"""
        if self.logger:
            extra_info = " | ".join(f"{k}={v}" for k, v in kwargs.items())
            full_message = f"{message} | {extra_info}" if extra_info else message
            self.logger.error(full_message)

    def exception(self, message: str):
        """Log exception with traceback"""
        if self.logger:
            self.logger.exception(message)

    def section(self, title: str):
        """Log section header"""
        if self.logger:
            self.logger.info("")
            self.logger.info("=" * 60)
            self.logger.info(f"  {title}")
            self.logger.info("=" * 60)

    def log_state_transition(self, from_state: str, to_state: str, reason: str = ""):
        """Log state transition"""
        if self.logger:
            msg = f"STATE TRANSITION: {from_state} → {to_state}"
            if reason:
                msg += f" | reason={reason}"
            self.logger.info(msg)

    def log_live_action(self, action: str, details: str = ""):
        """Log Live display action"""
        if self.logger:
            msg = f"LIVE DISPLAY: {action}"
            if details:
                msg += f" | {details}"
            self.logger.debug(msg)

    def log_user_input(self, input_value: str, context: str = ""):
        """Log user input"""
        if self.logger:
            msg = f"USER INPUT: '{input_value}'"
            if context:
                msg += f" | context={context}"
            self.logger.info(msg)

    def log_execution_start(self, task_name: str, task_id: str = ""):
        """Log task execution start"""
        if self.logger:
            self.section(f"TASK EXECUTION START: {task_name}")
            if task_id:
                self.logger.info(f"Task ID: {task_id}")

    def log_execution_end(self, task_name: str, success: bool, exit_code: Optional[int] = None):
        """Log task execution end"""
        if self.logger:
            status = "SUCCESS" if success else "FAILED"
            msg = f"TASK EXECUTION END: {task_name} | status={status}"
            if exit_code is not None:
                msg += f" | exit_code={exit_code}"
            self.logger.info(msg)

    def get_log_path(self) -> Optional[str]:
        """Get path to current log file"""
        return str(self.log_file) if self.log_file else None


# Convenience functions for global access
def init_debug_logger(debug_enabled: bool = False, target: str = "unknown") -> TUIDebugLogger:
    """Initialize global debug logger"""
    return TUIDebugLogger.initialize(debug_enabled=debug_enabled, target=target)


def get_debug_logger() -> TUIDebugLogger:
    """Get global debug logger instance"""
    return TUIDebugLogger.get_instance()


def log_debug(message: str, **kwargs):
    """Log debug message to global logger"""
    get_debug_logger().debug(message, **kwargs)


def log_info(message: str, **kwargs):
    """Log info message to global logger"""
    get_debug_logger().info(message, **kwargs)


def log_error(message: str, **kwargs):
    """Log error message to global logger"""
    get_debug_logger().error(message, **kwargs)


def log_section(title: str):
    """Log section header to global logger"""
    get_debug_logger().section(title)
