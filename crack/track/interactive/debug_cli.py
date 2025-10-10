"""
CLI Argument Parsing for Debug Logging

Helper functions to integrate precision debug logging with argparse-based CLIs.
"""

import argparse
from pathlib import Path
from typing import Optional

from .log_types import LogLevel
from .log_config import LogConfig
from .debug_logger import TUIDebugLogger, init_debug_logger


def add_debug_arguments(parser: argparse.ArgumentParser):
    """
    Add debug logging arguments to an argparse parser

    Args:
        parser: argparse.ArgumentParser instance

    Adds:
        --debug / -D: Enable debug logging
        --debug-categories: Comma-separated category specs
        --debug-modules: Comma-separated module names
        --debug-level: Global log level
        --debug-output: Output target (file, console, both)
        --debug-format: Log format (text, json, compact)
        --debug-config: Path to debug config JSON file
        --debug-timing: Include performance timing

    Example:
        parser = argparse.ArgumentParser()
        add_debug_arguments(parser)
        args = parser.parse_args()
        logger = create_logger_from_args(args, target="192.168.1.1")
    """
    debug_group = parser.add_argument_group('debug logging options')

    debug_group.add_argument(
        '--debug', '-D',
        action='store_true',
        help='Enable debug logging to file'
    )

    debug_group.add_argument(
        '--debug-categories',
        type=str,
        metavar='SPECS',
        help='Comma-separated category specs (e.g., "UI.INPUT:VERBOSE,STATE:NORMAL")'
    )

    debug_group.add_argument(
        '--debug-modules',
        type=str,
        metavar='MODULES',
        help='Comma-separated module names to log (prefix with ! to disable)'
    )

    debug_group.add_argument(
        '--debug-level',
        type=str,
        choices=['MINIMAL', 'NORMAL', 'VERBOSE', 'TRACE'],
        metavar='LEVEL',
        help='Global log level (MINIMAL, NORMAL, VERBOSE, TRACE)'
    )

    debug_group.add_argument(
        '--debug-output',
        type=str,
        choices=['file', 'console', 'both', 'json'],
        metavar='TARGET',
        help='Output target: file, console, both, or json'
    )

    debug_group.add_argument(
        '--debug-format',
        type=str,
        choices=['text', 'json', 'compact'],
        metavar='FORMAT',
        help='Log format: text, json, or compact'
    )

    debug_group.add_argument(
        '--debug-config',
        type=str,
        metavar='PATH',
        help='Path to debug configuration JSON file'
    )

    debug_group.add_argument(
        '--debug-timing',
        action='store_true',
        help='Include performance timing in logs'
    )


def create_config_from_args(args: argparse.Namespace) -> Optional[LogConfig]:
    """
    Create LogConfig from parsed command-line arguments

    Args:
        args: Parsed argparse.Namespace

    Returns:
        LogConfig instance if debug enabled, None otherwise
    """
    # Check if debug is enabled
    if not getattr(args, 'debug', False):
        return None

    # Load from config file if specified
    if hasattr(args, 'debug_config') and args.debug_config:
        config = LogConfig.from_file(Path(args.debug_config))
    else:
        # Create from CLI arguments
        config = LogConfig.from_cli_args(
            categories=getattr(args, 'debug_categories', None),
            modules=getattr(args, 'debug_modules', None),
            level=getattr(args, 'debug_level', None),
            output=getattr(args, 'debug_output', None),
            format=getattr(args, 'debug_format', None)
        )

    # Apply timing flag
    if hasattr(args, 'debug_timing') and args.debug_timing:
        config.include_timing = True

    return config


def create_logger_from_args(
    args: argparse.Namespace,
    target: str = "unknown"
) -> TUIDebugLogger:
    """
    Create and initialize debug logger from command-line arguments

    Args:
        args: Parsed argparse.Namespace
        target: Target IP or identifier

    Returns:
        Initialized TUIDebugLogger instance

    Example:
        parser = argparse.ArgumentParser()
        add_debug_arguments(parser)
        args = parser.parse_args()
        logger = create_logger_from_args(args, target="192.168.1.1")
    """
    config = create_config_from_args(args)

    if config:
        return init_debug_logger(config=config, target=target)
    else:
        # Debug not enabled, return disabled logger
        return init_debug_logger(debug_enabled=False, target=target)


def print_debug_help():
    """Print detailed debug logging usage help"""
    help_text = """
=== Precision Debug Logging ===

Basic Usage:
  --debug, -D                  Enable debug logging to file

Category Filtering:
  --debug-categories=SPECS     Select specific categories to log

  Formats:
    CATEGORY              Enable all messages for category
    CATEGORY:LEVEL        Enable category with specific verbosity
    CATEGORY1,CATEGORY2   Enable multiple categories

  Examples:
    UI.INPUT              Log all UI input events
    UI.INPUT:VERBOSE      Log UI input with verbose details
    UI,STATE,EXECUTION    Log UI, STATE, and EXECUTION categories
    UI:TRACE,STATE:NORMAL Log UI at TRACE level, STATE at NORMAL

  Available Categories:
    UI.*                  All UI events (RENDER, INPUT, MENU, PANEL, FORM, LIVE)
    STATE.*               All state events (TRANSITION, CHECKPOINT, LOAD, SAVE)
    EXECUTION.*           All execution events (START, OUTPUT, END, ERROR)
    DATA.*                All data events (PARSE, VALIDATION, TRANSFORMATION)
    NETWORK.*             All network events (REQUEST, RESPONSE, ERROR)
    PERFORMANCE.*         All performance events (TIMING, MEMORY)
    SYSTEM.*              All system events (INIT, SHUTDOWN, ERROR)

Module Filtering:
  --debug-modules=MODULES      Select specific Python modules to log from

  Examples:
    session              Log only from session module
    session,prompts      Log from session and prompts modules
    session,!test        Log from session, but not test module

Verbosity Levels:
  --debug-level=LEVEL          Set global verbosity level

  Levels (least to most verbose):
    MINIMAL              Critical information only
    NORMAL               Standard debug information (default)
    VERBOSE              Detailed debug information
    TRACE                Everything including internal details

Output Options:
  --debug-output=TARGET        Where to send log messages

  Targets:
    file                 Write to timestamped log file (default)
    console              Write to stderr
    both                 Write to both file and console
    json                 Write structured JSON to file

Format Options:
  --debug-format=FORMAT        Log message format

  Formats:
    text                 Human-readable text (default)
    json                 Structured JSON
    compact              Minimal compact format

Configuration File:
  --debug-config=PATH          Load configuration from JSON file

  Example config (~/.crack/debug_config.json):
  {
    "enabled": true,
    "global_level": "VERBOSE",
    "categories": {
      "UI.INPUT": "TRACE",
      "STATE": "NORMAL"
    },
    "modules": ["session", "prompts"],
    "output_target": "both",
    "log_format": "text",
    "include_timing": true
  }

Performance Tracking:
  --debug-timing               Include execution timing in logs

Environment Variables:
  CRACK_DEBUG_ENABLED=1        Enable debug logging
  CRACK_DEBUG_CATEGORIES=...   Set category filters
  CRACK_DEBUG_MODULES=...      Set module filters
  CRACK_DEBUG_LEVEL=...        Set global level
  CRACK_DEBUG_OUTPUT=...       Set output target
  CRACK_DEBUG_FORMAT=...       Set log format

Common Use Cases:

  1. Debug UI issues:
     --debug --debug-categories=UI:VERBOSE

  2. Debug state machine:
     --debug --debug-categories=STATE.TRANSITION:TRACE

  3. Track performance:
     --debug --debug-categories=PERFORMANCE --debug-timing

  4. Debug specific module:
     --debug --debug-modules=session --debug-level=TRACE

  5. Everything to console:
     --debug --debug-categories=all --debug-output=console

  6. Minimal logging to file:
     --debug --debug-level=MINIMAL

  7. Use config file:
     --debug --debug-config=~/.crack/debug_config.json

Log Files:
  Location: .debug_logs/tui_debug_<target>_<timestamp>.log
  Format:   HH:MM:SS.mmm [LEVEL] function:line - [CATEGORY] message

For more information, see the debug logging documentation.
"""
    print(help_text)


# Quick preset configurations
class DebugPresets:
    """Predefined debug configurations for common scenarios"""

    @staticmethod
    def ui_only() -> LogConfig:
        """Debug UI events only"""
        return LogConfig.from_string("UI:VERBOSE")

    @staticmethod
    def state_only() -> LogConfig:
        """Debug state transitions only"""
        return LogConfig.from_string("STATE:VERBOSE")

    @staticmethod
    def execution_only() -> LogConfig:
        """Debug execution events only"""
        return LogConfig.from_string("EXECUTION:VERBOSE")

    @staticmethod
    def performance() -> LogConfig:
        """Track performance metrics"""
        config = LogConfig.from_string("PERFORMANCE:TRACE")
        config.include_timing = True
        return config

    @staticmethod
    def everything() -> LogConfig:
        """Log everything at VERBOSE level"""
        config = LogConfig.from_string("all")
        config.global_level = LogLevel.VERBOSE
        return config

    @staticmethod
    def minimal() -> LogConfig:
        """Minimal logging (errors only)"""
        config = LogConfig.from_string("all")
        config.global_level = LogLevel.MINIMAL
        return config
