"""
Error Handler System for CRACK Track TUI

Provides centralized error handling with:
- Clear, actionable error messages with suggested fixes
- Error categorization (INPUT, EXECUTION, NETWORK, FILE, CONFIG, PERMISSION)
- Rich Panel formatting for TUI display
- Debug logging integration
- Context-aware help based on error type
- OSCP-specific error patterns and suggestions

Usage:
    handler = ErrorHandler(debug_logger=logger)
    handler.show_error(ErrorType.FILE, "Config not found", ["Run 'crack track --init'"])

    # Or automatically categorize and handle
    try:
        run_nmap(target)
    except Exception as e:
        handler.handle_exception(e, context="nmap scan")
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from rich.panel import Panel
from rich.text import Text
from rich.console import Console
from rich import box
import json
import os
import subprocess


class ErrorType(Enum):
    """Error categories for classification"""
    INPUT = "INPUT"              # User input validation errors
    EXECUTION = "EXECUTION"      # Task/command execution errors
    NETWORK = "NETWORK"          # Network connectivity errors
    FILE = "FILE"                # File system errors
    CONFIG = "CONFIG"            # Configuration errors
    PERMISSION = "PERMISSION"    # Permission/access errors


class ErrorHandler:
    """Centralized error handling system for TUI"""

    # OSCP-specific error patterns
    OSCP_PATTERNS = {
        'nmap': {
            'keywords': ['nmap', 'command not found'],
            'suggestions': [
                "Install nmap: sudo apt install nmap",
                "Check if nmap is in PATH: which nmap",
                "OSCP: nmap should be pre-installed on Kali Linux"
            ]
        },
        'permission': {
            'keywords': ['permission denied', 'operation not permitted', 'raw socket'],
            'suggestions': [
                "Raw socket operations require root: sudo <command>",
                "OSCP: Most scan tools need sudo privileges",
                "Check file permissions: ls -la <file>"
            ]
        },
        'network_unreachable': {
            'keywords': ['network unreachable', 'no route to host'],
            'suggestions': [
                "Verify VPN connection: ifconfig tun0",
                "OSCP: Check OVPN connection is active",
                "Ping gateway to test connectivity",
                "Check target is in correct subnet (192.168.x.x or 10.x.x.x)"
            ]
        },
        'timeout': {
            'keywords': ['timeout', 'timed out'],
            'suggestions': [
                "Increase timeout value with -T flag",
                "Check target is online: ping <target>",
                "OSCP: Some services may be slow, try -T2",
                "Verify firewall not dropping packets"
            ]
        },
        'wordlist': {
            'keywords': ['wordlist', '/usr/share/wordlists', 'rockyou'],
            'suggestions': [
                "Check wordlist exists: ls /usr/share/wordlists/",
                "OSCP: Common wordlists in /usr/share/wordlists/",
                "Extract rockyou: gunzip /usr/share/wordlists/rockyou.txt.gz",
                "Verify full path is correct"
            ]
        }
    }

    def __init__(self, debug_logger=None, console: Optional[Console] = None, max_history: int = 10):
        """
        Initialize error handler

        Args:
            debug_logger: Optional TUIDebugLogger instance for logging
            console: Optional Rich Console instance (creates new if None)
            max_history: Maximum number of errors to keep in history (default: 10)
        """
        self.debug_logger = debug_logger
        self.console = console or Console()
        self.max_history = max_history
        self._error_history: List[Dict[str, Any]] = []

    def categorize_error(self, exception: Exception) -> ErrorType:
        """
        Auto-detect error category from exception type and message content

        Args:
            exception: Python exception instance

        Returns:
            ErrorType enum matching the exception

        Examples:
            >>> handler.categorize_error(FileNotFoundError())
            ErrorType.FILE
            >>> handler.categorize_error(PermissionError())
            ErrorType.PERMISSION
            >>> handler.categorize_error(subprocess.CalledProcessError(1, 'nmap'))
            ErrorType.EXECUTION
        """
        error_msg = str(exception).lower()

        # Exception type mapping
        error_map = {
            FileNotFoundError: ErrorType.FILE,
            PermissionError: ErrorType.PERMISSION,
            IOError: ErrorType.FILE,
            ConnectionError: ErrorType.NETWORK,
            TimeoutError: ErrorType.NETWORK,
            json.JSONDecodeError: ErrorType.CONFIG,
            ValueError: ErrorType.INPUT,
            KeyError: ErrorType.CONFIG,
            subprocess.CalledProcessError: ErrorType.EXECUTION,
            subprocess.TimeoutExpired: ErrorType.NETWORK,
        }

        # Check specific exceptions before broad categories
        # TimeoutError and ConnectionError are OSError subclasses but should map to NETWORK
        if isinstance(exception, (TimeoutError, ConnectionError)):
            return ErrorType.NETWORK

        # Check exact type match
        exc_type = type(exception)
        if exc_type in error_map:
            # Special case: OSError can be file, permission, or network
            if isinstance(exception, OSError):
                if 'permission' in error_msg or (hasattr(exception, 'errno') and exception.errno == 13):
                    return ErrorType.PERMISSION
                elif 'network' in error_msg or 'connection' in error_msg:
                    return ErrorType.NETWORK
                return ErrorType.FILE
            return error_map[exc_type]

        # Check inheritance (for custom exceptions)
        for exc_class, error_type in error_map.items():
            if isinstance(exception, exc_class):
                return error_type

        # Message-based detection for uncategorized exceptions
        if 'permission' in error_msg or 'not permitted' in error_msg:
            return ErrorType.PERMISSION
        elif 'network' in error_msg or 'connection' in error_msg or 'unreachable' in error_msg:
            return ErrorType.NETWORK
        elif 'file' in error_msg or 'directory' in error_msg or 'no such' in error_msg:
            return ErrorType.FILE
        elif 'config' in error_msg or 'json' in error_msg:
            return ErrorType.CONFIG
        elif 'invalid' in error_msg or 'expected' in error_msg:
            return ErrorType.INPUT

        # Default to EXECUTION for unknown errors
        return ErrorType.EXECUTION

    def get_suggestions(self, error_type: ErrorType, message: str = "") -> List[str]:
        """
        Get context-aware suggestions based on error type with OSCP-specific enhancements

        Args:
            error_type: ErrorType enum
            message: Original error message for context

        Returns:
            List of actionable suggestion strings
        """
        message_lower = message.lower()

        # Check for OSCP-specific patterns first
        for pattern_name, pattern_info in self.OSCP_PATTERNS.items():
            if any(keyword in message_lower for keyword in pattern_info['keywords']):
                return pattern_info['suggestions']

        # Fall back to general suggestions by error type
        suggestions = []

        if error_type == ErrorType.FILE:
            if "config" in message.lower() or ".json" in message.lower():
                suggestions.append("Check if file exists: ls -la ~/.crack/config.json")
                suggestions.append("Initialize config: crack track --init")
                suggestions.append("Verify file permissions: chmod 644 ~/.crack/config.json")
            elif "target" in message.lower() or "profile" in message.lower():
                suggestions.append("Check if target profile exists: ls ~/.crack/targets/")
                suggestions.append("Create new profile: crack track new <TARGET>")
            else:
                suggestions.append("Verify file path exists and is readable")
                suggestions.append("Check file permissions: ls -la <file_path>")
                suggestions.append("Check current directory: pwd")

        elif error_type == ErrorType.PERMISSION:
            suggestions.append("Check file/directory permissions: ls -la")
            suggestions.append("Try running with sudo if appropriate: sudo crack track ...")
            suggestions.append("Verify file ownership: ls -l <file_path>")
            suggestions.append("Fix permissions: chmod 644 <file> or chmod 755 <dir>")

        elif error_type == ErrorType.NETWORK:
            suggestions.append("Check network connectivity: ping <target>")
            suggestions.append("Verify firewall rules: sudo iptables -L")
            suggestions.append("Check if service is running: nc -zv <target> <port>")
            suggestions.append("Verify DNS resolution: nslookup <target>")

        elif error_type == ErrorType.CONFIG:
            if "json" in message.lower():
                suggestions.append("File may be corrupted - delete and retry")
                suggestions.append("Backup old config: mv ~/.crack/config.json ~/.crack/config.json.bak")
                suggestions.append("Reinitialize: crack track --init")
            else:
                suggestions.append("Check config file syntax: cat ~/.crack/config.json")
                suggestions.append("Verify required fields are present")
                suggestions.append("Reset to defaults: crack track --init --force")

        elif error_type == ErrorType.INPUT:
            suggestions.append("Check input format and try again")
            suggestions.append("See help for valid options: crack track --help")
            suggestions.append("Use quotes for strings with spaces")

        elif error_type == ErrorType.EXECUTION:
            if "command not found" in message.lower():
                suggestions.append("Install missing tool: sudo apt install <tool>")
                suggestions.append("Check PATH: echo $PATH")
                suggestions.append("Verify tool is installed: which <command>")
            else:
                suggestions.append("Check command syntax and arguments")
                suggestions.append("Try running command manually for debugging")
                suggestions.append("Check debug logs: ls -la .debug_logs/")

        return suggestions

    def format_error_panel(
        self,
        error_type: ErrorType,
        message: str,
        suggestions: List[str]
    ) -> Panel:
        """
        Create Rich Panel for error display

        Args:
            error_type: ErrorType enum
            message: Error message text
            suggestions: List of actionable suggestions

        Returns:
            Rich Panel with formatted error content
        """
        content = Text()

        # Error icon and type header
        error_icons = {
            ErrorType.FILE: "📁",
            ErrorType.PERMISSION: "🔒",
            ErrorType.NETWORK: "🌐",
            ErrorType.CONFIG: "⚙️",
            ErrorType.INPUT: "⌨️",
            ErrorType.EXECUTION: "⚠️"
        }
        icon = error_icons.get(error_type, "❌")

        content.append(f"{icon} {error_type.value} ERROR\n", style="bold red")
        content.append("─" * 70 + "\n", style="dim red")
        content.append("\n")

        # Error message
        content.append("Error Details:\n", style="bold yellow")
        content.append(f"  {message}\n", style="white")
        content.append("\n")

        # Suggestions section
        if suggestions:
            content.append("Suggested Fixes:\n", style="bold cyan")
            for idx, suggestion in enumerate(suggestions, 1):
                # Check if suggestion contains a command (has ':' separator)
                if ':' in suggestion:
                    desc, cmd = suggestion.split(':', 1)
                    content.append(f"  {idx}. {desc}:\n", style="yellow")
                    content.append(f"     {cmd.strip()}\n", style="bright_black")
                else:
                    content.append(f"  {idx}. {suggestion}\n", style="yellow")
            content.append("\n")

        # Help footer
        content.append("Press Enter to continue...", style="dim cyan")

        # Panel styling based on error type
        border_color = "red" if error_type in [ErrorType.EXECUTION, ErrorType.PERMISSION] else "yellow"

        return Panel(
            content,
            title=f"[bold red]ERROR[/bold red]",
            border_style=border_color,
            box=box.HEAVY
        )

    def show_error(
        self,
        error_type: ErrorType,
        message: str,
        suggestions: Optional[List[str]] = None
    ):
        """
        Display formatted error panel in TUI

        Args:
            error_type: ErrorType enum
            message: Error message text
            suggestions: Optional list of suggestions (auto-generated if None)

        Examples:
            >>> handler.show_error(ErrorType.FILE, "Config not found")
            >>> handler.show_error(
            ...     ErrorType.NETWORK,
            ...     "Connection refused",
            ...     ["Check firewall", "Verify service is running"]
            ... )
        """
        # Auto-generate suggestions if not provided
        if suggestions is None:
            suggestions = self.get_suggestions(error_type, message)

        # Log error if debug logger available
        if self.debug_logger:
            self.debug_logger.error(
                f"{error_type.value} error: {message}",
                suggestions_count=len(suggestions)
            )

        # Store in error history (trim to max_history)
        self._error_history.append({
            'type': error_type.value,
            'message': message,
            'suggestions': suggestions,
            'timestamp': self._get_timestamp()
        })

        # Trim to max_history (FIFO)
        if len(self._error_history) > self.max_history:
            self._error_history = self._error_history[-self.max_history:]

        # Display error panel
        panel = self.format_error_panel(error_type, message, suggestions)
        self.console.print("\n")
        self.console.print(panel)
        self.console.print("\n")

    def log_error(self, error: Exception, context: str = ""):
        """
        Log error to debug log with context

        Args:
            error: Exception instance
            context: Optional context string (e.g., "task execution", "file import")

        Examples:
            >>> try:
            ...     open('/nonexistent/file')
            ... except Exception as e:
            ...     handler.log_error(e, context="config loading")
        """
        error_type = self.categorize_error(error)

        if self.debug_logger:
            self.debug_logger.section("ERROR LOGGED")
            self.debug_logger.error(f"Type: {error_type.value}")
            self.debug_logger.error(f"Exception: {type(error).__name__}")
            self.debug_logger.error(f"Message: {str(error)}")
            if context:
                self.debug_logger.error(f"Context: {context}")

            # Log suggestions
            suggestions = self.get_suggestions(error_type, str(error))
            if suggestions:
                self.debug_logger.info(f"Auto-generated {len(suggestions)} suggestions")
                for idx, suggestion in enumerate(suggestions, 1):
                    self.debug_logger.info(f"  {idx}. {suggestion}")

    def handle_exception(
        self,
        exception: Exception,
        context: str = "",
        custom_suggestions: Optional[List[str]] = None
    ):
        """
        Complete exception handling workflow

        Automatically categorizes, logs, and displays error with suggestions.

        Args:
            exception: Python exception instance
            context: Optional context description
            custom_suggestions: Override auto-generated suggestions

        Examples:
            >>> try:
            ...     with open('/etc/passwd', 'w') as f:
            ...         f.write('hack')
            ... except Exception as e:
            ...     handler.handle_exception(e, context="privilege escalation attempt")
        """
        # Categorize error
        error_type = self.categorize_error(exception)

        # Log to debug
        self.log_error(exception, context)

        # Build message
        message = str(exception)
        if context:
            message = f"{context}: {message}"

        # Show error panel
        self.show_error(error_type, message, custom_suggestions)

    def get_error_history(self) -> List[Dict[str, Any]]:
        """
        Get history of all errors in this session

        Returns:
            List of error dictionaries with type, message, suggestions, timestamp
        """
        return self._error_history.copy()

    def clear_error_history(self):
        """Clear error history (useful for testing or session reset)"""
        self._error_history.clear()
        if self.debug_logger:
            self.debug_logger.info("Error history cleared")

    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp string"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# Common error patterns with specific handlers
class CommonErrors:
    """Pre-defined handlers for common error scenarios"""

    @staticmethod
    def file_not_found(handler: ErrorHandler, filepath: str):
        """Handle file not found error"""
        handler.show_error(
            ErrorType.FILE,
            f"File not found: {filepath}",
            [
                f"Check file exists: ls -la {filepath}",
                f"Verify path is correct: pwd",
                "Check spelling and try again"
            ]
        )

    @staticmethod
    def permission_denied(handler: ErrorHandler, filepath: str):
        """Handle permission denied error"""
        handler.show_error(
            ErrorType.PERMISSION,
            f"Permission denied: {filepath}",
            [
                f"Check permissions: ls -la {filepath}",
                f"Fix permissions: chmod 644 {filepath}",
                "Try running with sudo if appropriate"
            ]
        )

    @staticmethod
    def config_corrupted(handler: ErrorHandler, config_path: str = "~/.crack/config.json"):
        """Handle corrupted config file"""
        handler.show_error(
            ErrorType.CONFIG,
            "Configuration file is corrupted or invalid JSON",
            [
                f"Backup current: mv {config_path} {config_path}.bak",
                "Reinitialize config: crack track --init",
                f"Manual inspection: cat {config_path}"
            ]
        )

    @staticmethod
    def network_unreachable(handler: ErrorHandler, target: str):
        """Handle network unreachable error"""
        handler.show_error(
            ErrorType.NETWORK,
            f"Cannot reach target: {target}",
            [
                f"Test connectivity: ping {target}",
                f"Check routing: traceroute {target}",
                "Verify firewall rules: sudo iptables -L",
                f"DNS check: nslookup {target}"
            ]
        )

    @staticmethod
    def command_not_found(handler: ErrorHandler, command: str):
        """Handle command not found error"""
        handler.show_error(
            ErrorType.EXECUTION,
            f"Command not found: {command}",
            [
                f"Install tool: sudo apt install {command}",
                f"Check if installed: which {command}",
                "Update PATH: echo $PATH",
                "Search packages: apt search {command}"
            ]
        )
