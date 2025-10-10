"""
Test Error Handler Component

Validates error categorization, suggestion generation, and display formatting.
"""

import pytest
import subprocess
import json
from unittest.mock import Mock
from rich.console import Console

from crack.track.interactive.components.error_handler import (
    ErrorHandler,
    ErrorType,
    CommonErrors
)


class TestErrorCategorization:
    """Test automatic error categorization"""

    def test_categorize_file_not_found(self):
        """FileNotFoundError -> FILE"""
        handler = ErrorHandler()
        error = FileNotFoundError("config.json not found")
        assert handler.categorize_error(error) == ErrorType.FILE

    def test_categorize_permission_error(self):
        """PermissionError -> PERMISSION"""
        handler = ErrorHandler()
        error = PermissionError("Permission denied")
        assert handler.categorize_error(error) == ErrorType.PERMISSION

    def test_categorize_value_error(self):
        """ValueError -> INPUT"""
        handler = ErrorHandler()
        error = ValueError("Invalid format")
        assert handler.categorize_error(error) == ErrorType.INPUT

    def test_categorize_subprocess_error(self):
        """subprocess.CalledProcessError -> EXECUTION"""
        handler = ErrorHandler()
        error = subprocess.CalledProcessError(1, 'nmap')
        assert handler.categorize_error(error) == ErrorType.EXECUTION

    def test_categorize_connection_error(self):
        """ConnectionError -> NETWORK"""
        handler = ErrorHandler()
        error = ConnectionError("Connection refused")
        assert handler.categorize_error(error) == ErrorType.NETWORK

    def test_categorize_timeout_error(self):
        """TimeoutError -> NETWORK"""
        handler = ErrorHandler()
        error = TimeoutError("Operation timed out")
        assert handler.categorize_error(error) == ErrorType.NETWORK

    def test_categorize_json_decode_error(self):
        """json.JSONDecodeError -> CONFIG"""
        handler = ErrorHandler()
        error = json.JSONDecodeError("Invalid JSON", '{"bad": json', 0)
        assert handler.categorize_error(error) == ErrorType.CONFIG

    def test_categorize_key_error(self):
        """KeyError -> CONFIG"""
        handler = ErrorHandler()
        error = KeyError("missing_key")
        assert handler.categorize_error(error) == ErrorType.CONFIG

    def test_categorize_oserror_permission(self):
        """OSError with permission message -> PERMISSION"""
        handler = ErrorHandler()
        error = OSError("permission denied")
        assert handler.categorize_error(error) == ErrorType.PERMISSION

    def test_categorize_oserror_network(self):
        """OSError with network message -> NETWORK"""
        handler = ErrorHandler()
        error = OSError("network unreachable")
        assert handler.categorize_error(error) == ErrorType.NETWORK

    def test_categorize_oserror_default(self):
        """OSError without specific keywords -> FILE"""
        handler = ErrorHandler()
        error = OSError("Generic OS error")
        assert handler.categorize_error(error) == ErrorType.FILE

    def test_categorize_unknown_exception(self):
        """Unknown exception -> EXECUTION"""
        handler = ErrorHandler()
        error = RuntimeError("Unknown error")
        assert handler.categorize_error(error) == ErrorType.EXECUTION


class TestOSCPPatterns:
    """Test OSCP-specific error pattern detection"""

    def test_oscp_nmap_pattern(self):
        """nmap command not found -> OSCP suggestions"""
        handler = ErrorHandler()
        suggestions = handler.get_suggestions(
            ErrorType.EXECUTION,
            "nmap: command not found"
        )
        assert any("sudo apt install nmap" in s for s in suggestions)
        assert any("OSCP" in s for s in suggestions)

    def test_oscp_permission_pattern(self):
        """Permission denied with raw socket -> OSCP suggestions"""
        handler = ErrorHandler()
        suggestions = handler.get_suggestions(
            ErrorType.PERMISSION,
            "raw socket operation not permitted"
        )
        assert any("sudo" in s for s in suggestions)
        assert any("OSCP" in s for s in suggestions)

    def test_oscp_network_unreachable_pattern(self):
        """Network unreachable -> OSCP VPN suggestions"""
        handler = ErrorHandler()
        suggestions = handler.get_suggestions(
            ErrorType.NETWORK,
            "Network is unreachable: no route to host"
        )
        assert any("tun0" in s for s in suggestions)
        assert any("OSCP" in s for s in suggestions)

    def test_oscp_timeout_pattern(self):
        """Timeout error -> OSCP timing suggestions"""
        handler = ErrorHandler()
        suggestions = handler.get_suggestions(
            ErrorType.NETWORK,
            "Operation timed out"
        )
        assert any("-T" in s for s in suggestions)
        assert any("OSCP" in s for s in suggestions)

    def test_oscp_wordlist_pattern(self):
        """Wordlist not found -> OSCP wordlist suggestions"""
        handler = ErrorHandler()
        suggestions = handler.get_suggestions(
            ErrorType.FILE,
            "/usr/share/wordlists/rockyou.txt not found"
        )
        assert any("wordlists" in s for s in suggestions)
        assert any("OSCP" in s for s in suggestions)


class TestSuggestionGeneration:
    """Test suggestion generation for different error types"""

    def test_file_error_suggestions(self):
        """FILE error generates file-related suggestions"""
        handler = ErrorHandler()
        suggestions = handler.get_suggestions(ErrorType.FILE, "file not found")
        assert len(suggestions) > 0
        assert any("ls" in s.lower() for s in suggestions)

    def test_permission_error_suggestions(self):
        """PERMISSION error generates permission-related suggestions"""
        handler = ErrorHandler()
        suggestions = handler.get_suggestions(ErrorType.PERMISSION, "denied")
        assert len(suggestions) > 0
        assert any("chmod" in s.lower() or "sudo" in s.lower() for s in suggestions)

    def test_network_error_suggestions(self):
        """NETWORK error generates network-related suggestions"""
        handler = ErrorHandler()
        suggestions = handler.get_suggestions(ErrorType.NETWORK, "unreachable")
        # Should get OSCP VPN suggestions
        assert len(suggestions) > 0
        assert any("ping" in s.lower() or "tun0" in s.lower() for s in suggestions)

    def test_config_error_suggestions(self):
        """CONFIG error generates config-related suggestions"""
        handler = ErrorHandler()
        suggestions = handler.get_suggestions(ErrorType.CONFIG, "invalid json")
        assert len(suggestions) > 0
        assert any("config" in s.lower() or "json" in s.lower() for s in suggestions)

    def test_input_error_suggestions(self):
        """INPUT error generates input-related suggestions"""
        handler = ErrorHandler()
        suggestions = handler.get_suggestions(ErrorType.INPUT, "invalid input")
        assert len(suggestions) > 0
        assert any("help" in s.lower() or "format" in s.lower() for s in suggestions)

    def test_execution_error_suggestions(self):
        """EXECUTION error generates execution-related suggestions"""
        handler = ErrorHandler()
        suggestions = handler.get_suggestions(ErrorType.EXECUTION, "failed")
        assert len(suggestions) > 0
        assert any("command" in s.lower() or "debug" in s.lower() for s in suggestions)


class TestErrorHistory:
    """Test error history tracking"""

    def test_error_history_adds_entry(self):
        """show_error adds entry to history"""
        handler = ErrorHandler(max_history=10)
        handler.show_error(ErrorType.FILE, "Test error")

        history = handler.get_error_history()
        assert len(history) == 1
        assert history[0]['type'] == 'FILE'
        assert history[0]['message'] == 'Test error'

    def test_error_history_respects_max(self):
        """Error history respects max_history limit"""
        handler = ErrorHandler(max_history=3)

        # Add 5 errors
        for i in range(5):
            handler.show_error(ErrorType.EXECUTION, f"Error {i+1}")

        history = handler.get_error_history()
        assert len(history) == 3  # Should only keep last 3
        assert history[0]['message'] == 'Error 3'  # Oldest kept
        assert history[2]['message'] == 'Error 5'  # Newest

    def test_error_history_clear(self):
        """clear_error_history removes all entries"""
        handler = ErrorHandler()
        handler.show_error(ErrorType.FILE, "Test error")
        handler.clear_error_history()

        history = handler.get_error_history()
        assert len(history) == 0


class TestCommonErrors:
    """Test CommonErrors helper functions"""

    def test_file_not_found_helper(self):
        """CommonErrors.file_not_found displays correctly"""
        handler = ErrorHandler()
        # Should not raise exception
        CommonErrors.file_not_found(handler, "/etc/test.conf")

        history = handler.get_error_history()
        assert len(history) == 1
        assert history[0]['type'] == 'FILE'

    def test_permission_denied_helper(self):
        """CommonErrors.permission_denied displays correctly"""
        handler = ErrorHandler()
        CommonErrors.permission_denied(handler, "/etc/shadow")

        history = handler.get_error_history()
        assert len(history) == 1
        assert history[0]['type'] == 'PERMISSION'

    def test_config_corrupted_helper(self):
        """CommonErrors.config_corrupted displays correctly"""
        handler = ErrorHandler()
        CommonErrors.config_corrupted(handler)

        history = handler.get_error_history()
        assert len(history) == 1
        assert history[0]['type'] == 'CONFIG'

    def test_network_unreachable_helper(self):
        """CommonErrors.network_unreachable displays correctly"""
        handler = ErrorHandler()
        CommonErrors.network_unreachable(handler, "192.168.45.100")

        history = handler.get_error_history()
        assert len(history) == 1
        assert history[0]['type'] == 'NETWORK'

    def test_command_not_found_helper(self):
        """CommonErrors.command_not_found displays correctly"""
        handler = ErrorHandler()
        CommonErrors.command_not_found(handler, "gobuster")

        history = handler.get_error_history()
        assert len(history) == 1
        assert history[0]['type'] == 'EXECUTION'


class TestHandleException:
    """Test complete exception handling workflow"""

    def test_handle_exception_categorizes(self):
        """handle_exception auto-categorizes exception"""
        handler = ErrorHandler()
        error = FileNotFoundError("config.json")

        handler.handle_exception(error)

        history = handler.get_error_history()
        assert len(history) == 1
        assert history[0]['type'] == 'FILE'

    def test_handle_exception_with_context(self):
        """handle_exception includes context in message"""
        handler = ErrorHandler()
        error = PermissionError("denied")

        handler.handle_exception(error, context="loading config")

        history = handler.get_error_history()
        assert "loading config" in history[0]['message']

    def test_handle_exception_custom_suggestions(self):
        """handle_exception accepts custom suggestions"""
        handler = ErrorHandler()
        error = ValueError("bad input")
        custom = ["Try again", "Check format"]

        handler.handle_exception(error, custom_suggestions=custom)

        history = handler.get_error_history()
        assert history[0]['suggestions'] == custom


class TestDebugLoggerIntegration:
    """Test integration with debug logger"""

    def test_logs_to_debug_logger(self):
        """Error handler logs to debug logger if provided"""
        mock_logger = Mock()
        handler = ErrorHandler(debug_logger=mock_logger)

        handler.show_error(ErrorType.FILE, "test error")

        # Should have called logger.error()
        assert mock_logger.error.called

    def test_log_error_method(self):
        """log_error method logs to debug logger"""
        mock_logger = Mock()
        handler = ErrorHandler(debug_logger=mock_logger)

        error = FileNotFoundError("test")
        handler.log_error(error, context="testing")

        # Should have called logger methods
        assert mock_logger.section.called
        assert mock_logger.error.called


class TestErrorDisplay:
    """Test error panel formatting"""

    def test_format_error_panel_returns_panel(self):
        """format_error_panel returns Rich Panel"""
        handler = ErrorHandler()
        panel = handler.format_error_panel(
            ErrorType.FILE,
            "Test error",
            ["Suggestion 1", "Suggestion 2"]
        )

        # Should be a Panel instance
        from rich.panel import Panel
        assert isinstance(panel, Panel)

    def test_show_error_with_custom_suggestions(self):
        """show_error uses custom suggestions when provided"""
        handler = ErrorHandler()
        custom = ["Custom suggestion 1", "Custom suggestion 2"]

        handler.show_error(ErrorType.FILE, "test", suggestions=custom)

        history = handler.get_error_history()
        assert history[0]['suggestions'] == custom

    def test_show_error_auto_generates_suggestions(self):
        """show_error auto-generates suggestions when None"""
        handler = ErrorHandler()

        handler.show_error(ErrorType.FILE, "test", suggestions=None)

        history = handler.get_error_history()
        assert len(history[0]['suggestions']) > 0  # Should have auto-generated


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
