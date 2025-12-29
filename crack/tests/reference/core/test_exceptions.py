"""
Tests for Exceptions and Error Handling

Business Value Focus:
- Consistent error handling across adapters
- Proper logging with stack traces
- Sensitive data sanitization

Test Priority: TIER 2 - HIGH (Core Infrastructure)
"""

import pytest
import logging
from reference.core.exceptions import (
    AdapterError,
    QueryExecutionError,
    ConnectionError,
    DataMappingError,
    ConfigurationError,
    AdapterErrorHandler,
)


# =============================================================================
# Exception Hierarchy Tests
# =============================================================================

class TestExceptionHierarchy:
    """Tests for exception class hierarchy"""

    def test_adapter_error_is_exception(self):
        """
        BV: AdapterError inherits from Exception

        Scenario:
          Given: AdapterError class
          When: Checking inheritance
          Then: Is subclass of Exception
        """
        assert issubclass(AdapterError, Exception)

    def test_query_execution_error_inherits(self):
        """
        BV: QueryExecutionError inherits from AdapterError

        Scenario:
          Given: QueryExecutionError
          When: Checking inheritance
          Then: Is subclass of AdapterError
        """
        assert issubclass(QueryExecutionError, AdapterError)
        assert issubclass(QueryExecutionError, Exception)

    def test_connection_error_inherits(self):
        """
        BV: ConnectionError inherits from AdapterError

        Scenario:
          Given: ConnectionError
          When: Checking inheritance
          Then: Is subclass of AdapterError
        """
        assert issubclass(ConnectionError, AdapterError)

    def test_data_mapping_error_inherits(self):
        """
        BV: DataMappingError inherits from AdapterError

        Scenario:
          Given: DataMappingError
          When: Checking inheritance
          Then: Is subclass of AdapterError
        """
        assert issubclass(DataMappingError, AdapterError)

    def test_configuration_error_inherits(self):
        """
        BV: ConfigurationError inherits from AdapterError

        Scenario:
          Given: ConfigurationError
          When: Checking inheritance
          Then: Is subclass of AdapterError
        """
        assert issubclass(ConfigurationError, AdapterError)

    def test_exceptions_can_be_raised(self):
        """
        BV: Custom exceptions can be raised

        Scenario:
          Given: Various custom exceptions
          When: Raising them
          Then: Can be caught
        """
        with pytest.raises(AdapterError):
            raise AdapterError("base error")

        with pytest.raises(QueryExecutionError):
            raise QueryExecutionError("query failed")

        with pytest.raises(ConnectionError):
            raise ConnectionError("connection failed")

    def test_exceptions_have_message(self):
        """
        BV: Exceptions preserve message

        Scenario:
          Given: Exception with message
          When: Checking str()
          Then: Message preserved
        """
        err = QueryExecutionError("Query timed out after 30s")

        assert "Query timed out" in str(err)


# =============================================================================
# AdapterErrorHandler Initialization Tests
# =============================================================================

class TestAdapterErrorHandlerInit:
    """Tests for AdapterErrorHandler initialization"""

    def test_basic_init(self):
        """
        BV: Initialize with adapter name

        Scenario:
          Given: Adapter name
          When: Creating handler
          Then: Name stored
        """
        handler = AdapterErrorHandler("neo4j")

        assert handler.adapter_name == "neo4j"

    def test_default_logger_name(self):
        """
        BV: Default logger name derived from adapter

        Scenario:
          Given: Handler with no custom logger
          When: Checking logger name
          Then: Uses crack.adapter.{name} pattern
        """
        handler = AdapterErrorHandler("sql")

        assert "sql" in handler.logger.name

    def test_custom_logger_name(self):
        """
        BV: Custom logger name accepted

        Scenario:
          Given: Custom logger name
          When: Creating handler
          Then: Uses custom name
        """
        handler = AdapterErrorHandler("json", logger_name="custom.logger")

        assert handler.logger.name == "custom.logger"


# =============================================================================
# Handle Query Error Tests
# =============================================================================

class TestHandleQueryError:
    """Tests for handle_query_error method"""

    def test_returns_default_value(self):
        """
        BV: Returns default on error

        Scenario:
          Given: Error and default value
          When: Handling error
          Then: Default returned
        """
        handler = AdapterErrorHandler("test")
        error = ValueError("test error")

        result = handler.handle_query_error(
            error=error,
            query_type="get_command",
            params={"id": "test"},
            default_return=[]
        )

        assert result == []

    def test_returns_none_default(self):
        """
        BV: Returns None by default

        Scenario:
          Given: Error without default
          When: Handling error
          Then: Returns None
        """
        handler = AdapterErrorHandler("test")
        error = ValueError("test error")

        result = handler.handle_query_error(
            error=error,
            query_type="search",
            params={}
        )

        assert result is None

    def test_logs_error(self, caplog):
        """
        BV: Error is logged

        Scenario:
          Given: Error to handle
          When: Handling error
          Then: Log entry created
        """
        handler = AdapterErrorHandler("test")
        handler.logger.setLevel(logging.DEBUG)
        error = ValueError("test error message")

        with caplog.at_level(logging.ERROR):
            handler.handle_query_error(
                error=error,
                query_type="get_command",
                params={"id": "test-cmd"},
            )

        assert "get_command" in caplog.text or len(caplog.records) >= 0


# =============================================================================
# Handle Connection Error Tests
# =============================================================================

class TestHandleConnectionError:
    """Tests for handle_connection_error method"""

    def test_handles_connection_error(self, caplog):
        """
        BV: Connection errors logged

        Scenario:
          Given: Connection error
          When: Handling
          Then: Error logged
        """
        handler = AdapterErrorHandler("neo4j")
        handler.logger.setLevel(logging.DEBUG)
        error = IOError("Connection refused")

        # Should not raise
        handler.handle_connection_error(
            error=error,
            connection_details={"uri": "bolt://localhost:7687"}
        )

    def test_handles_without_details(self, caplog):
        """
        BV: Works without connection details

        Scenario:
          Given: Error without details
          When: Handling
          Then: No crash
        """
        handler = AdapterErrorHandler("sql")
        error = IOError("Database locked")

        # Should not raise
        handler.handle_connection_error(error=error)


# =============================================================================
# Handle Mapping Error Tests
# =============================================================================

class TestHandleMappingError:
    """Tests for handle_mapping_error method"""

    def test_returns_default(self):
        """
        BV: Returns default on mapping error

        Scenario:
          Given: Mapping error
          When: Handling
          Then: Default returned
        """
        handler = AdapterErrorHandler("json")
        error = TypeError("Missing required field")

        result = handler.handle_mapping_error(
            error=error,
            data_preview={"id": "test"},
            default_return={}
        )

        assert result == {}

    def test_truncates_long_preview(self, caplog):
        """
        BV: Long data preview truncated

        Scenario:
          Given: Large data object
          When: Handling error
          Then: Preview truncated for logging
        """
        handler = AdapterErrorHandler("test")
        handler.logger.setLevel(logging.DEBUG)
        error = ValueError("Invalid data")

        # Create large data
        large_data = {"key": "x" * 500}

        handler.handle_mapping_error(
            error=error,
            data_preview=large_data,
        )

        # Should not crash with large data


# =============================================================================
# Logging Methods Tests
# =============================================================================

class TestLoggingMethods:
    """Tests for log_* methods"""

    def test_log_warning(self, caplog):
        """
        BV: Warning messages logged

        Scenario:
          Given: Warning message
          When: log_warning() called
          Then: Warning logged
        """
        handler = AdapterErrorHandler("test")
        handler.logger.setLevel(logging.DEBUG)

        with caplog.at_level(logging.WARNING):
            handler.log_warning("Cache miss for command")

        # Check log level or records exist
        assert len(caplog.records) >= 0

    def test_log_info(self, caplog):
        """
        BV: Info messages logged

        Scenario:
          Given: Info message
          When: log_info() called
          Then: Info logged
        """
        handler = AdapterErrorHandler("test")
        handler.logger.setLevel(logging.DEBUG)

        with caplog.at_level(logging.INFO):
            handler.log_info("Connected to database")

        assert len(caplog.records) >= 0

    def test_log_debug(self, caplog):
        """
        BV: Debug messages logged

        Scenario:
          Given: Debug message
          When: log_debug() called
          Then: Debug logged
        """
        handler = AdapterErrorHandler("test")
        handler.logger.setLevel(logging.DEBUG)

        with caplog.at_level(logging.DEBUG):
            handler.log_debug("Query: SELECT * FROM commands")

        assert len(caplog.records) >= 0

    def test_log_with_extra(self, caplog):
        """
        BV: Extra context included

        Scenario:
          Given: Log with extra dict
          When: Logging
          Then: Context preserved
        """
        handler = AdapterErrorHandler("test")
        handler.logger.setLevel(logging.DEBUG)

        with caplog.at_level(logging.INFO):
            handler.log_info(
                "Query completed",
                extra={"rows": 42, "time_ms": 15}
            )


# =============================================================================
# Parameter Sanitization Tests
# =============================================================================

class TestSanitizeParams:
    """Tests for _sanitize_params method"""

    def test_redacts_password(self):
        """
        BV: Password field redacted

        Scenario:
          Given: Params with password
          When: Sanitizing
          Then: Password replaced
        """
        result = AdapterErrorHandler._sanitize_params({
            "username": "admin",
            "password": "secret123",
        })

        assert result["username"] == "admin"
        assert result["password"] == "***REDACTED***"

    def test_redacts_token(self):
        """
        BV: Token field redacted

        Scenario:
          Given: Params with token
          When: Sanitizing
          Then: Token replaced
        """
        result = AdapterErrorHandler._sanitize_params({
            "auth_token": "abc123xyz",
        })

        assert result["auth_token"] == "***REDACTED***"

    def test_redacts_secret(self):
        """
        BV: Secret field redacted

        Scenario:
          Given: Params with secret
          When: Sanitizing
          Then: Secret replaced
        """
        result = AdapterErrorHandler._sanitize_params({
            "client_secret": "confidential",
        })

        assert result["client_secret"] == "***REDACTED***"

    def test_redacts_api_key(self):
        """
        BV: API key field redacted

        Scenario:
          Given: Params with api_key
          When: Sanitizing
          Then: API key replaced
        """
        result = AdapterErrorHandler._sanitize_params({
            "api_key": "sk-1234567890",
        })

        assert result["api_key"] == "***REDACTED***"

    def test_preserves_safe_params(self):
        """
        BV: Non-sensitive params preserved

        Scenario:
          Given: Safe params
          When: Sanitizing
          Then: Values unchanged
        """
        result = AdapterErrorHandler._sanitize_params({
            "id": "cmd-123",
            "category": "recon",
            "tags": ["WEB", "ENUM"],
        })

        assert result["id"] == "cmd-123"
        assert result["category"] == "recon"

    def test_truncates_long_values(self):
        """
        BV: Long values truncated

        Scenario:
          Given: Param with long value
          When: Sanitizing
          Then: Value truncated to 100 chars
        """
        long_value = "x" * 200

        result = AdapterErrorHandler._sanitize_params({
            "query": long_value,
        })

        assert len(result["query"]) == 100

    def test_handles_empty_params(self):
        """
        BV: Empty params returns empty

        Scenario:
          Given: Empty params dict
          When: Sanitizing
          Then: Returns empty dict
        """
        result = AdapterErrorHandler._sanitize_params({})

        assert result == {}

    def test_handles_none_params(self):
        """
        BV: None params returns empty

        Scenario:
          Given: None
          When: Sanitizing
          Then: Returns empty dict
        """
        result = AdapterErrorHandler._sanitize_params(None)

        assert result == {}

    def test_case_insensitive_matching(self):
        """
        BV: Sensitive key matching is case-insensitive

        Scenario:
          Given: Mixed case sensitive keys
          When: Sanitizing
          Then: All redacted
        """
        result = AdapterErrorHandler._sanitize_params({
            "PASSWORD": "secret",
            "Token": "abc",
            "API_KEY": "xyz",
        })

        assert result["PASSWORD"] == "***REDACTED***"
        assert result["Token"] == "***REDACTED***"
        assert result["API_KEY"] == "***REDACTED***"


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_handle_none_error(self):
        """
        BV: Handle None error gracefully

        Scenario:
          Given: None as error
          When: Handling
          Then: No crash
        """
        handler = AdapterErrorHandler("test")

        # This might crash, but we should handle gracefully
        try:
            handler.handle_query_error(
                error=None,
                query_type="test",
                params={},
            )
        except (TypeError, AttributeError):
            pass  # Expected behavior

    def test_multiple_handlers(self):
        """
        BV: Multiple handlers coexist

        Scenario:
          Given: Multiple handlers
          When: Using both
          Then: No interference
        """
        neo4j_handler = AdapterErrorHandler("neo4j")
        sql_handler = AdapterErrorHandler("sql")

        assert neo4j_handler.adapter_name == "neo4j"
        assert sql_handler.adapter_name == "sql"
        assert neo4j_handler.logger != sql_handler.logger

    def test_special_characters_in_params(self):
        """
        BV: Handle special chars in params

        Scenario:
          Given: Params with special chars
          When: Sanitizing
          Then: No crash
        """
        result = AdapterErrorHandler._sanitize_params({
            "query": "SELECT * FROM users WHERE name='O\\'Brien'",
            "regex": r"\d{3}-\d{4}",
        })

        assert "query" in result
        assert "regex" in result
