"""
Exceptions and Error Handling - Centralized error handling for adapters

This module provides consistent error handling, logging, and exception types
across all backend adapters, replacing inconsistent print statements with
proper logging that includes stack traces.
"""

import logging
from typing import Optional, Any, Dict


# Custom exception types for adapters
class AdapterError(Exception):
    """Base exception for all adapter errors"""
    pass


class QueryExecutionError(AdapterError):
    """Query execution failed"""
    pass


class ConnectionError(AdapterError):
    """Connection to backend failed"""
    pass


class DataMappingError(AdapterError):
    """Error mapping data to Command dataclass"""
    pass


class ConfigurationError(AdapterError):
    """Invalid configuration provided"""
    pass


class AdapterErrorHandler:
    """
    Centralized error handling for backend adapters

    Provides:
    - Consistent logging format across all adapters
    - Automatic stack trace capture
    - Structured error context (operation, params, error type)
    - Default return value handling
    """

    def __init__(self, adapter_name: str, logger_name: str = None):
        """
        Initialize error handler for an adapter

        Args:
            adapter_name: Name of adapter (e.g., 'neo4j', 'sql', 'json')
            logger_name: Optional custom logger name
        """
        self.adapter_name = adapter_name

        if logger_name is None:
            logger_name = f"crack.adapter.{adapter_name}"

        self.logger = logging.getLogger(logger_name)

        # Configure logging format if not already configured
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def handle_query_error(
        self,
        error: Exception,
        query_type: str,
        params: Dict[str, Any],
        default_return: Any = None
    ) -> Any:
        """
        Standard error handling for query execution

        Logs error with full context and returns default value.
        Preserves stack trace for debugging.

        Args:
            error: The exception that occurred
            query_type: Type of query (e.g., 'get_command', 'search')
            params: Query parameters (for debugging)
            default_return: Value to return on error

        Returns:
            default_return value

        Example:
            >>> handler = AdapterErrorHandler('neo4j')
            >>> try:
            ...     result = session.run(query)
            ... except ServiceUnavailable as e:
            ...     return handler.handle_query_error(
            ...         e, 'get_command', {'id': 'cmd-1'}, None
            ...     )
        """
        # Build error context
        context = {
            'adapter': self.adapter_name,
            'query_type': query_type,
            'params': self._sanitize_params(params),
            'error_type': type(error).__name__,
            'error_message': str(error)
        }

        # Log with full stack trace
        self.logger.error(
            f"Query failed: {query_type}",
            extra=context,
            exc_info=True  # Includes full stack trace
        )

        return default_return

    def handle_connection_error(
        self,
        error: Exception,
        connection_details: Dict[str, Any] = None
    ) -> None:
        """
        Handle connection failures

        Args:
            error: The connection exception
            connection_details: Optional connection info (URI, etc.)
        """
        context = {
            'adapter': self.adapter_name,
            'error_type': type(error).__name__,
            'error_message': str(error)
        }

        if connection_details:
            context.update(self._sanitize_params(connection_details))

        self.logger.error(
            f"{self.adapter_name.capitalize()} connection failed",
            extra=context,
            exc_info=True
        )

    def handle_mapping_error(
        self,
        error: Exception,
        data_preview: Dict[str, Any],
        default_return: Any = None
    ) -> Any:
        """
        Handle data mapping errors

        Args:
            error: The mapping exception
            data_preview: Sample of problematic data
            default_return: Value to return on error

        Returns:
            default_return value
        """
        context = {
            'adapter': self.adapter_name,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'data_preview': str(data_preview)[:200]  # Limit preview size
        }

        self.logger.error(
            "Data mapping failed",
            extra=context,
            exc_info=True
        )

        return default_return

    def log_warning(self, message: str, extra: Dict[str, Any] = None):
        """
        Log warning message

        Args:
            message: Warning message
            extra: Additional context
        """
        context = {'adapter': self.adapter_name}
        if extra:
            context.update(extra)

        self.logger.warning(message, extra=context)

    def log_info(self, message: str, extra: Dict[str, Any] = None):
        """
        Log info message

        Args:
            message: Info message
            extra: Additional context
        """
        context = {'adapter': self.adapter_name}
        if extra:
            context.update(extra)

        self.logger.info(message, extra=context)

    def log_debug(self, message: str, extra: Dict[str, Any] = None):
        """
        Log debug message

        Args:
            message: Debug message
            extra: Additional context
        """
        context = {'adapter': self.adapter_name}
        if extra:
            context.update(extra)

        self.logger.debug(message, extra=context)

    @staticmethod
    def _sanitize_params(params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize parameters for logging (remove sensitive data)

        Args:
            params: Original parameters

        Returns:
            Sanitized parameters dict
        """
        if not params:
            return {}

        sanitized = {}
        sensitive_keys = {'password', 'token', 'secret', 'api_key', 'auth'}

        for key, value in params.items():
            # Check if key contains sensitive keywords
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = '***REDACTED***'
            else:
                # Truncate long values
                str_value = str(value)
                sanitized[key] = str_value[:100] if len(str_value) > 100 else value

        return sanitized
