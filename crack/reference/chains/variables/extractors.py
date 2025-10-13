"""
Variable extractors - Convert parsed findings to variables.

Provides mapping rules from finding types to variable names.
"""

from typing import Dict, Any, List, Optional


class VariableExtractor:
    """
    Extract variable candidates from parsed findings.

    Maps common finding types to standardized variable names for reuse
    across different chain types.
    """

    # Standard mapping: finding_key -> variable_name
    EXTRACTION_RULES = {
        # SUID findings
        'exploitable_binaries': '<TARGET_BIN>',
        # Web enumeration
        'directories': '<TARGET_DIR>',
        'files': '<TARGET_FILE>',
        # Network enumeration
        'open_ports': '<TARGET_PORT>',
        'services': '<TARGET_SERVICE>',
        # User enumeration
        'users': '<TARGET_USER>',
        'groups': '<TARGET_GROUP>',
        # SMB/Share enumeration
        'shares': '<TARGET_SHARE>',
        # Database enumeration
        'databases': '<TARGET_DB>',
        'tables': '<TARGET_TABLE>',
        'columns': '<TARGET_COLUMN>',
        # Credential findings
        'credentials': '<TARGET_CREDENTIAL>',
        # Vulnerability findings
        'vulnerabilities': '<TARGET_VULN>',
        'cves': '<TARGET_CVE>',
        # Docker findings
        'running_containers': '<CONTAINER_NAME>',
        'available_images': '<IMAGE_NAME>',
        'docker_socket_path': '<DOCKER_SOCKET>',
        # Capabilities findings
        'exploitable_capabilities': '<CAP_BINARY>',
        'capabilities': '<CAPABILITY>',
        # Sudo findings
        'nopasswd_commands': '<NOPASSWD_COMMANDS>',
        'gtfobins_binaries': '<SUDO_BINARY>',
        'env_keep_flags': '<ENV_KEEP_FLAGS>',
    }

    @classmethod
    def extract(cls, findings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert findings to variable candidates.

        Args:
            findings: Dictionary from parser (e.g., {'exploitable_binaries': [...]})

        Returns:
            Dictionary with:
            - Simple variables: {var_name: value}
            - Selection-required: {var_name: {'select_from': [options], 'prompt': str}}

        Note:
            Single-value findings are auto-resolved.
            Multi-value findings require user selection.
        """
        candidates = {}

        for finding_key, var_name in cls.EXTRACTION_RULES.items():
            if finding_key not in findings:
                continue

            values = findings[finding_key]

            # Handle different value types
            if isinstance(values, list):
                if len(values) == 0:
                    # Empty list - skip
                    continue
                elif len(values) == 1:
                    # Single option - auto-select
                    candidates[var_name] = cls._extract_value(values[0])
                else:
                    # Multiple options - require selection
                    candidates[var_name] = {
                        'select_from': [cls._extract_value(v) for v in values],
                        'prompt': cls._make_prompt(finding_key),
                    }
            elif isinstance(values, str):
                # Direct string value
                candidates[var_name] = values
            elif isinstance(values, dict):
                # Complex object - extract primary field
                primary_value = cls._extract_primary_field(values)
                if primary_value:
                    candidates[var_name] = primary_value

        return candidates

    @classmethod
    def _extract_value(cls, item: Any) -> str:
        """
        Extract string value from various types.

        Args:
            item: Finding item (string, dict, etc.)

        Returns:
            String representation
        """
        if isinstance(item, str):
            return item
        elif isinstance(item, dict):
            # Try common fields
            for field in ['path', 'name', 'value', 'id']:
                if field in item:
                    return str(item[field])
            # Fallback to first value
            if item:
                return str(next(iter(item.values())))
        return str(item)

    @classmethod
    def _extract_primary_field(cls, obj: Dict[str, Any]) -> Optional[str]:
        """
        Extract primary field from complex object.

        Args:
            obj: Dictionary object

        Returns:
            Primary field value or None
        """
        # Try common primary fields
        for field in ['path', 'name', 'value', 'id', 'address']:
            if field in obj:
                return str(obj[field])
        return None

    @classmethod
    def _make_prompt(cls, finding_key: str) -> str:
        """
        Generate user-friendly prompt for selection.

        Args:
            finding_key: Finding type key

        Returns:
            Prompt string
        """
        # Convert snake_case to Title Case
        display_name = finding_key.replace('_', ' ').title()
        return f"Select {display_name}:"

    @classmethod
    def add_rule(cls, finding_key: str, variable_name: str):
        """
        Add custom extraction rule.

        Args:
            finding_key: Key in findings dict
            variable_name: Target variable name

        Note:
            Allows chains to define custom extraction rules at runtime.
        """
        cls.EXTRACTION_RULES[finding_key] = variable_name

    @classmethod
    def remove_rule(cls, finding_key: str):
        """
        Remove extraction rule.

        Args:
            finding_key: Key to remove

        Note:
            Primarily for testing.
        """
        if finding_key in cls.EXTRACTION_RULES:
            del cls.EXTRACTION_RULES[finding_key]
