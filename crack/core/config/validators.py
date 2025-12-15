"""
Validation utilities for CRACK configuration variables

Provides regex patterns and validation functions for common data types
"""

import re
import ipaddress
from pathlib import Path
from typing import Optional, Tuple


class Validators:
    """Collection of validation methods for config variables"""

    # Regex patterns
    IPV4_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    CIDR_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')
    PORT_PATTERN = re.compile(r'^(\d{1,5})$')
    URL_PATTERN = re.compile(r'^https?://[^\s]+$')
    DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z]{2,})+$')
    HASH_32_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')  # LM, NTLM
    CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$')
    DATE_PATTERN = re.compile(r'^\d{4}-\d{2}-\d{2}$')
    HTTP_METHOD_PATTERN = re.compile(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$')

    @staticmethod
    def validate_ip(value: str) -> Tuple[bool, Optional[str]]:
        """
        Validate IPv4 address

        Returns:
            (is_valid, error_message)
        """
        if not value:
            return False, "IP address cannot be empty"

        if not Validators.IPV4_PATTERN.match(value):
            return False, f"Invalid IP format: {value}"

        try:
            ipaddress.IPv4Address(value)
            return True, None
        except ValueError:
            return False, f"Invalid IP address: {value}"

    @staticmethod
    def validate_cidr(value: str) -> Tuple[bool, Optional[str]]:
        """
        Validate CIDR notation (e.g., 192.168.1.0/24)

        Returns:
            (is_valid, error_message)
        """
        if not value:
            return False, "CIDR cannot be empty"

        if not Validators.CIDR_PATTERN.match(value):
            return False, f"Invalid CIDR format: {value}"

        try:
            ipaddress.IPv4Network(value, strict=False)
            return True, None
        except ValueError as e:
            return False, f"Invalid CIDR: {str(e)}"

    @staticmethod
    def validate_port(value: str) -> Tuple[bool, Optional[str]]:
        """
        Validate port number (1-65535)

        Returns:
            (is_valid, error_message)
        """
        if not value:
            return False, "Port cannot be empty"

        if not Validators.PORT_PATTERN.match(value):
            return False, f"Port must be numeric: {value}"

        try:
            port = int(value)
            if 1 <= port <= 65535:
                return True, None
            else:
                return False, f"Port must be between 1-65535: {port}"
        except ValueError:
            return False, f"Invalid port: {value}"

    @staticmethod
    def validate_url(value: str) -> Tuple[bool, Optional[str]]:
        """
        Validate URL (must start with http:// or https://)

        Returns:
            (is_valid, error_message)
        """
        if not value:
            return False, "URL cannot be empty"

        if not Validators.URL_PATTERN.match(value):
            return False, f"URL must start with http:// or https://: {value}"

        return True, None

    @staticmethod
    def validate_domain(value: str) -> Tuple[bool, Optional[str]]:
        """
        Validate domain name

        Returns:
            (is_valid, error_message)
        """
        if not value:
            return False, "Domain cannot be empty"

        if not Validators.DOMAIN_PATTERN.match(value):
            return False, f"Invalid domain format: {value}"

        return True, None

    @staticmethod
    def validate_path(value: str, must_exist: bool = False) -> Tuple[bool, Optional[str]]:
        """
        Validate file system path

        Args:
            value: Path to validate
            must_exist: If True, path must exist on filesystem

        Returns:
            (is_valid, error_message)
        """
        if not value:
            return False, "Path cannot be empty"

        if must_exist:
            path = Path(value).expanduser()
            if not path.exists():
                return False, f"Path does not exist: {value}"

        return True, None

    @staticmethod
    def validate_wordlist(value: str) -> Tuple[bool, Optional[str]]:
        """
        Validate wordlist path (must exist and be readable)

        Returns:
            (is_valid, error_message)
        """
        if not value:
            return False, "Wordlist path cannot be empty"

        path = Path(value).expanduser()

        if not path.exists():
            return False, f"Wordlist not found: {value}"

        if not path.is_file():
            return False, f"Wordlist is not a file: {value}"

        if not path.suffix == '.txt':
            return False, f"Wordlist should be a .txt file: {value}"

        return True, None

    @staticmethod
    def validate_hash(value: str, length: int = 32) -> Tuple[bool, Optional[str]]:
        """
        Validate hash (hex string of specific length)

        Args:
            value: Hash to validate
            length: Expected length (32 for LM/NTLM, 64 for SHA256, etc.)

        Returns:
            (is_valid, error_message)
        """
        if not value:
            return False, "Hash cannot be empty"

        pattern = re.compile(f'^[a-fA-F0-9]{{{length}}}$')
        if not pattern.match(value):
            return False, f"Hash must be {length} hexadecimal characters: {value}"

        return True, None

    @staticmethod
    def validate_cve(value: str) -> Tuple[bool, Optional[str]]:
        """
        Validate CVE identifier (CVE-YYYY-NNNNN)

        Returns:
            (is_valid, error_message)
        """
        if not value:
            return False, "CVE cannot be empty"

        if not Validators.CVE_PATTERN.match(value):
            return False, f"Invalid CVE format (expected CVE-YYYY-NNNNN): {value}"

        return True, None

    @staticmethod
    def validate_http_method(value: str) -> Tuple[bool, Optional[str]]:
        """
        Validate HTTP method

        Returns:
            (is_valid, error_message)
        """
        if not value:
            return False, "HTTP method cannot be empty"

        if not Validators.HTTP_METHOD_PATTERN.match(value.upper()):
            return False, f"Invalid HTTP method: {value}"

        return True, None

    @staticmethod
    def validate_threads(value: str) -> Tuple[bool, Optional[str]]:
        """
        Validate thread count (1-100)

        Returns:
            (is_valid, error_message)
        """
        if not value:
            return False, "Thread count cannot be empty"

        try:
            threads = int(value)
            if 1 <= threads <= 100:
                return True, None
            else:
                return False, f"Thread count should be between 1-100: {threads}"
        except ValueError:
            return False, f"Thread count must be numeric: {value}"

    @staticmethod
    def validate_date(value: str) -> Tuple[bool, Optional[str]]:
        """
        Validate date (YYYY-MM-DD format)

        Returns:
            (is_valid, error_message)
        """
        if not value:
            return False, "Date cannot be empty"

        if not Validators.DATE_PATTERN.match(value):
            return False, f"Date must be in YYYY-MM-DD format: {value}"

        # Validate actual date values
        try:
            year, month, day = map(int, value.split('-'))
            if not (1900 <= year <= 2100):
                return False, f"Year must be between 1900-2100: {year}"
            if not (1 <= month <= 12):
                return False, f"Month must be between 1-12: {month}"
            if not (1 <= day <= 31):
                return False, f"Day must be between 1-31: {day}"
            return True, None
        except ValueError:
            return False, f"Invalid date values: {value}"

    @staticmethod
    def validate_interface(value: str) -> Tuple[bool, Optional[str]]:
        """
        Validate network interface name

        Returns:
            (is_valid, error_message)
        """
        if not value:
            return False, "Interface cannot be empty"

        # Common interface patterns
        valid_patterns = [
            r'^eth\d+$',      # eth0, eth1
            r'^wlan\d+$',     # wlan0, wlan1
            r'^tun\d+$',      # tun0, tun1 (VPN)
            r'^tap\d+$',      # tap0, tap1
            r'^lo$',          # loopback
            r'^enp\d+s\d+$',  # enp0s3 (predictable names)
            r'^wlp\d+s\d+$',  # wlp3s0 (wireless predictable)
        ]

        for pattern in valid_patterns:
            if re.match(pattern, value):
                return True, None

        return False, f"Invalid interface name: {value}"

    @staticmethod
    def get_validator_for_variable(var_name: str):
        """
        Get the appropriate validator function for a variable

        Returns:
            Callable validator function or None
        """
        validator_map = {
            'LHOST': Validators.validate_ip,
            'TARGET': Validators.validate_ip,
            'IP': Validators.validate_ip,
            'DISCOVERED_IP': Validators.validate_ip,
            'NAMESERVER': Validators.validate_ip,
            'LPORT': Validators.validate_port,
            'PORT': Validators.validate_port,
            'URL': Validators.validate_url,
            'DOMAIN': Validators.validate_domain,
            'WORDLIST': Validators.validate_wordlist,
            'INTERFACE': Validators.validate_interface,
            'TARGET_SUBNET': Validators.validate_cidr,
            'SUBNET': Validators.validate_cidr,
            'LM_HASH': lambda v: Validators.validate_hash(v, 32),
            'NTLM_HASH': lambda v: Validators.validate_hash(v, 32),
            'CVE_ID': Validators.validate_cve,
            'METHOD': Validators.validate_http_method,
            'THREADS': Validators.validate_threads,
            'DATE': Validators.validate_date,
        }

        return validator_map.get(var_name)

    @staticmethod
    def validate_variable(var_name: str, value: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a variable value using the appropriate validator

        Args:
            var_name: Variable name (without angle brackets)
            value: Value to validate

        Returns:
            (is_valid, error_message)
        """
        validator = Validators.get_validator_for_variable(var_name)

        if validator:
            return validator(value)

        # No specific validator, accept any non-empty value
        if value:
            return True, None
        else:
            return False, f"{var_name} cannot be empty"
