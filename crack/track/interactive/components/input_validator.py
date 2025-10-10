"""
Input Validator Utility for CRACK Track TUI

Provides comprehensive input validation for all panels with helpful error messages.
Follows the surgical, incremental development pattern with single-responsibility methods.

Usage:
    validator = InputValidator()
    is_valid, error = validator.validate_ip("192.168.1.1")
    if not is_valid:
        print(error)
"""

import re
import ipaddress
from pathlib import Path
from typing import Tuple, Dict, Any, List, Optional
from enum import Enum


class FormatType(Enum):
    """Supported validation format types"""
    IP = "ip"
    PORT = "port"
    EMAIL = "email"
    URL = "url"
    PATH = "path"
    ALPHA = "alpha"
    NUMERIC = "numeric"
    ALPHANUMERIC = "alphanumeric"


class InputValidator:
    """
    Standalone input validation utility for TUI components.

    Returns tuple of (is_valid: bool, error_message: str) for all validation methods.
    Error messages are user-friendly and actionable.
    """

    # Regex patterns for format validation
    PATTERNS = {
        FormatType.EMAIL: r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
        FormatType.URL: r'^https?://[^\s/$.?#].[^\s]*$',
        FormatType.ALPHA: r'^[a-zA-Z]+$',
        FormatType.NUMERIC: r'^[0-9]+$',
        FormatType.ALPHANUMERIC: r'^[a-zA-Z0-9]+$',
    }

    def validate_ip(self, ip_str: str) -> Tuple[bool, str]:
        """
        Validate IPv4 or IPv6 address.

        Args:
            ip_str: IP address string to validate

        Returns:
            (True, "") if valid
            (False, error_message) if invalid

        Examples:
            >>> validator.validate_ip("192.168.1.1")
            (True, "")
            >>> validator.validate_ip("999.999.999.999")
            (False, "Invalid IP address: ...")
        """
        if not ip_str or not ip_str.strip():
            return False, "IP address cannot be empty"

        ip_str = ip_str.strip()

        try:
            # ipaddress module handles both IPv4 and IPv6
            ipaddress.ip_address(ip_str)
            return True, ""
        except ValueError as e:
            return False, f"Invalid IP address: {str(e)}"

    def validate_port(self, port_str: str) -> Tuple[bool, str]:
        """
        Validate port number (1-65535).

        Args:
            port_str: Port number as string

        Returns:
            (True, "") if valid
            (False, error_message) if invalid

        Examples:
            >>> validator.validate_port("80")
            (True, "")
            >>> validator.validate_port("70000")
            (False, "Port must be between 1 and 65535")
        """
        if not port_str or not port_str.strip():
            return False, "Port cannot be empty"

        port_str = port_str.strip()

        # Check numeric format
        if not port_str.isdigit():
            return False, f"Port must be a number, got: {port_str}"

        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                return False, f"Port must be between 1 and 65535, got: {port}"
            return True, ""
        except ValueError:
            return False, f"Invalid port number: {port_str}"

    def validate_file_path(
        self,
        path: str,
        mode: str = 'r',
        must_exist: bool = True
    ) -> Tuple[bool, str]:
        """
        Validate file path with permission checks.

        Args:
            path: File path to validate
            mode: Required access mode ('r', 'w', 'x')
            must_exist: If True, file/directory must exist

        Returns:
            (True, "") if valid
            (False, error_message) if invalid

        Examples:
            >>> validator.validate_file_path("/etc/passwd", mode='r')
            (True, "")
            >>> validator.validate_file_path("/nonexistent", mode='r')
            (False, "File does not exist: /nonexistent")
        """
        if not path or not path.strip():
            return False, "File path cannot be empty"

        path = path.strip()
        path_obj = Path(path).expanduser().resolve()

        # Check existence if required
        if must_exist and not path_obj.exists():
            return False, f"Path does not exist: {path}"

        # If path doesn't exist but must_exist is False, check parent directory
        if not must_exist and not path_obj.exists():
            parent = path_obj.parent
            if not parent.exists():
                return False, f"Parent directory does not exist: {parent}"
            if not parent.is_dir():
                return False, f"Parent is not a directory: {parent}"

        # Validate mode permissions
        if path_obj.exists():
            if mode == 'r':
                if not path_obj.is_file() and not path_obj.is_dir():
                    return False, f"Path is not a file or directory: {path}"
                # Check read permission by attempting to access
                try:
                    if path_obj.is_file():
                        path_obj.read_text(encoding='utf-8', errors='ignore')
                    else:
                        list(path_obj.iterdir())
                except PermissionError:
                    return False, f"No read permission for: {path}"
                except Exception as e:
                    # File might not be text, but we can read it
                    if "Permission" in str(e):
                        return False, f"No read permission for: {path}"

            elif mode == 'w':
                if path_obj.is_file():
                    # Check write permission
                    if not path_obj.stat().st_mode & 0o200:
                        return False, f"No write permission for: {path}"
                elif path_obj.is_dir():
                    # Check directory write permission
                    if not path_obj.stat().st_mode & 0o200:
                        return False, f"No write permission for directory: {path}"
                else:
                    return False, f"Path is not a file or directory: {path}"

            elif mode == 'x':
                if not path_obj.is_file():
                    return False, f"Execute mode requires a file: {path}"
                if not path_obj.stat().st_mode & 0o100:
                    return False, f"No execute permission for: {path}"

            else:
                return False, f"Invalid mode: {mode}. Use 'r', 'w', or 'x'"

        return True, ""

    def validate_required(self, fields_dict: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validate that required fields are not empty.

        Args:
            fields_dict: Dictionary of field_name -> value pairs

        Returns:
            (True, "") if all fields have values
            (False, error_message) listing empty fields

        Examples:
            >>> validator.validate_required({"name": "test", "ip": "192.168.1.1"})
            (True, "")
            >>> validator.validate_required({"name": "", "ip": "192.168.1.1"})
            (False, "Required fields missing: name")
        """
        if not fields_dict:
            return False, "No fields provided for validation"

        empty_fields = []

        for field_name, value in fields_dict.items():
            # Check for None, empty string, or whitespace-only string
            if value is None:
                empty_fields.append(field_name)
            elif isinstance(value, str) and not value.strip():
                empty_fields.append(field_name)
            elif isinstance(value, (list, dict)) and not value:
                empty_fields.append(field_name)

        if empty_fields:
            fields_str = ", ".join(empty_fields)
            return False, f"Required fields missing: {fields_str}"

        return True, ""

    def validate_format(
        self,
        value: str,
        format_type: str
    ) -> Tuple[bool, str]:
        """
        Validate string against a specific format pattern.

        Args:
            value: String to validate
            format_type: Format type (IP, PORT, EMAIL, URL, PATH, ALPHA, NUMERIC, ALPHANUMERIC)

        Returns:
            (True, "") if matches format
            (False, error_message) if doesn't match

        Examples:
            >>> validator.validate_format("test@example.com", "EMAIL")
            (True, "")
            >>> validator.validate_format("not-an-email", "EMAIL")
            (False, "Invalid EMAIL format")
        """
        if not value or not value.strip():
            return False, f"{format_type} value cannot be empty"

        value = value.strip()

        # Normalize format_type to FormatType enum
        try:
            if isinstance(format_type, str):
                format_type = format_type.upper()
                fmt = FormatType(format_type.lower())
            else:
                fmt = format_type
        except ValueError:
            valid_types = ", ".join([f.value.upper() for f in FormatType])
            return False, f"Invalid format type: {format_type}. Use: {valid_types}"

        # Handle special cases with dedicated methods
        if fmt == FormatType.IP:
            return self.validate_ip(value)

        if fmt == FormatType.PORT:
            return self.validate_port(value)

        if fmt == FormatType.PATH:
            return self.validate_file_path(value, must_exist=False)

        # Handle regex-based validation
        if fmt in self.PATTERNS:
            pattern = self.PATTERNS[fmt]
            if re.match(pattern, value):
                return True, ""
            else:
                return False, f"Invalid {fmt.value.upper()} format: {value}"

        # Should never reach here
        return False, f"Validation not implemented for format: {fmt.value}"

    def validate_choice(
        self,
        value: str,
        valid_choices: List[str]
    ) -> Tuple[bool, str]:
        """
        Validate that value is in the list of allowed choices.

        Args:
            value: Value to check
            valid_choices: List of valid choice strings

        Returns:
            (True, "") if value in choices
            (False, error_message) if not in choices

        Examples:
            >>> validator.validate_choice("a", ["a", "b", "c"])
            (True, "")
            >>> validator.validate_choice("d", ["a", "b", "c"])
            (False, "Invalid choice 'd'. Valid options: a, b, c")
        """
        if not value:
            return False, "Choice cannot be empty"

        if not valid_choices:
            return False, "No valid choices provided"

        value = value.strip()

        # Case-insensitive comparison
        valid_choices_lower = [str(c).lower() for c in valid_choices]

        if value.lower() in valid_choices_lower:
            return True, ""
        else:
            choices_str = ", ".join(str(c) for c in valid_choices)
            return False, f"Invalid choice '{value}'. Valid options: {choices_str}"

    def validate_ip_range(
        self,
        ip_range_str: str
    ) -> Tuple[bool, str]:
        """
        Validate IP range in CIDR notation (e.g., 192.168.1.0/24).

        Args:
            ip_range_str: IP range in CIDR notation

        Returns:
            (True, "") if valid CIDR range
            (False, error_message) if invalid

        Examples:
            >>> validator.validate_ip_range("192.168.1.0/24")
            (True, "")
            >>> validator.validate_ip_range("192.168.1.0/99")
            (False, "Invalid CIDR notation: ...")
        """
        if not ip_range_str or not ip_range_str.strip():
            return False, "IP range cannot be empty"

        ip_range_str = ip_range_str.strip()

        try:
            ipaddress.ip_network(ip_range_str, strict=False)
            return True, ""
        except ValueError as e:
            return False, f"Invalid CIDR notation: {str(e)}"

    def validate_port_range(
        self,
        port_range_str: str
    ) -> Tuple[bool, str]:
        """
        Validate port range (e.g., "80", "1-1024", "80,443,8080").

        Args:
            port_range_str: Port or range specification

        Returns:
            (True, "") if valid port range
            (False, error_message) if invalid

        Examples:
            >>> validator.validate_port_range("80")
            (True, "")
            >>> validator.validate_port_range("1-1024")
            (True, "")
            >>> validator.validate_port_range("80,443,8080")
            (True, "")
            >>> validator.validate_port_range("80-443")
            (True, "")
        """
        if not port_range_str or not port_range_str.strip():
            return False, "Port range cannot be empty"

        port_range_str = port_range_str.strip()

        # Handle comma-separated list
        if ',' in port_range_str:
            ports = [p.strip() for p in port_range_str.split(',')]
            for port in ports:
                is_valid, error = self.validate_port(port)
                if not is_valid:
                    return False, f"Invalid port in list: {error}"
            return True, ""

        # Handle range (e.g., "1-1024" or "80-443")
        if '-' in port_range_str:
            parts = port_range_str.split('-')
            if len(parts) != 2:
                return False, f"Invalid port range format: {port_range_str}. Use: START-END"

            start_port, end_port = parts[0].strip(), parts[1].strip()

            # Validate start port
            is_valid, error = self.validate_port(start_port)
            if not is_valid:
                return False, f"Invalid start port: {error}"

            # Validate end port
            is_valid, error = self.validate_port(end_port)
            if not is_valid:
                return False, f"Invalid end port: {error}"

            # Check range order
            if int(start_port) > int(end_port):
                return False, f"Start port ({start_port}) must be <= end port ({end_port})"

            return True, ""

        # Single port
        return self.validate_port(port_range_str)

    def validate_hostname(
        self,
        hostname: str
    ) -> Tuple[bool, str]:
        """
        Validate hostname or FQDN.

        Args:
            hostname: Hostname to validate

        Returns:
            (True, "") if valid hostname
            (False, error_message) if invalid

        Examples:
            >>> validator.validate_hostname("example.com")
            (True, "")
            >>> validator.validate_hostname("sub.example.com")
            (True, "")
        """
        if not hostname or not hostname.strip():
            return False, "Hostname cannot be empty"

        hostname = hostname.strip()

        # Hostname regex pattern (RFC 1123)
        # - 1-63 characters per label
        # - alphanumeric and hyphens (not starting/ending with hyphen)
        # - case insensitive
        hostname_pattern = r'^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*(?!-)[A-Za-z0-9-]{1,63}(?<!-)$'

        if re.match(hostname_pattern, hostname):
            return True, ""
        else:
            return False, f"Invalid hostname format: {hostname}"

    def validate_multiple(
        self,
        validations: List[Tuple[callable, Any, str]]
    ) -> Tuple[bool, str]:
        """
        Run multiple validations and return first error.

        Args:
            validations: List of (validator_method, value, field_name) tuples

        Returns:
            (True, "") if all validations pass
            (False, error_message) with first error found

        Examples:
            >>> validations = [
            ...     (validator.validate_ip, "192.168.1.1", "target"),
            ...     (validator.validate_port, "80", "port")
            ... ]
            >>> validator.validate_multiple(validations)
            (True, "")
        """
        if not validations:
            return True, ""

        for validator_method, value, field_name in validations:
            is_valid, error = validator_method(value)
            if not is_valid:
                return False, f"{field_name}: {error}"

        return True, ""

    # OSCP-Specific Validators

    def validate_target(
        self,
        target: str
    ) -> Tuple[bool, str]:
        """
        Validate target format (IP address or hostname) - OSCP-specific.

        Args:
            target: Target IP or hostname

        Returns:
            (True, "") if valid target
            (False, error_message) if invalid

        Examples:
            >>> validator.validate_target("192.168.45.100")
            (True, "")
            >>> validator.validate_target("example.com")
            (True, "")
            >>> validator.validate_target("invalid!")
            (False, "Invalid target format: ...")
        """
        if not target or not target.strip():
            return False, "Target cannot be empty"

        target = target.strip()

        # Try IP validation first
        is_valid_ip, _ = self.validate_ip(target)
        if is_valid_ip:
            return True, ""

        # Try hostname validation
        is_valid_hostname, _ = self.validate_hostname(target)
        if is_valid_hostname:
            return True, ""

        return False, f"Invalid target format: {target} (must be IP address or hostname)"

    def validate_wordlist_path(
        self,
        path: str
    ) -> Tuple[bool, str]:
        """
        Validate wordlist file path with OSCP-specific common locations.

        Args:
            path: Wordlist file path

        Returns:
            (True, "") if valid wordlist
            (False, error_message) with suggestions if invalid

        Examples:
            >>> validator.validate_wordlist_path("/usr/share/wordlists/rockyou.txt")
            (True, "")
        """
        if not path or not path.strip():
            return False, "Wordlist path cannot be empty"

        path = path.strip()

        # First check if it's a valid readable file
        is_valid, error = self.validate_file_path(path, mode='r', must_exist=True)

        if is_valid:
            return True, ""

        # If invalid, provide OSCP-specific suggestions
        common_wordlist_paths = [
            "/usr/share/wordlists",
            "/usr/share/seclists",
            "/usr/share/dirb/wordlists",
            "/usr/share/dirbuster/wordlists",
            "/usr/share/wfuzz/wordlist",
        ]

        suggestions = []
        path_obj = Path(path)
        filename = path_obj.name

        # Search common locations for similar files
        for common_path in common_wordlist_paths:
            common_dir = Path(common_path)
            if common_dir.exists() and common_dir.is_dir():
                # Look for exact filename match
                potential_match = common_dir / filename
                if potential_match.exists() and potential_match.is_file():
                    suggestions.append(str(potential_match))
                    continue

                # Look for similar filenames (recursive search)
                try:
                    for wordlist in common_dir.rglob(f"*{filename}*"):
                        if wordlist.is_file() and len(suggestions) < 3:
                            suggestions.append(str(wordlist))
                except (PermissionError, OSError):
                    # Skip directories we can't access
                    continue

        # Build enhanced error message
        error_msg = error

        if suggestions:
            suggestions_list = "\n  - ".join(suggestions[:3])
            error_msg += f"\n\nDid you mean:\n  - {suggestions_list}"
        else:
            common_locations = "\n  - ".join(common_wordlist_paths)
            error_msg += f"\n\nCommon wordlist locations:\n  - {common_locations}"

        return False, error_msg

    def validate_url(
        self,
        url: str,
        require_scheme: bool = True
    ) -> Tuple[bool, str]:
        """
        Validate URL format - OSCP-specific for web enumeration.

        Args:
            url: URL to validate
            require_scheme: If True, URL must have http:// or https://

        Returns:
            (True, "") if valid URL
            (False, error_message) if invalid

        Examples:
            >>> validator.validate_url("https://example.com")
            (True, "")
            >>> validator.validate_url("example.com", require_scheme=False)
            (True, "")
        """
        if not url or not url.strip():
            return False, "URL cannot be empty"

        url = url.strip()

        # URL regex pattern
        url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'

        if require_scheme:
            if re.match(url_pattern, url):
                return True, ""
            else:
                return False, f"Invalid URL format (must include http:// or https://): {url}"
        else:
            # Allow URLs without scheme
            if re.match(url_pattern, url) or re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$', url):
                return True, ""
            else:
                return False, f"Invalid URL format: {url}"

    def validate_domain(
        self,
        domain: str
    ) -> Tuple[bool, str]:
        """
        Validate domain name format - OSCP-specific.

        Args:
            domain: Domain name to validate

        Returns:
            (True, "") if valid domain
            (False, error_message) if invalid

        Examples:
            >>> validator.validate_domain("example.com")
            (True, "")
            >>> validator.validate_domain("sub.example.com")
            (True, "")
        """
        if not domain or not domain.strip():
            return False, "Domain cannot be empty"

        domain = domain.strip()

        # Domain pattern: labels separated by dots
        # - Each label: 1-63 alphanumeric/hyphen (not starting/ending with hyphen)
        # - At least one dot
        # - TLD: 2+ alphabetic characters
        domain_pattern = r'^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$'

        if re.match(domain_pattern, domain):
            return True, ""
        else:
            return False, f"Invalid domain format: {domain}"

    def validate_email(
        self,
        email: str
    ) -> Tuple[bool, str]:
        """
        Validate email address format.

        Args:
            email: Email address to validate

        Returns:
            (True, "") if valid email
            (False, error_message) if invalid

        Examples:
            >>> validator.validate_email("admin@example.com")
            (True, "")
            >>> validator.validate_email("not-an-email")
            (False, "Invalid email format: ...")
        """
        if not email or not email.strip():
            return False, "Email cannot be empty"

        email = email.strip()

        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

        if re.match(email_pattern, email):
            return True, ""
        else:
            return False, f"Invalid email format: {email}"

    def validate_hash(
        self,
        hash_value: str,
        hash_type: str
    ) -> Tuple[bool, str]:
        """
        Validate hash format - OSCP-specific for password cracking.

        Args:
            hash_value: Hash string to validate
            hash_type: Hash type (md5, sha1, sha256, ntlm)

        Returns:
            (True, "") if valid hash
            (False, error_message) if invalid

        Examples:
            >>> validator.validate_hash("5f4dcc3b5aa765d61d8327deb882cf99", "md5")
            (True, "")
        """
        if not hash_value or not hash_value.strip():
            return False, "Hash cannot be empty"

        hash_value = hash_value.strip()
        hash_type = hash_type.lower()

        # Hash length specifications
        hash_specs = {
            'md5': 32,
            'sha1': 40,
            'sha256': 64,
            'sha512': 128,
            'ntlm': 32,
        }

        if hash_type not in hash_specs:
            valid_types = ", ".join(hash_specs.keys())
            return False, f"Unknown hash type: {hash_type} (valid: {valid_types})"

        expected_length = hash_specs[hash_type]

        # Check if hash is hexadecimal
        if not re.match(r'^[0-9a-fA-F]+$', hash_value):
            return False, f"Invalid {hash_type.upper()} hash format (must be hexadecimal): {hash_value}"

        # Check length
        if len(hash_value) != expected_length:
            return False, f"Invalid {hash_type.upper()} hash length (expected {expected_length}, got {len(hash_value)}): {hash_value}"

        return True, ""

    def validate_mac_address(
        self,
        mac: str
    ) -> Tuple[bool, str]:
        """
        Validate MAC address format.

        Args:
            mac: MAC address to validate

        Returns:
            (True, "") if valid MAC address
            (False, error_message) if invalid

        Examples:
            >>> validator.validate_mac_address("00:11:22:33:44:55")
            (True, "")
            >>> validator.validate_mac_address("00-11-22-33-44-55")
            (True, "")
        """
        if not mac or not mac.strip():
            return False, "MAC address cannot be empty"

        mac = mac.strip()

        # MAC address patterns: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'

        if re.match(mac_pattern, mac):
            return True, ""
        else:
            return False, f"Invalid MAC address format (use XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX): {mac}"


# Convenience function for quick single validations
def validate(
    value: Any,
    validation_type: str,
    **kwargs
) -> Tuple[bool, str]:
    """
    Convenience function for quick validation without creating validator instance.

    Args:
        value: Value to validate
        validation_type: Type of validation (ip, port, email, target, etc.)
        **kwargs: Additional keyword arguments for specific validators

    Returns:
        (is_valid, error_message) tuple

    Examples:
        >>> validate("192.168.45.100", "ip")
        (True, "")
        >>> validate("80-443", "port_range")
        (True, "")
        >>> validate("admin@oscp.local", "email")
        (True, "")
    """
    validator = InputValidator()

    # Map validation types to methods
    validation_map = {
        'ip': validator.validate_ip,
        'ip_range': validator.validate_ip_range,
        'port': validator.validate_port,
        'port_range': validator.validate_port_range,
        'file': lambda v: validator.validate_file_path(v, **kwargs),
        'hostname': validator.validate_hostname,
        'target': validator.validate_target,
        'wordlist': validator.validate_wordlist_path,
        'url': lambda v: validator.validate_url(v, **kwargs),
        'domain': validator.validate_domain,
        'email': validator.validate_email,
        'hash': lambda v: validator.validate_hash(v, **kwargs),
        'mac': validator.validate_mac_address,
        'choice': lambda v: validator.validate_choice(v, **kwargs),
        'format': lambda v: validator.validate_format(v, **kwargs),
        'required': lambda v: validator.validate_required(v),
    }

    if validation_type not in validation_map:
        return False, f"Unknown validation type: {validation_type}"

    return validation_map[validation_type](value)


if __name__ == '__main__':
    # Demo and testing
    print("="*70)
    print("CRACK Track Input Validator - Demo")
    print("="*70)
    print()

    validator = InputValidator()

    # Test cases with expected results
    test_cases = [
        # Basic validations
        ("IP Address (valid)", validator.validate_ip, "192.168.45.100", True),
        ("IP Address (invalid)", validator.validate_ip, "999.999.999.999", False),
        ("IPv6 Address", validator.validate_ip, "fe80::1", True),
        ("CIDR Range", validator.validate_ip_range, "192.168.1.0/24", True),
        ("Invalid CIDR", validator.validate_ip_range, "192.168.1.0/99", False),

        # Port validations
        ("Single Port", validator.validate_port, "80", True),
        ("Port Range", validator.validate_port_range, "80-443", True),
        ("Port List", validator.validate_port_range, "80,443,8080", True),
        ("Invalid Port", validator.validate_port, "99999", False),

        # OSCP-specific validations
        ("Target (IP)", validator.validate_target, "192.168.45.100", True),
        ("Target (Hostname)", validator.validate_target, "example.com", True),
        ("Target (Invalid)", validator.validate_target, "invalid!", False),

        # Network validations
        ("Hostname (valid)", validator.validate_hostname, "example.com", True),
        ("Hostname (subdomain)", validator.validate_hostname, "sub.example.com", True),
        ("Domain (valid)", validator.validate_domain, "example.com", True),
        ("Email (valid)", validator.validate_email, "admin@oscp.local", True),
        ("Email (invalid)", validator.validate_email, "not-an-email", False),

        # Hash validations
        ("MD5 Hash", validator.validate_hash, "5f4dcc3b5aa765d61d8327deb882cf99", {"hash_type": "md5"}, True),
        ("SHA1 Hash", validator.validate_hash, "356a192b7913b04c54574d18c28d46e6395428ab", {"hash_type": "sha1"}, True),
        ("Invalid MD5", validator.validate_hash, "short", {"hash_type": "md5"}, False),

        # URL validations
        ("URL (https)", validator.validate_url, "https://example.com", True),
        ("URL (http)", validator.validate_url, "http://192.168.1.1:8080/path", True),
        ("URL (no scheme)", validator.validate_url, "example.com", False),

        # MAC address
        ("MAC (colon)", validator.validate_mac_address, "00:11:22:33:44:55", True),
        ("MAC (hyphen)", validator.validate_mac_address, "00-11-22-33-44-55", True),
        ("MAC (invalid)", validator.validate_mac_address, "00:11:22", False),

        # Choice validation
        ("Choice (valid)", validator.validate_choice, "a", {"valid_choices": ["a", "b", "c"]}, True),
        ("Choice (invalid)", validator.validate_choice, "z", {"valid_choices": ["a", "b", "c"]}, False),

        # File validation (using /etc/passwd as known readable file)
        ("File Path (readable)", validator.validate_file_path, "/etc/passwd", {"mode": "r"}, True),
        ("File Path (nonexistent)", validator.validate_file_path, "/nonexistent/file", {}, False),
    ]

    print("Running validation tests...\n")

    passed = 0
    failed = 0

    for test_name, method, value, *args in test_cases:
        # Handle different argument patterns
        if len(args) == 2:
            # kwargs and expected result
            kwargs, expected = args
            is_valid, error = method(value, **kwargs)
        elif len(args) == 1:
            # Just expected result
            expected = args[0]
            is_valid, error = method(value)
        else:
            print(f"ERROR: Invalid test case format for {test_name}")
            continue

        # Check if result matches expected
        if is_valid == expected:
            status = "PASS"
            passed += 1
        else:
            status = "FAIL"
            failed += 1

        # Print result
        symbol = "✓" if is_valid else "✗"
        print(f"[{status}] {symbol} {test_name}: {value}")
        if error and not expected:
            # Only show error for expected failures (makes output cleaner)
            print(f"      → {error[:80]}...")

    print()
    print("="*70)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("="*70)
    print()

    # Demonstrate convenience function
    print("Convenience function examples:")
    print("-" * 70)

    is_valid, error = validate("192.168.45.100", "ip")
    print(f"validate('192.168.45.100', 'ip'): {is_valid}")

    is_valid, error = validate("80-443", "port_range")
    print(f"validate('80-443', 'port_range'): {is_valid}")

    is_valid, error = validate("admin@oscp.local", "email")
    print(f"validate('admin@oscp.local', 'email'): {is_valid}")

    is_valid, error = validate("example.com", "target")
    print(f"validate('example.com', 'target'): {is_valid}")

    print()
    print("="*70)
    print("Input Validator Ready for Integration")
    print("="*70)
