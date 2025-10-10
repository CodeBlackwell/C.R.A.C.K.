# Input Validator Component - Usage Guide

## Overview

The `InputValidator` component provides comprehensive input validation for all CRACK Track TUI panels. It follows the surgical, standalone component pattern and returns helpful error messages.

**File**: `/home/kali/OSCP/crack/track/interactive/components/input_validator.py`

## Architecture

- **Standalone utility class** - No dependencies on TUI session
- **Consistent return pattern** - All methods return `(is_valid: bool, error_message: str)`
- **Type-hinted** - Full type annotations for IDE support
- **OSCP-specific validators** - Tailored for penetration testing workflows

## Basic Usage

### Method 1: Class Instance

```python
from track.interactive.components import InputValidator

validator = InputValidator()

# IP address validation
is_valid, error = validator.validate_ip("192.168.45.100")
if not is_valid:
    print(f"Error: {error}")

# Port validation
is_valid, error = validator.validate_port("80")
if not is_valid:
    print(f"Error: {error}")
```

### Method 2: Convenience Function

```python
from track.interactive.components import validate

# Quick validation without creating instance
is_valid, error = validate("192.168.45.100", "ip")
is_valid, error = validate("80-443", "port_range")
is_valid, error = validate("admin@oscp.local", "email")
```

## Validation Methods

### Core Validators

#### IP Address Validation
```python
# IPv4 or IPv6
is_valid, error = validator.validate_ip("192.168.45.100")
is_valid, error = validator.validate_ip("fe80::1")

# Returns:
# (True, "") if valid
# (False, "Invalid IP address: ...") if invalid
```

#### CIDR Range Validation
```python
# IP range in CIDR notation
is_valid, error = validator.validate_ip_range("192.168.1.0/24")

# Returns:
# (True, "") if valid
# (False, "Invalid CIDR notation: ...") if invalid
```

#### Port Validation
```python
# Single port (1-65535)
is_valid, error = validator.validate_port("80")

# Returns:
# (True, "") if valid
# (False, "Port must be 1-65535, got: 99999") if invalid
```

#### Port Range Validation
```python
# Single port, range, or comma-separated list
is_valid, error = validator.validate_port_range("80")
is_valid, error = validator.validate_port_range("80-443")
is_valid, error = validator.validate_port_range("80,443,8080")

# Returns:
# (True, "") if valid
# (False, "Invalid port range format: ...") if invalid
```

#### File Path Validation
```python
# Validate file existence and permissions
is_valid, error = validator.validate_file_path("/etc/passwd", mode='r')  # Read
is_valid, error = validator.validate_file_path("/tmp/output.txt", mode='w')  # Write
is_valid, error = validator.validate_file_path("/usr/bin/nmap", mode='x')  # Execute

# Optional: Allow non-existent files (for output paths)
is_valid, error = validator.validate_file_path("/tmp/new.txt", mode='w', must_exist=False)

# Returns:
# (True, "") if valid
# (False, "File does not exist: ...") if invalid
# (False, "File not readable: ...") if permission denied
```

#### Directory Path Validation
```python
# Validate directory existence and permissions
is_valid, error = validator.validate_directory_path("/usr/share/wordlists", mode='r')

# Returns:
# (True, "") if valid
# (False, "Directory does not exist: ...") if invalid
```

#### Required Field Validation
```python
# Validate that required fields are present and non-empty
fields = {
    'username': 'admin',
    'password': 'secret123',
    'email': ''
}

is_valid, error = validator.validate_required(fields)

# Returns:
# (True, "") if all fields have values
# (False, "Required fields missing: email") if empty
```

#### Choice Validation
```python
# Validate user choice against allowed options
is_valid, error = validator.validate_choice("a", ["a", "b", "c"])

# Case-insensitive by default
is_valid, error = validator.validate_choice("A", ["a", "b", "c"])  # Valid

# Returns:
# (True, "") if valid choice
# (False, "Invalid choice: z (valid options: a, b, c)") if invalid
```

### OSCP-Specific Validators

#### Target Validation
```python
# Accepts IP address OR hostname
is_valid, error = validator.validate_target("192.168.45.100")  # IP
is_valid, error = validator.validate_target("example.com")     # Hostname

# Returns:
# (True, "") if valid target
# (False, "Invalid target format: ... (must be IP or hostname)") if invalid
```

#### Wordlist Path Validation
```python
# Validates wordlist file with OSCP-specific suggestions
is_valid, error = validator.validate_wordlist_path("/usr/share/wordlists/rockyou.txt")

# If invalid, provides suggestions from common locations:
# - /usr/share/wordlists
# - /usr/share/seclists
# - /usr/share/dirb/wordlists
# - /usr/share/dirbuster/wordlists
# - /usr/share/wfuzz/wordlist

# Returns:
# (True, "") if valid
# (False, "File not readable: ...\n\nDid you mean:\n  - /usr/share/wordlists/...") with suggestions
```

#### URL Validation
```python
# Validate HTTP/HTTPS URL
is_valid, error = validator.validate_url("https://example.com")
is_valid, error = validator.validate_url("http://192.168.1.1:8080/admin")

# Allow URLs without scheme
is_valid, error = validator.validate_url("example.com", require_scheme=False)

# Returns:
# (True, "") if valid
# (False, "Invalid URL format (must include http/https): ...") if invalid
```

#### Domain Validation
```python
# Validate domain name format
is_valid, error = validator.validate_domain("example.com")
is_valid, error = validator.validate_domain("sub.example.com")

# Returns:
# (True, "") if valid
# (False, "Invalid domain format: ...") if invalid
```

#### Hostname Validation
```python
# Validate hostname (RFC 1123)
is_valid, error = validator.validate_hostname("example.com")
is_valid, error = validator.validate_hostname("web-server-01")

# Returns:
# (True, "") if valid
# (False, "Invalid hostname format: ...") if invalid
```

#### Email Validation
```python
# Validate email address format
is_valid, error = validator.validate_email("admin@oscp.local")

# Returns:
# (True, "") if valid
# (False, "Invalid email format: ...") if invalid
```

#### Hash Validation
```python
# Validate hash format for password cracking
is_valid, error = validator.validate_hash("5f4dcc3b5aa765d61d8327deb882cf99", "md5")
is_valid, error = validator.validate_hash("356a192b7913b04c54574d18c28d46e6395428ab", "sha1")
is_valid, error = validator.validate_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256")

# Supported hash types: md5, sha1, sha256, sha512, ntlm

# Returns:
# (True, "") if valid
# (False, "Invalid MD5 hash length (expected 32, got 10): ...") if invalid
```

#### MAC Address Validation
```python
# Validate MAC address format
is_valid, error = validator.validate_mac_address("00:11:22:33:44:55")  # Colon-separated
is_valid, error = validator.validate_mac_address("00-11-22-33-44-55")  # Hyphen-separated

# Returns:
# (True, "") if valid
# (False, "Invalid MAC address format (use XX:XX:XX:XX:XX:XX): ...") if invalid
```

### Advanced Validators

#### Multiple Validations
```python
# Run multiple validations and return first error
validations = [
    (validator.validate_ip, "192.168.45.100", "target"),
    (validator.validate_port, "80", "port"),
    (validator.validate_file_path, "/usr/share/wordlists/common.txt", "wordlist")
]

is_valid, error = validator.validate_multiple(validations)

# Returns:
# (True, "") if all pass
# (False, "port: Port must be 1-65535, got: ...") with field name prefix
```

#### Positive Integer Validation
```python
# Validate positive integer with optional range
is_valid, error = validator.validate_positive_integer("5", min_value=1, max_value=10)

# Returns:
# (True, "") if valid
# (False, "Value must be between 1 and 10, got: 15") if out of range
```

#### Format Validation (Legacy)
```python
# Generic format validation using FormatType enum
is_valid, error = validator.validate_format("admin@example.com", "email")
is_valid, error = validator.validate_format("192.168.1.1", "ip")

# Returns:
# (True, "") if valid
# (False, "Invalid EMAIL format: ...") if invalid
```

## Integration Examples

### Panel Input Validation

```python
from track.interactive.components import InputValidator

class CredentialFormPanel:
    @staticmethod
    def render(profile):
        validator = InputValidator()
        
        # Get user input
        username = input("Username: ")
        password = input("Password: ")
        
        # Validate required fields
        fields = {'username': username, 'password': password}
        is_valid, error = validator.validate_required(fields)
        
        if not is_valid:
            print(f"[!] {error}")
            return None
        
        # Additional validations...
        return {'username': username, 'password': password}
```

### Form Field Validation

```python
from track.interactive.components import InputValidator

def get_target_input():
    validator = InputValidator()
    
    while True:
        target = input("Enter target IP or hostname: ").strip()
        
        is_valid, error = validator.validate_target(target)
        if is_valid:
            return target
        
        print(f"[!] {error}")
        print("[*] Please enter a valid IP address or hostname")
```

### Wordlist Path Validation with Suggestions

```python
from track.interactive.components import InputValidator

def get_wordlist_path():
    validator = InputValidator()
    
    while True:
        path = input("Wordlist path: ").strip()
        
        is_valid, error = validator.validate_wordlist_path(path)
        if is_valid:
            return path
        
        # Error includes suggestions from common OSCP locations
        print(f"[!] {error}")
```

### Multiple Field Validation

```python
from track.interactive.components import InputValidator

def validate_scan_config(config):
    validator = InputValidator()
    
    validations = [
        (validator.validate_target, config['target'], "target"),
        (validator.validate_port_range, config['ports'], "ports"),
        (validator.validate_positive_integer, config['threads'], "threads")
    ]
    
    is_valid, error = validator.validate_multiple(validations)
    
    if not is_valid:
        raise ValueError(f"Invalid configuration: {error}")
    
    return True
```

## Convenience Function Usage

The `validate()` function provides a quick way to validate without creating an instance:

```python
from track.interactive.components import validate

# Validation type mapping:
validation_types = {
    'ip': 'IP address',
    'ip_range': 'CIDR range',
    'port': 'Single port',
    'port_range': 'Port or range',
    'file': 'File path',
    'directory': 'Directory path',
    'hostname': 'Hostname',
    'target': 'IP or hostname (OSCP)',
    'wordlist': 'Wordlist path (OSCP)',
    'url': 'HTTP/HTTPS URL',
    'domain': 'Domain name',
    'email': 'Email address',
    'hash': 'Hash value',
    'mac': 'MAC address',
    'choice': 'User choice',
    'format': 'Generic format',
    'required': 'Required fields'
}

# Examples:
is_valid, error = validate("192.168.45.100", "ip")
is_valid, error = validate("80-443", "port_range")
is_valid, error = validate("example.com", "target")

# With kwargs:
is_valid, error = validate("/etc/passwd", "file", mode='r')
is_valid, error = validate("5f4dcc3b5aa765d61d8327deb882cf99", "hash", hash_type='md5')
is_valid, error = validate("https://example.com", "url", require_scheme=True)
```

## Testing

Run the built-in demo to verify all validators:

```bash
python3 track/interactive/components/input_validator.py
```

Expected output:
```
======================================================================
CRACK Track Input Validator - Demo
======================================================================

Running validation tests...

[PASS] ✓ IP Address (valid): 192.168.45.100
[PASS] ✗ IP Address (invalid): 999.999.999.999
...
======================================================================
Test Results: 30 passed, 0 failed
======================================================================
```

## Error Message Examples

The validator provides helpful, actionable error messages:

- **IP**: `Invalid IP address: '999.999.999.999' does not appear to be an IPv4 or IPv6 address`
- **Port**: `Port must be 1-65535, got: 99999`
- **Port Range**: `Invalid port range format: 80-443-8080. Use: START-END`
- **File**: `File does not exist: /nonexistent/file`
- **Target**: `Invalid target format: invalid! (must be IP address or hostname)`
- **Wordlist**: `File not readable: /bad/path\n\nDid you mean:\n  - /usr/share/wordlists/rockyou.txt`
- **Hash**: `Invalid MD5 hash length (expected 32, got 10): short`
- **Choice**: `Invalid choice 'z'. Valid options: a, b, c`

## Best Practices

1. **Always validate user input** before using it
2. **Show error messages** to guide users
3. **Use OSCP-specific validators** (target, wordlist, url) for pentesting workflows
4. **Leverage suggestions** from wordlist validator to help users find files
5. **Validate early** to prevent cascading errors
6. **Return helpful errors** that explain what's wrong and how to fix it

## Integration Checklist

- [ ] Import `InputValidator` or `validate` from `track.interactive.components`
- [ ] Validate all user inputs before processing
- [ ] Display error messages to users
- [ ] Handle validation failures gracefully
- [ ] Test with both valid and invalid inputs
- [ ] Use OSCP-specific validators where applicable

## File Location

**Component**: `/home/kali/OSCP/crack/track/interactive/components/input_validator.py`

**Exports**: 
- `InputValidator` class
- `validate()` convenience function

**No reinstall needed** - Changes to this component load immediately.
