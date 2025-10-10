# Input Validator - Quick Reference

## Import
```python
from track.interactive.components import InputValidator, validate
```

## Quick Usage
```python
# Method 1: Class instance
validator = InputValidator()
is_valid, error = validator.validate_ip("192.168.45.100")

# Method 2: Convenience function
is_valid, error = validate("192.168.45.100", "ip")
```

## Common Validators (One-Liners)

```python
# IP & Network
validate("192.168.45.100", "ip")                    # IPv4/IPv6
validate("192.168.1.0/24", "ip_range")              # CIDR notation
validate("example.com", "hostname")                 # Hostname
validate("192.168.45.100", "target")                # IP or hostname (OSCP)

# Ports
validate("80", "port")                              # Single port (1-65535)
validate("80-443", "port_range")                    # Port range
validate("80,443,8080", "port_range")               # Port list

# Files & Paths
validate("/etc/passwd", "file", mode='r')           # Readable file
validate("/tmp/output.txt", "file", mode='w')       # Writable file
validate("/usr/share/wordlists", "directory")       # Directory
validate("/usr/share/wordlists/rockyou.txt", "wordlist")  # OSCP wordlist (with suggestions)

# Network & Web
validate("https://example.com", "url")              # HTTP/HTTPS URL
validate("example.com", "domain")                   # Domain name
validate("admin@oscp.local", "email")               # Email address
validate("00:11:22:33:44:55", "mac")                # MAC address

# Hashes (OSCP)
validate("5f4dcc3b5aa765d61d8327deb882cf99", "hash", hash_type="md5")      # MD5
validate("356a192b7913b04c54574d18c28d46e6395428ab", "hash", hash_type="sha1")  # SHA1
validate("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hash", hash_type="sha256")  # SHA256

# Forms & Choices
validate("a", "choice", valid_choices=["a", "b", "c"])  # User choice
validator.validate_required({'username': 'admin', 'password': ''})  # Required fields
```

## Return Pattern
All validators return `(is_valid: bool, error_message: str)`

Success: `(True, "")`
Failure: `(False, "Helpful error message")`

## Example: Form Validation Loop
```python
from track.interactive.components import InputValidator

validator = InputValidator()

# Get validated target
while True:
    target = input("Target IP or hostname: ").strip()
    is_valid, error = validator.validate_target(target)
    if is_valid:
        break
    print(f"[!] {error}")

# Get validated port
while True:
    port = input("Port (1-65535): ").strip()
    is_valid, error = validator.validate_port(port)
    if is_valid:
        break
    print(f"[!] {error}")

print(f"[+] Validated: {target}:{port}")
```

## OSCP-Specific Features

1. **Target Validation** - Accepts IP or hostname
2. **Wordlist Path** - Auto-suggests from common OSCP locations
3. **Hash Validation** - MD5/SHA1/SHA256/NTLM for password cracking
4. **Port Ranges** - Supports nmap-style port specifications

## File Location
`/home/kali/OSCP/crack/track/interactive/components/input_validator.py`

## Full Documentation
See `INPUT_VALIDATOR_USAGE.md` for complete API reference and examples.
