# CRACK Configuration System

**Shared configuration module for the entire CRACK toolkit**

## Overview

The `crack.config` module provides centralized variable management, validation, and auto-detection for all CRACK modules (reference, track, sessions, etc.). This eliminates duplication and ensures consistency across the entire toolkit.

## Architecture

```
crack/config/
├── __init__.py          # Module exports
├── manager.py           # ConfigManager class (load/save/validate)
├── variables.py         # Variable definitions (77 variables)
├── validators.py        # Validation patterns (IP, port, path, etc.)
└── README.md            # This file
```

## Key Features

✅ **Single Source of Truth** - All 77 variables defined in one place
✅ **Cross-Module Consistency** - Track and Reference use same config
✅ **Automatic Validation** - IP/port/path validation before setting
✅ **Alias Support** - `<COMMUNITY>` → `<SNMP_COMMUNITY>` auto-resolves
✅ **Auto-Detection** - Detect LHOST, INTERFACE automatically
✅ **Category Organization** - Variables grouped by usage
✅ **Interactive Setup** - Guided wizard for first-time configuration

## Usage

### Basic Usage

```python
from crack.config import ConfigManager

# Initialize (loads ~/.crack/config.json)
config = ConfigManager()

# Set variables (with validation)
success, error = config.set_variable('LHOST', '10.10.14.5')
success, error = config.set_variable('TARGET', '192.168.45.100')

# Get variables
lhost = config.get_variable('LHOST')  # Returns: '10.10.14.5'

# Alias resolution (automatic)
community = config.get_variable('COMMUNITY')  # Resolves to SNMP_COMMUNITY
```

### CLI Usage

```bash
# Interactive setup wizard
crack config setup

# Auto-detect network settings
crack config auto

# Set individual variables
crack config set LHOST 10.10.14.5
crack config set TARGET 192.168.45.100
crack config set WORDLIST /usr/share/wordlists/rockyou.txt

# List all configured variables
crack config list

# List variables by category
crack config list network
crack config list web
crack config list credentials

# Get variable value
crack config get LHOST

# Validate all configured values
crack config validate

# View all categories
crack config categories

# Export/import config
crack config export backup.json
crack config import backup.json --merge

# Edit config file directly
crack config edit
```

## Variable Categories

### Network (12 variables)
- `LHOST` - Local/attacker IP address (auto-detectable)
- `LPORT` - Local port for listener (default: 4444)
- `TARGET` - Target machine IP address
- `TARGET_SUBNET` - Target subnet in CIDR notation
- `INTERFACE` - Network interface (auto-detectable)
- `PORT` - Target port number
- `PORTS` - Port range or list
- `IP` - Generic IP address
- `SUBNET` - Network subnet
- `NAMESERVER` - DNS nameserver (alias: `NS`)
- `DOMAIN` - Target domain name
- `DISCOVERED_IP` - IP discovered during enumeration

### Web (11 variables)
- `URL` - Target URL
- `WORDLIST` - Path to wordlist file
- `EXTENSIONS` - File extensions to search
- `THREADS` - Number of threads for scanning
- `RATE` - Request rate limit
- `WPSCAN_API_TOKEN` - WPScan API token (alias: `API_TOKEN`)
- `SESSION_TOKEN` - Session/auth token (alias: `TOKEN`)
- `PARAM` - URL parameter name
- `METHOD` - HTTP method
- `CMS` - Content Management System name
- `PLUGIN` - Plugin/module name

### Credentials (7 variables)
- `USERNAME` - Username (alias: `USER`)
- `PASSWORD` - Password (alias: `PASS`)
- `CREDFILE` - Credentials file path
- `USERS` - Username list file
- `LM_HASH` - LAN Manager hash (alias: `LM`)
- `NTLM_HASH` - NTLM hash (alias: `NTLM`)

### Enumeration (7 variables)
- `SNMP_COMMUNITY` - SNMP community string (alias: `COMMUNITY`)
- `SHARE` - SMB/NFS share name
- `SERVICE` - Service name or type
- `SERVICE_NAME` - Specific service name
- `VERSION` - Software version number
- `SERVER_VERSION` - Server software version
- `SERVICE_PRINCIPAL_NAME` - Kerberos SPN (alias: `SPN`)

### Exploitation (4 variables)
- `PAYLOAD` - Exploit payload
- `CVE_ID` - CVE identifier (alias: `CVE`)
- `EDB_ID` - Exploit-DB ID number
- `SEARCH_TERM` - Search term for exploit lookup

### File Transfer (7 variables)
- `FILE` - File name
- `FILENAME` - Full file name with extension
- `LOCAL_PATH` - Local file system path
- `PATH` - File or directory path
- `OUTPUT_FILE` - Output file path
- `OUTPUT_DIR` - Output directory path
- `SERVER` - Server address or hostname
- `MOUNT_POINT` - Directory mount point

### SQL Injection (4 variables)
- `DATABASE` - Database name (alias: `DB`)
- `NULL_COLUMNS` - Null values for UNION SQLi
- `EMPTY_COLS` - Number of empty columns
- `MAX_COLS` - Maximum columns to test

### Miscellaneous (25 variables)
- `OUTPUT`, `DIR`, `FOUND_DIR`, `NAME`, `ID`, `VALUE`, `SIZE`, `RANGE`, `DATE`
- `SCRIPT`, `SCRIPT_NAME`, `ARGUMENTS`, `OPTIONS`, `BLACKLIST`, `DEST`, `THEME`

## Validation

Variables are automatically validated when set:

```python
# IP address validation
config.set_variable('LHOST', '10.10.14.5')       # ✓ Valid
config.set_variable('LHOST', 'invalid')          # ✗ Error: Invalid IP format

# Port validation
config.set_variable('LPORT', '4444')             # ✓ Valid
config.set_variable('LPORT', '99999')            # ✗ Error: Port must be 1-65535

# URL validation
config.set_variable('URL', 'http://target.com')  # ✓ Valid
config.set_variable('URL', 'target.com')         # ✗ Error: Must start with http://

# Disable validation (when needed)
config.set_variable('WORDLIST', '/custom/path', validate=False)
```

## Auto-Detection

```python
# Auto-detect network settings
updates = config.auto_configure()
# Returns: {'INTERFACE': 'tun0', 'LHOST': '10.10.14.5'}

# Manual auto-detection
interface = config.auto_detect_interface()  # Returns: 'tun0'
ip = config.auto_detect_ip('tun0')          # Returns: '10.10.14.5'
```

## Integration Examples

### Reference Module

```python
from crack.config import ConfigManager

class PlaceholderEngine:
    def __init__(self):
        self.config = ConfigManager()  # Shared config

    def substitute(self, command: str) -> str:
        """Replace <PLACEHOLDERS> with config values"""
        # Get all configured values with angle brackets
        values = self.config.get_placeholder_values()
        # Returns: {'<LHOST>': '10.10.14.5', '<TARGET>': '192.168.45.100', ...}

        for placeholder, value in values.items():
            command = command.replace(placeholder, value)

        return command
```

### Track Module

```python
from crack.config import ConfigManager

class TargetProfile:
    def __init__(self, target_ip: str):
        self.config = ConfigManager()  # Same shared config
        self.target_ip = target_ip

        # Auto-set TARGET variable
        self.config.set_variable('TARGET', target_ip)

    def get_lhost(self) -> str:
        """Get LHOST from shared config"""
        return self.config.get_variable('LHOST')
```

### Custom Module

```python
from crack.config import ConfigManager, VARIABLE_REGISTRY

config = ConfigManager()

# Get all variables in a category
network_vars = config.get_variables_by_category('network')

# Check if variable is configured
lhost = config.get_variable('LHOST')
if not lhost:
    print("LHOST not configured. Run: crack config auto")

# Validate all configured variables
errors = config.validate_all()
if errors:
    for var, error_list in errors.items():
        print(f"Error in {var}: {error_list}")
```

## Configuration File

**Location:** `~/.crack/config.json`

**Structure:**
```json
{
  "variables": {
    "LHOST": {
      "value": "10.10.14.5",
      "description": "Local/attacker IP address (your machine)",
      "source": "auto-detected",
      "updated": "2025-10-12T10:30:00"
    },
    "TARGET": {
      "value": "192.168.45.100",
      "description": "Target machine IP address",
      "source": "manual",
      "updated": "2025-10-12T10:31:00"
    }
  },
  "sessions": {},
  "settings": {
    "auto_detect_interface": true,
    "auto_detect_ip": true,
    "confirm_before_fill": false,
    "show_source": true
  },
  "theme": {
    "current": "oscp",
    "description": "TUI color theme"
  }
}
```

## Alias System

Aliases allow backward compatibility and shorter names:

```python
# Old placeholder name → New canonical name
'<COMMUNITY>'     → '<SNMP_COMMUNITY>'
'<API_TOKEN>'     → '<WPSCAN_API_TOKEN>'
'<TOKEN>'         → '<SESSION_TOKEN>'
'<DB>'            → '<DATABASE>'
'<USER>'          → '<USERNAME>'
'<PASS>'          → '<PASSWORD>'
'<LM>'            → '<LM_HASH>'
'<NTLM>'          → '<NTLM_HASH>'
'<SPN>'           → '<SERVICE_PRINCIPAL_NAME>'
'<NS>'            → '<NAMESERVER>'

# Usage (automatically resolves)
config.get_variable('COMMUNITY')      # Returns SNMP_COMMUNITY value
config.get_variable('SNMP_COMMUNITY') # Same result
```

## Migration from Old Config

**Old:** `reference/core/config.py` (reference-specific)
**New:** `crack/config/manager.py` (shared across all modules)

**Backward Compatibility:**
The old `reference/core/config.py` now imports from `crack.config`:
```python
# reference/core/config.py
from crack.config import ConfigManager
__all__ = ['ConfigManager']
```

Existing code continues to work:
```python
# Old import still works
from crack.reference.core.config import ConfigManager

# New import (preferred)
from crack.config import ConfigManager
```

## Development

### Adding New Variables

1. Edit `crack/config/variables.py`
2. Add to `VARIABLE_REGISTRY`:
```python
'NEW_VAR': Variable(
    name='NEW_VAR',
    category='network',  # or web, credentials, etc.
    description='Description of this variable',
    example='example_value',
    required=False,
    validation=re.compile(r'^pattern$'),  # Optional
    aliases=['OLD_NAME']  # Optional
)
```
3. No reinstall needed - config loads dynamically

### Adding Validation

1. Edit `crack/config/validators.py`
2. Add validator function:
```python
@staticmethod
def validate_new_type(value: str) -> Tuple[bool, Optional[str]]:
    """Validate new data type"""
    if not value:
        return False, "Value cannot be empty"

    # Custom validation logic
    if not pattern.match(value):
        return False, f"Invalid format: {value}"

    return True, None
```
3. Register in `get_validator_for_variable()`:
```python
validator_map = {
    ...
    'NEW_VAR': Validators.validate_new_type,
}
```

## Benefits

### For Users
- Single `crack config setup` command configures entire toolkit
- Consistent variable names across all modules
- Validation prevents common mistakes
- Auto-detection saves time

### For Developers
- No code duplication (DRY principle)
- Easy to add new variables (one location)
- Validation logic shared across modules
- Module-agnostic (works with track, reference, sessions, etc.)

## Testing

```bash
# Test config management
python3 -c "
from crack.config import ConfigManager
config = ConfigManager()
config.set_variable('LHOST', '10.10.14.5')
print(config.get_variable('LHOST'))
"

# Test validation
python3 -c "
from crack.config import ConfigManager
config = ConfigManager()
success, error = config.set_variable('LHOST', 'invalid')
print(f'Success: {success}, Error: {error}')
"

# Test alias resolution
python3 -c "
from crack.config import ConfigManager
config = ConfigManager()
config.set_variable('SNMP_COMMUNITY', 'public')
print(config.get_variable('COMMUNITY'))  # Should print 'public'
"
```

## File Locations

- **Config file:** `~/.crack/config.json`
- **Module code:** `crack/config/`
- **CLI integration:** `crack/cli.py` (config_command)
- **Reference integration:** `reference/core/placeholder.py`
- **Track integration:** (future) `track/core/state.py`

## Support

For issues or questions:
- GitHub: https://github.com/anthropics/crack
- Documentation: `crack/CLAUDE.md`
- Config help: `crack config` (no args)

---

**Version:** 1.0.0
**Created:** 2025-10-12
**Status:** Production Ready
