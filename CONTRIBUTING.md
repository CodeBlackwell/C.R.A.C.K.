# CRACK Toolkit Contribution Guide

## Adding New Tools to CRACK

Follow these steps for seamless integration of new commands into the CRACK toolkit.

**All tools are accessed via**: `crack <tool-name> [options]`

### 1. Create Your Tool Script

**Location:** `/home/kali/OSCP/crack/enumeration/your_tool.py`

```python
#!/usr/bin/env python3
"""Tool description"""

import argparse
import sys

# Import utilities
try:
    from ..utils.colors import Colors
except ImportError:
    sys.path.insert(0, '/home/kali/OSCP')
    from crack.utils.colors import Colors

def main():
    parser = argparse.ArgumentParser(
        description='Your tool description',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    # Add arguments
    args = parser.parse_args()
    # Tool logic here

if __name__ == '__main__':
    main()
```

### 2. Add CLI Integration

**File:** `/home/kali/OSCP/crack/cli.py`

Add two components:

#### 2.1 Command Function (around line 40-60)
```python
def your_tool_command(args):
    """Execute your tool"""
    from crack.enumeration import your_tool
    sys.argv = ['your_tool'] + args
    your_tool.main()
```

#### 2.2 Subparser Registration (around line 115-120)
```python
# Your Tool subcommand
your_tool_parser = subparsers.add_parser('your-tool',
                                         help='Your Tool Description',
                                         add_help=False)
your_tool_parser.set_defaults(func=your_tool_command)
```

### 3. Update Package Configuration

#### 3.1 Edit `pyproject.toml`

**Note:** The main `crack` command is already configured. No additional script entries needed.

**If creating a submodule, add to `[tool.setuptools]` packages:**
```toml
packages = ["crack", "crack.enumeration", "crack.enumeration.your_module", "crack.utils"]
```

#### 3.2 Edit `setup.py` (if maintaining both)

**Note:** The main `crack` command entry point should already exist. No additional entries needed.

### 4. Update Documentation

#### 4.1 CLI Help Text (`crack/cli.py` line ~68-78)
```python
Available Tools:
  your-tool       Your Tool - Brief description

Examples:
  crack your-tool [options]
```

#### 4.2 README.md
- Add tool description to features section
- Add usage examples
- Update package structure if needed

### 5. Install and Test

```bash
# Uninstall existing
pip uninstall crack-toolkit -y --break-system-packages 2>/dev/null

# Reinstall with new changes
pip install -e . --break-system-packages

# Test the command
crack your-tool --help           # Via crack CLI
python3 crack/enumeration/your_tool.py --help  # Direct execution (for development)
```

### 6. Module Organization (Optional)

For complex tools with multiple files:

```
crack/enumeration/your_module/
├── __init__.py          # Module exports
├── __main__.py          # Allow: python -m crack.enumeration.your_module
├── core.py              # Core logic
├── utils.py             # Helper functions
└── your_tool.py         # CLI entry point
```

**`__init__.py`:**
```python
from .core import YourClass
__all__ = ['YourClass']
```

**`__main__.py`:**
```python
from .your_tool import main
if __name__ == '__main__':
    main()
```

### 7. Integration Checklist

- [ ] Tool script created in `crack/enumeration/`
- [ ] Imports use relative imports with fallback
- [ ] `main()` function with argparse
- [ ] CLI command function added
- [ ] Subparser registered
- [ ] README.md updated
- [ ] Package reinstalled
- [ ] Command tested via `crack your-tool`

### 8. Color Standards

Use consistent colors from `crack.utils.colors`:
- `Colors.BOLD` + `Colors.GREEN` - Success/Headers
- `Colors.YELLOW` - Warnings/Categories
- `Colors.RED` - Errors/Critical
- `Colors.CYAN` - Information/Items
- `Colors.BLUE` - Sub-information

### 9. Naming Conventions

- **Files:** `snake_case.py`
- **Subcommands:** `kebab-case` (e.g., `crack your-tool`)
- **Classes:** `PascalCase`
- **Functions:** `snake_case`

### 10. Testing Requirements

Before submitting:
1. Tool works standalone for development: `python3 crack/enumeration/your_tool.py`
2. Tool works via crack CLI: `crack your-tool`
3. Help text displays correctly
4. Error handling for missing arguments
5. Graceful KeyboardInterrupt handling

---

## Quick Integration Example

Adding a new tool called "dns-enum":

```bash
# 1. Create tool
vim crack/enumeration/dns_enum.py

# 2. Add to CLI
vim crack/cli.py
# Add: dns_enum_command() and subparser

# 3. Reinstall
pip uninstall crack-toolkit -y --break-system-packages
pip install -e . --break-system-packages

# 4. Test
crack dns-enum --help
```

---

**Note:** Always maintain backward compatibility. Never remove existing commands or change their interfaces without proper deprecation notices.