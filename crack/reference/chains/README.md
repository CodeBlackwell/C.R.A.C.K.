# Attack Chain Parsing System

## Overview

The attack chain system now includes automatic output parsing, variable extraction, and interactive selection. This eliminates manual work and enables intelligent chain progression based on command results.

## Architecture

```
User executes command
  ↓
Raw output captured
  ↓
ParserRegistry finds matching parser
  ↓
Parser extracts structured findings
  ↓
VariableExtractor converts findings → variables
  ↓
FindingSelector presents options (if multiple)
  ↓
Variables stored in VariableContext
  ↓
Next step auto-fills from context
```

## Key Components

### 1. Output Parsers (`parsing/`)

**Base**: `BaseOutputParser` - Abstract interface all parsers implement

**Registry**: Auto-discovery via `@ParserRegistry.register` decorator

**Built-in Parsers**:
- `SUIDParser` - SUID binary enumeration with GTFOBins detection
- *(More parsers coming: Web, SQLi, Network, etc.)*

### 2. Variable Resolution (`variables/`)

**VariableContext** - Hierarchical variable scoping:
1. Step-scoped (highest priority) - From parsing current step
2. Session-scoped - Persists across chain
3. Config-scoped - From `~/.crack/config.json`
4. Default - From command variable definitions

**VariableExtractor** - Maps findings to variables:
- `exploitable_binaries` → `<TARGET_BIN>`
- `directories` → `<TARGET_DIR>`
- `files` → `<TARGET_FILE>`
- *(See `extractors.py` for full mapping)*

### 3. Interactive Selection (`filtering/`)

**FindingSelector** - User-friendly selection UI:
- Auto-select for single option
- Numbered list (1-9 for single-key)
- Multi-select support
- Skip option

### 4. Session Storage (Enhanced)

Stores:
- `step_findings` - Parsed findings per step (for inspection/resume)
- `step_variables` - Step-scoped variables
- `variables` - Session-scoped variables
- `step_outputs` - Raw command outputs

## Example: SUID Chain Flow

**Before Enhancement:**
```
Step 1: find / -perm -4000
→ Output: 120 binaries (user scrolls manually)

Step 2: grep filter
→ Output: 60 binaries (user copies one manually)

Step 3: Visit GTFOBins manually

Step 4: /usr/bin/find . -exec /bin/bash -p \; -quit
→ Hardcoded binary path
```

**After Enhancement:**
```
Step 1: find / -perm -4000
→ Parsing: 120 binaries found
→ SUIDParser: Identified 5 exploitable (vim, find, base64, nmap, python)
→ Stored in step_findings['find-suid']

Step 2: grep filter
→ Auto-skipped (parser already filtered)
→ User prompt: "Select SUID binary to exploit:"
  1. /usr/bin/find (GTFOBins)
  2. /usr/bin/vim (GTFOBins)
  3. /usr/bin/base64 (GTFOBins)
  4. /usr/bin/nmap (GTFOBins)
  5. /usr/bin/python (GTFOBins)
→ User presses '1'
→ <TARGET_BIN> = '/usr/bin/find'

Step 3: Auto-lookup (no user action)
→ GTFOBins technique retrieved

Step 4: Auto-filled command
→ /usr/bin/find . -exec /bin/bash -p \; -quit
→ <TARGET_BIN> resolved from step 2
→ Execute → Root shell
```

## Adding New Parsers

### 1. Create Parser Class

```python
# reference/chains/parsing/my_parser.py
from .base import BaseOutputParser, ParsingResult
from .registry import ParserRegistry

@ParserRegistry.register
class MyParser(BaseOutputParser):
    @property
    def name(self) -> str:
        return "my-parser"

    def can_parse(self, step: Dict, command: str) -> bool:
        return 'my-tool' in command.lower()

    def parse(self, output: str, step: Dict, command: str) -> ParsingResult:
        result = ParsingResult(parser_name=self.name)

        # Extract findings
        findings = {}
        # ... parsing logic ...
        result.findings = findings

        # Auto-resolve single values
        if len(findings['items']) == 1:
            result.variables['<MY_VAR>'] = findings['items'][0]
        # Or require selection
        else:
            result.selection_required['<MY_VAR>'] = findings['items']

        return result
```

### 2. Import in `__init__.py`

```python
# reference/chains/parsing/__init__.py
from .my_parser import MyParser  # Auto-registers via decorator
```

### 3. Use in Chains

Parser automatically activates when `can_parse()` returns `True`. No chain JSON changes needed!

**Optional**: Explicitly specify parser in chain JSON:

```json
{
  "id": "my-step",
  "command_ref": "my-command",
  "output_handling": {
    "parser": "my-parser"
  }
}
```

## Variable Extraction Rules

**Standard Mappings** (`VariableExtractor.EXTRACTION_RULES`):
- `exploitable_binaries` → `<TARGET_BIN>`
- `directories` → `<TARGET_DIR>`
- `files` → `<TARGET_FILE>`
- `open_ports` → `<TARGET_PORT>`
- `users` → `<TARGET_USER>`
- `databases` → `<TARGET_DB>`
- `shares` → `<TARGET_SHARE>`

**Custom Rules**:
```python
VariableExtractor.add_rule('my_finding_key', '<MY_VARIABLE>')
```

## Testing

### Unit Tests
```bash
pytest crack/tests/reference/chains/test_parsers.py
pytest crack/tests/reference/chains/test_variables.py
pytest crack/tests/reference/chains/test_selector.py
```

### Integration Test
```bash
crack reference --chains linux-privesc-suid-basic -i
```

## Debugging

**Enable verbose parsing**:
```python
# In interactive.py, after parse_result
import json
print(json.dumps(parse_result, indent=2))
```

**Check registered parsers**:
```python
from crack.reference.chains.parsing import ParserRegistry
print(ParserRegistry.list_parsers())
```

**Inspect session findings**:
```bash
cat ~/.crack/chain_sessions/linux-privesc-suid-basic-192_168_45_100.json
```

## Design Principles

1. **Zero Configuration** - Parsers self-register via decorators
2. **Graceful Degradation** - Missing parser → store raw output
3. **User Control** - Always show what was parsed, allow skip
4. **Single Responsibility** - Each parser handles one tool/pattern
5. **Composition** - Small, testable, reusable components
6. **No Duplication** - Share parsing with `crack.track.parsers`

## Future Enhancements

- [ ] Web enumeration parser (directories, files, forms)
- [ ] SQLi parser (databases, tables, columns)
- [ ] Network parser (ports, services, versions)
- [ ] Conditional branching (if findings match X, go to step Y)
- [ ] Parallel step execution (enumerate multiple ports simultaneously)
- [ ] Finding-to-documentation export (auto-generate OSCP reports)

## Files Modified

**New**:
- `parsing/base.py` - Base parser interface
- `parsing/registry.py` - Auto-discovery system
- `parsing/suid_parser.py` - SUID implementation
- `variables/context.py` - Variable scoping
- `variables/extractors.py` - Finding→variable mapping
- `filtering/selector.py` - Interactive UI
- `core/step_processor.py` - Orchestration

**Enhanced**:
- `session_storage.py` - Added findings/variables storage
- `interactive.py` - Integrated parsing/selection
