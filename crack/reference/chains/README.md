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

---

## Chain Builder

### Overview

The chain builder provides an interactive CLI wizard for creating new attack chains or cloning existing ones. It integrates with the existing validation system to ensure all chains meet schema requirements.

### Quick Start

**Create a new chain from scratch:**
```bash
crack chain-builder create
```

**Clone an existing chain:**
```bash
crack chain-builder clone linux-privesc-suid-basic
```

### Features

1. **Interactive Wizard** - Guided prompts for metadata and steps
2. **Template Cloning** - Start from existing chains
3. **Command Browsing** - Search available commands while building
4. **Real-Time Validation** - Schema, circular dependencies, command references
5. **Auto-Save** - Saves to correct directory based on category

### Workflow

#### Create Mode

```
crack chain-builder create

1. Chain Metadata Prompts:
   - Chain ID (e.g., linux-privesc-suid-basic)
   - Name
   - Description
   - Category (privilege_escalation, enumeration, etc.)
   - Platform (linux, windows, web, etc.)
   - Difficulty (beginner, intermediate, advanced, expert)
   - Time estimate
   - OSCP relevance
   - Author (auto-detected from git config)
   - Tags

2. Step Creation:
   - Name
   - Objective
   - Command reference (enter ID or browse)
   - Step ID (optional, for dependencies)
   - Dependencies (select from previous step IDs)
   - Success criteria

3. Validation:
   - JSON Schema compliance
   - Circular dependency detection
   - Command reference validation
   - Option to save with warnings

4. Save:
   - Auto-generates filepath: reference/data/attack_chains/{category}/{chain-id}.json
   - Pretty-printed JSON with 2-space indent
```

#### Clone Mode

```
crack chain-builder clone linux-privesc-suid-basic

1. Load template chain
2. Prompt for new chain ID
3. Optionally modify steps:
   - Add new steps
   - Delete existing steps
4. Optionally update metadata
5. Validate and save
```

### Command Browsing

When adding a step, you can browse available commands:

```
Command reference options:
  1. Enter command ID directly
  2. Browse available commands

Choice [1/2]: 2

=== BROWSE COMMANDS ===
Search term (or Enter to list all): suid

1. Find SUID Binaries [linux-suid-find]
   Locate files with SUID bit set for privilege escalation

2. Check GTFOBins [linux-gtfobins-lookup]
   Search GTFOBins for SUID binary exploits

Select number (or 'q' to cancel): 1
✓ Selected: Find SUID Binaries
```

### Validation

All chains are validated before saving:

**Schema Validation:**
- Chain ID format: `platform-category-technique-variant`
- Version format: `1.0.0`
- Time estimate format: `10 minutes`
- Difficulty enum: beginner|intermediate|advanced|expert

**Dependency Validation:**
- No circular dependencies in step graph
- All referenced step IDs exist

**Command Reference Validation:**
- All `command_ref` IDs resolve to real commands
- Uses CommandResolver for lookup

**Error Example:**
```
⚠️  Validation failed:
  • Invalid chain ID format. Expected: platform-category-technique-variant
  • Step 'exploit-suid' has circular dependency: exploit-suid → verify-root → exploit-suid
  • Command reference 'invalid-cmd' could not be resolved

Save anyway (not recommended)? [y/N]:
```

### File Structure

**Saved chains:**
```
reference/data/attack_chains/
├── privilege_escalation/
│   ├── linux-privesc-suid-basic.json
│   └── windows-privesc-unquoted-basic.json
├── enumeration/
│   └── web-exploit-sqli-union.json
└── lateral_movement/
    └── windows-lateral-psexec-basic.json
```

**Auto-loaded by ChainRegistry** - No manual registration needed.

### Architecture

**Core Classes:**

- `ChainBuilder` (`reference/builders/chain_builder.py`) - Chain creation/modification logic
- `ChainBuilderCLI` (`reference/cli/chain_builder.py`) - Interactive wizard
- `ChainValidator` (`reference/chains/validator.py`) - Validation (reused)
- `CommandResolver` (`reference/chains/command_resolver.py`) - Command lookup (reused)

**Integration:**
```python
# Leverages existing systems
from crack.reference.builders.chain_builder import ChainBuilder
from crack.reference.chains.validator import ChainValidator
from crack.reference.chains.command_resolver import CommandResolver

builder = ChainBuilder.from_scratch()
builder.set_metadata(id='test-chain', category='privilege_escalation')
builder.add_step({'name': 'Step 1', 'objective': 'Test', 'command_ref': 'test-cmd'})

errors = builder.validate()  # Uses ChainValidator + CommandResolver
if not errors:
    filepath = builder.save()  # Auto-generates path
```

### Examples

**Minimal Chain:**
```bash
crack chain-builder create

Chain ID: linux-test-minimal-basic
Chain name: Minimal Test Chain
Description: Test chain for examples
Category: privilege_escalation
Platform: linux
Difficulty: beginner
Time estimate: 5 minutes
OSCP relevant? [Y/n]: y
Author name: (auto-detected)
Tags: OSCP, TEST

=== ADD STEPS ===

--- Step 1 ---
Step name: Find SUID
Objective: Locate SUID binaries
Command reference: 2 (browse)
  → Search: suid
  → Select: 1 (linux-suid-find)
Step ID: find-suid
Dependencies: (none)
Success criteria: Binaries found

Add another step? [Y/n]: n

=== VALIDATION ===
✓ All validations passed!

=== SAVE ===
✓ Chain saved to: reference/data/attack_chains/privilege_escalation/linux-test-minimal-basic.json
```

**Clone and Modify:**
```bash
crack chain-builder clone linux-privesc-suid-basic

✓ Loaded template: SUID Binary Privilege Escalation
Steps: 6

New chain ID: linux-privesc-suid-advanced

Modify steps? [y/N]: y

Current steps:
  1. Check sudo privileges [check-sudo-privs]
  2. Find SUID binaries [linux-suid-find]
  3. Filter interesting binaries [grep]
  4. Check GTFOBins [linux-gtfobins-lookup]
  5. Exploit SUID binary [manual]
  6. Verify root access [id]

Options:
  a - Add step
  d - Delete step
  q - Done

Choice: a

--- Step 7 ---
Step name: Cleanup
Objective: Remove artifacts
Command reference: cleanup-logs
...

✓ Chain saved to: reference/data/attack_chains/privilege_escalation/linux-privesc-suid-advanced.json
```

### Testing

**Run tests:**
```bash
pytest tests/reference/test_chain_builder.py -v
```

**Test coverage:**
- ChainBuilder core methods (from_scratch, from_template, add_step, validate, save)
- ChainBuilderCLI validation logic
- Error handling (missing required fields, invalid IDs, etc.)
- Template cloning (no mutation of original)
- Dependency management

### Design Decisions

**Why standalone CLI?**
- Faster than TUI for quick chain creation
- Scriptable (future: accept JSON input)
- Lower complexity (no state management)
- Exam-safe (no mouse, no complex UI)

**Why template cloning?**
- Reduces duplicate effort
- Ensures consistency with existing chains
- Easy to create variants (basic → advanced)

**Why auto-save to `reference/data/attack_chains/`?**
- Same location as built-in chains
- Auto-discovered by ChainLoader
- Simpler user experience (no path prompts)
- Easier to contribute back to project

**Why validate before save?**
- Prevents corrupted chains from breaking registry
- Provides immediate feedback
- Allows override for power users (with warning)

### Future Enhancements

- [ ] JSON/YAML import (bulk chain creation)
- [ ] Step reordering (move steps up/down)
- [ ] Dependency visualization (ASCII graph)
- [ ] Export to other formats (Markdown, HTML)
- [ ] TUI integration (`crack track --tui` chain builder panel)
- [ ] Database storage option (PostgreSQL backend)
- [ ] Chain diff/merge (collaborative editing)
- [ ] Validation pre-commit hook (CI/CD integration)
