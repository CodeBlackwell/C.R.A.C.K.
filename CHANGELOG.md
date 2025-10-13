# Changelog

All notable changes to the CRACK toolkit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Attack Chains Interactive Mode (`-i` flag)** - Step-by-step guided execution of multi-stage attack chains
  - Full interactive workflow: display → fill → execute → verify → next
  - Session persistence with save/resume functionality (`--resume` flag)
  - Progress tracking across chain steps with automatic checkpointing
  - Session storage in `~/.crack/chain_sessions/` for resume capability
  - Smart target input with default to `.` (local system) for testing
  - Command resolution preview showing actual commands before variable filling

- **Enhanced Chain Display System** - Comprehensive educational interface
  - Chain header enhancements:
    - OSCP relevance indicator with color coding
    - Prerequisites list (what you need before starting)
    - Notes section with word-wrapped OSCP tips and exam context
  - Step display enhancements:
    - Success criteria (expected evidence to look for)
    - Failure conditions (common issues and troubleshooting)
    - Better description formatting with automatic word wrapping
    - Color-coded indicators (✓ green for success, ✗ red for failure)
  - Command filling enhancements:
    - Flag explanations for all command parameters
    - Clear "no variables to fill" message for ready-to-run commands
    - Visual structure showing command name, template, and flags
  - Post-execution enhancements:
    - Verification checklist based on step's success criteria
    - Next step preview showing objective of upcoming step
    - Visual guidance for manual result verification

- **Chain Session Management** - Full state persistence
  - `ChainSession` class for progress tracking
  - JSON storage: `~/.crack/chain_sessions/{chain_id}-{target}.json`
  - Tracks: current step index, completed steps, variables, outputs
  - Automatic save after each step completion
  - Clean session deletion after chain completion

- **Chain Interactive Components** (`crack/reference/chains/`)
  - `session_storage.py` - Session save/load/delete functionality (150 lines)
  - `interactive.py` - Main interactive loop implementation (440 lines)
  - Integration with existing `ChainRegistry`, `ChainLoader`, `CommandResolver`
  - Reuses `HybridCommandRegistry` for command resolution and variable filling
  - Leverages `ConfigManager` for auto-fill (LHOST, LPORT, TARGET)

### Changed
- **Reference CLI** - Added interactive mode support for chains
  - `crack/reference/cli/chains.py` - Added `execute_interactive()` method
  - `crack/reference/cli/main.py` - Added `-i` and `--resume` flag handling
  - Updated help text to include interactive execution examples
  - Chain details footer now suggests `-i` for interactive execution

### Fixed
- Empty target input now defaults to `.` (local system) instead of error
- Command references now display resolved commands before variable filling
- Import path corrected for `ConfigManager` (from `crack.config` not `crack.reference.core.config`)
- Single-keystroke confirmations (Y/n prompts no longer require Enter key)

## Usage Examples

### Interactive Chain Execution
```bash
# Launch interactive chain
crack reference --chains linux-privesc-suid-basic -i

# Resume interrupted session
crack reference --chains linux-privesc-suid-basic -i --resume

# List available chains
crack reference --chains

# View chain details
crack reference --chains web-sqli-postgres-fileretrieve
```

### Session Files
```bash
# View saved sessions
ls ~/.crack/chain_sessions/

# View session state
cat ~/.crack/chain_sessions/linux-privesc-suid-basic-192_168_45_100.json
```

## Technical Details

### Architecture
- **Event-driven**: Integrates with existing command registry and resolver
- **State machine**: Linear step progression with checkpoint persistence
- **Modular design**: Reuses core components (registry, config, theme)
- **Educational focus**: Every step includes learning context

### File Structure
```
crack/reference/chains/
├── session_storage.py   # NEW - Session persistence
├── interactive.py       # NEW - Interactive execution engine
├── registry.py          # Existing - Chain registry
├── loader.py            # Existing - JSON loader
├── command_resolver.py  # Existing - Command resolution
└── validator.py         # Existing - Schema validation

~/.crack/
└── chain_sessions/      # NEW - Session storage
    ├── {chain_id}-{target}.json
    └── ...
```

### Integration Points
- **HybridCommandRegistry**: Command resolution and placeholder filling
- **ConfigManager**: Auto-fill for <LHOST>, <LPORT>, <TARGET>
- **ReferenceTheme**: Consistent color scheme and formatting
- **CommandResolver**: Resolves command_ref to actual commands

## Testing

All features tested with:
- `linux-privesc-suid-basic` (5 steps, beginner)
- `web-sqli-postgres-fileretrieve` (9 steps, intermediate)
- Session save/resume workflow
- Empty target handling
- Command preview display

## Future Enhancements

Potential V2 features (post-real-world testing):
- Auto-detect success/failure via output parsing
- Jump-to-step navigation (`j` shortcut)
- Retry with command editing (`r` shortcut)
- Output viewer overlay (`o` shortcut)
- Keyboard shortcuts (match `track -i` UX)
- Variable persistence across steps
- Conditional branching based on results

---

## Development Stats

- **Implementation time**: ~5 hours (MVP + enhancements)
- **Lines added**: ~600 (session_storage.py + interactive.py)
- **Files modified**: 4 (interactive.py, session_storage.py, chains.py, main.py)
- **Test coverage**: Manual testing on 4 available chains
