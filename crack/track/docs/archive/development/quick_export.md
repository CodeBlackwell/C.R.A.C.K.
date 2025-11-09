# Quick Export (qx) Implementation Summary

## Overview

Implemented the **qx (Quick Export)** tool for CRACK Track Interactive Mode, enabling users to export findings, tasks, credentials, notes, port scan results, and full status reports to files or clipboard in multiple formats (text, markdown, JSON).

## Implementation Details

### Files Modified

1. **crack/track/interactive/session.py** (~500 lines added)
   - Main handler: `handle_quick_export()` - Interactive export menu
   - Export helpers:
     - `_get_export_dir()` - Creates ~/.crack/exports/TARGET/
     - `_has_clipboard()` - Detects xclip/xsel
     - `_copy_to_clipboard()` - Clipboard integration
     - `_generate_export_content()` - Content router
   - Format methods:
     - `_format_status()` - Full status report (markdown/JSON)
     - `_format_task_tree()` - Task tree (text/JSON)
     - `_format_findings()` - Findings (markdown/text/JSON)
     - `_format_credentials()` - Credentials (markdown table/text/JSON)
     - `_format_notes()` - Notes (markdown/text/JSON)
     - `_format_ports()` - Port scan results (markdown table/text/JSON)

2. **crack/track/interactive/shortcuts.py** (3 lines)
   - Added shortcut registration: `'qx': ('Quick export', 'quick_export')`
   - Added handler method: `quick_export()`

3. **crack/track/interactive/input_handler.py** (1 line)
   - Added 'qx' to SHORTCUTS list for input recognition

4. **crack/track/interactive/prompts.py** (1 line)
   - Updated help text with qx shortcut description

5. **crack/tests/track/test_quick_export.py** (NEW - 460 lines)
   - Comprehensive test coverage with 27 tests
   - All tests passing ✓

## Features

### Export Types
1. **Status Report** - Full profile status with recommendations
2. **Task Tree** - Complete task hierarchy
3. **Findings** - All documented vulnerabilities/discoveries
4. **Credentials** - Authentication credentials found
5. **Notes** - General notes and observations
6. **Ports** - Port scan results with services/versions
7. **Profile** - Complete profile dump (JSON only)

### Export Formats
- **Markdown** - Human-readable reports with tables/headings
- **Plain Text** - Simple text format for terminals
- **JSON** - Machine-readable structured data

### Export Destinations
- **File** - Saves to ~/.crack/exports/TARGET/
- **Clipboard** - Copies to system clipboard (if xclip/xsel available)
- **Both** - Exports to both file and clipboard

### File Naming Convention
```
~/.crack/exports/TARGET/TYPE_YYYYMMDD_HHMMSS.EXT

Examples:
findings_20251008_145030.md
credentials_20251008_145100.txt
status_20251008_145200.json
```

## Usage Example

```
Interactive Mode
TARGET: 192.168.45.100

Choice: qx

Quick Export
==================================================

Select what to export:
  1. Full status report (markdown)
  2. Task tree (text tree format)
  3. Findings only (markdown list)
  4. Credentials only (markdown table)
  5. Notes only (markdown list)
  6. Port scan results (text)
  7. Full profile (JSON)

Choice [1-7]: 3

Export to:
  [c] Clipboard
  [f] File (default)
  [b] Both
  [x] Cancel

Destination [f]: b

Export format:
  [t] Plain text
  [m] Markdown (default)
  [j] JSON

Format [m]: m

Exporting findings to markdown...

✓ Copied to clipboard
✓ Exported to: /home/kali/.crack/exports/192.168.45.100/findings_20251008_145030.md
  Size: 1247 bytes

View file? [y/N]: n
```

## Test Coverage

### Test Classes (27 tests total)

1. **TestQuickExportShortcut** (3 tests)
   - Shortcut registration
   - Input handler recognition
   - Handler callable

2. **TestExportDirectory** (2 tests)
   - Directory creation
   - Persistence across sessions

3. **TestFindingsExport** (4 tests)
   - Markdown format
   - JSON format
   - Text format
   - Empty findings handling

4. **TestCredentialsExport** (3 tests)
   - Markdown table format
   - JSON format
   - Text format

5. **TestPortsExport** (2 tests)
   - Markdown table
   - Text format

6. **TestNotesExport** (1 test)
   - Markdown format

7. **TestTaskTreeExport** (1 test)
   - JSON format

8. **TestStatusExport** (1 test)
   - Full status report

9. **TestClipboardDetection** (3 tests)
   - xclip detection
   - xsel detection
   - No clipboard tools

10. **TestFileExport** (2 tests)
    - File naming convention
    - Content preservation

11. **TestExportContentGeneration** (3 tests)
    - Status export
    - Profile JSON export
    - Invalid type handling

12. **TestExportIntegration** (2 tests)
    - Full workflow
    - Multiple exports

**All 27 tests passing ✓**

## Architecture

### Directory Structure
```
~/.crack/
├── targets/           # Profile storage
├── sessions/          # Session checkpoints
├── snapshots/         # Session snapshots
└── exports/           # Quick exports (NEW)
    └── TARGET/
        ├── findings_*.md
        ├── credentials_*.md
        ├── tasks_*.txt
        ├── status_*.md
        └── profile_*.json
```

### Integration Points

**Formatters Integration:**
- Uses existing `ConsoleFormatter` for task tree and status reports
- Custom formatters for findings, credentials, notes, ports

**Profile Integration:**
- Accesses `profile.findings`, `profile.credentials`, `profile.notes`, `profile.ports`
- Uses `profile.to_dict()` for full JSON export

**Clipboard Integration (Optional):**
- Detects xclip or xsel automatically
- Gracefully degrades if not available
- Cross-platform compatible (Linux-focused)

## Key Design Decisions

1. **Multiple Formats** - Supports markdown (human-readable), text (simple), and JSON (machine-readable)
2. **Auto-naming** - Timestamp-based filenames prevent overwrites
3. **Organized Storage** - Per-target export directories for clarity
4. **Optional Clipboard** - Works without clipboard tools (file-only mode)
5. **Empty Data Handling** - Gracefully handles empty findings/credentials/notes
6. **Consistent Tables** - Markdown tables for credentials and ports
7. **Source Tracking** - All exports include source attribution (OSCP requirement)

## Lines of Code

- Implementation: ~500 lines (session.py)
- Tests: ~460 lines (test_quick_export.py)
- Integrations: ~5 lines (shortcuts.py, input_handler.py, prompts.py)
- **Total: ~965 lines**

## Success Criteria Met

✓ Single keystroke ('qx') opens export menu
✓ Exports findings, tasks, status, credentials, notes, ports
✓ Supports text, markdown, and JSON formats
✓ Auto-names files with timestamp
✓ Optionally copies to clipboard (if xclip/xsel available)
✓ Creates organized export directory structure
✓ All 27 tests passing
✓ ~500 lines of implementation
✓ No external dependencies (clipboard optional)
✓ Proper error handling for empty data
✓ Human-readable markdown output
✓ OSCP-compliant source tracking

## Future Enhancements

- PDF export support
- HTML report generation with CSS styling
- Email export (send reports to specified address)
- Encrypted exports for sensitive credentials
- Export templates (custom markdown/HTML templates)
- Diff exports (compare two sessions)
- Batch export (export multiple targets at once)

## Documentation

- Updated help text in interactive mode
- Inline comments in code
- Comprehensive test documentation
- This implementation summary

## Performance

- Export time: <1 second for typical profiles
- File size: ~1-5 KB for markdown exports
- Memory usage: Minimal (streaming writes)
- No blocking operations (async-ready if needed)

## Compatibility

- Python 3.8+
- Linux (Kali Linux tested)
- Works with or without clipboard tools
- Compatible with existing CRACK Track infrastructure

---

**Implementation Date:** 2025-10-08
**Tool ID:** qx
**Status:** Complete ✓
**Tests:** 27/27 passing ✓
