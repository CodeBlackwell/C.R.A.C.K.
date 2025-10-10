# Foundation Components Integration Checklist

**Status**: 2/11 tasks completed (18%)

## ✅ Completed

- [x] Debug checkpoint detection in CLI mode (InteractiveSession)
- [x] Add checkpoint detection to TUISessionV2.run()

## 📋 Remaining Tasks

### Phase 1: CLI Mode Integration (session.py)

- [ ] **Add InputValidator integration to session.py**
  - Import: Already imported in `__init__` (line 66)
  - Integrate: Use `self.validator.validate_*()` in user input methods
  - Target methods:
    - `add_finding()` - validate IPs, ports
    - `add_credential()` - validate username, port, service
    - `import_scan_file()` - validate file paths
    - `_get_port_choice()` - validate port numbers
    - Any input() prompts that accept IPs/ports/paths

- [ ] **Add ErrorHandler integration to session.py**
  - Import: Already imported in `__init__` (line 67)
  - Integrate: Wrap try/except blocks with `self.error_handler.handle()`
  - Target areas:
    - File operations (import, export)
    - Profile operations (save, load)
    - Command execution
    - User input validation failures

- [ ] **Add LoadingIndicators to long-running operations in session.py**
  - Import: Already available from components
  - Integrate: Wrap long operations with Spinner/ProgressBar
  - Target operations:
    - File imports (nmap scans)
    - Profile loading/saving
    - Command execution (if in CLI mode)
    - Wordlist scanning

### Phase 2: TUI Mode Integration (tui_session_v2.py)

- [ ] **Integrate ResizeHandler into TUISessionV2**
  - Location: `__init__()` and `run()`
  - Actions:
    - Import ResizeHandler in `__init__()`
    - Call `ResizeHandler.setup_handler(callback)` before Live context
    - Implement `_handle_resize()` callback method
    - Check minimum size with `ResizeHandler.check_minimum_size()`
    - Gracefully handle too-small terminals

- [ ] **Wire FindingFormPanel into TUISessionV2 via ExecutionOverlay**
  - Location: `ExecutionOverlay.execute_choice()` in overlays/execution_overlay.py
  - Actions:
    - Add case for choice_id == 'finding' or 'document-finding'
    - Instantiate FindingFormPanel(profile)
    - Call panel methods to collect data
    - Save to profile.add_finding()
    - Return to dashboard

- [ ] **Wire CredentialFormPanel into TUISessionV2 via ExecutionOverlay**
  - Location: `ExecutionOverlay.execute_choice()`
  - Actions:
    - Add case for choice_id == 'credential' or 'add-cred'
    - Instantiate CredentialFormPanel(profile)
    - Call panel methods to collect data
    - Save to profile.add_credential()
    - Return to dashboard

- [ ] **Wire ImportForm into TUISessionV2 via ExecutionOverlay**
  - Location: `ExecutionOverlay.execute_choice()`
  - Actions:
    - Add case for choice_id == 'import' or 'import-scan'
    - Instantiate ImportForm(profile)
    - Call panel methods to select file
    - Parse file with ParserRegistry
    - Return to dashboard

- [ ] **Wire NoteFormPanel into TUISessionV2 via ExecutionOverlay**
  - Location: `ExecutionOverlay.execute_choice()`
  - Actions:
    - Add case for choice_id == 'note' or 'add-note'
    - Instantiate NoteFormPanel(profile)
    - Call panel methods to collect note text
    - Save to profile.add_note()
    - Return to dashboard

### Phase 3: Testing

- [ ] **Test CLI mode with validation and error handling**
  - Test InputValidator on invalid IPs, ports, paths
  - Test ErrorHandler catches and displays errors correctly
  - Test LoadingIndicator shows during long operations
  - Test checkpoint detection with test scripts

- [ ] **Test TUI mode with all integrated forms and components**
  - Test ResizeHandler on terminal resize events
  - Test FindingFormPanel form submission
  - Test CredentialFormPanel form submission
  - Test ImportForm file selection and parsing
  - Test NoteFormPanel note submission
  - Test checkpoint detection in TUI mode

## 📝 Notes

### Component Locations
- **Components**: `track/interactive/components/`
  - `input_validator.py` - Already imported ✓
  - `error_handler.py` - Already imported ✓
  - `loading_indicator.py` - Available for import
  - `resize_handler.py` - Ready for integration

- **Panels**: `track/interactive/panels/`
  - `finding_form.py` - Already exported ✓
  - `credential_form.py` - Already exported ✓
  - `import_form.py` - Already exported ✓
  - `note_form.py` - Already exported ✓

- **State**: `track/interactive/state/`
  - `checkpoint_manager.py` - Already integrated ✓

### ExecutionOverlay Location
- File: `track/interactive/overlays/execution_overlay.py`
- Method: `execute_choice(live, session, choice)`
- Pattern: Stop Live → Show form → Collect data → Resume Live

### Testing Scripts
- `create_test_checkpoints.py` - Creates fake interrupted tasks
- `clear_test_checkpoints.py` - Cleans up test checkpoints

## 🎯 Next Steps

**Recommended order:**
1. Start with CLI mode integrations (easier to test)
2. Move to TUI ResizeHandler (foundational)
3. Wire form panels one at a time (test each)
4. Final comprehensive testing

**Time Estimate**: ~4-6 hours for all remaining tasks
