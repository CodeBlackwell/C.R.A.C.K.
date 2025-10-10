TUI Development Roadmap - Layered Pipeline Approach

  ROADMAP_CHECKLIST.md

  # TUI Layered Pipeline Development Checklist
  **Approach:** 4 Parallel Agents per Stage | 3 Stages | Review Gates
  **Total Duration:** 10-12 hours
  **Risk Level:** MEDIUM
  **Generated:** 2025-10-10

  ---

  ## Pre-Flight Checklist

  ### Environment Setup
  - [ ] Verify working directory: `/home/kali/OSCP/crack`
  - [ ] Run initial test suite: `./run_tests.sh track`
  - [ ] Record baseline pass rate: ____%
  - [ ] Create development branch: `git checkout -b tui-layered-pipeline`
  - [ ] Clear debug logs: `rm -f .debug_logs/tui_debug_*.log`
  - [ ] Kill any running TUI sessions
  - [ ] Backup current profile: `cp ~/.crack/targets/testbox-192.168.45.100.json
  ~/.crack/targets/testbox-192.168.45.100.json.backup`

  ### Agent Assignment Strategy
  - Agents work on DIFFERENT files when possible
  - If same file (`session.py`), work on DIFFERENT methods
  - Each agent creates own test file
  - Integration handled at review gates

  ---

  ## STAGE 1: Foundation (3 hours)
  **Goal:** Fix critical bugs, add missing handlers, establish test infrastructure

  ### Agent 1.1: Bug Fix & Test Harness
  **Duration:** 45 minutes
  **Files:**
  - `track/interactive/hotkey_input.py`
  - `tests/track/interactive/test_tui_startup.py` (create)

  #### Tasks:
  - [ ] Fix LogLevel.DEBUG → LogLevel.VERBOSE (line 42)
  - [ ] Create TUI startup test
  - [ ] Test basic navigation (h, s, t, q)
  - [ ] Document any other startup bugs found
  - [ ] Create `tests/track/interactive/test_fixtures.py` with common mocks

  #### Success Criteria:
  ```bash
  crack track --tui testbox-192.168.45.100 --debug
  # TUI starts without crash
  # Config panel displays
  # Can navigate to dashboard

  Agent 1.2: Progress Dashboard Handler

  Duration: 2 hours
  Files:
  - track/interactive/session.py (add method ~line 3800)
  - tests/track/interactive/test_progress_dashboard.py

  Tasks:

  - Add handle_progress_dashboard() method
  - Calculate progress metrics (completed/total)
  - Create ASCII progress bar
  - Group tasks by service
  - Identify quick wins
  - Highlight high priority tasks
  - Show next recommended task
  - Add tests (13 test cases from roadmap)

  Success Criteria:

  pytest tests/track/interactive/test_progress_dashboard.py -v
  # All tests pass
  # Manual test: press 'pd' in TUI shows dashboard

  Agent 1.3: Session Snapshot Handler

  Duration: 2 hoursFiles:
  - track/interactive/session.py (fix method ~line 3900)
  - tests/track/interactive/test_session_snapshot.py

  Tasks:

  - Fix handle_session_snapshot() method
  - Add filename sanitization (regex)
  - Fix timestamp format in filename
  - Fix list_snapshots() return structure
  - Add delete functionality
  - Validate empty names
  - Create snapshot directory structure
  - Add tests (16 test cases)

  Success Criteria:

  pytest tests/track/interactive/test_session_snapshot.py -v
  # All tests pass
  # Manual test: 'ss' saves/restores/lists/deletes

  Agent 1.4: Task Retry & Error Handler

  Duration: 45 minutes
  Files:
  - track/interactive/session.py (update sorting)
  - tests/track/interactive/test_task_retry.py
  - Integration points for ErrorHandler

  Tasks:

  - Fix task retry sorting (by failed_at timestamp)
  - Add failed_at to task metadata on failure
  - Integrate ErrorHandler in execute_task()
  - Add ErrorHandler to input validation
  - Test retry order is correct
  - Test error messages display properly

  Success Criteria:

  pytest tests/track/interactive/test_task_retry.py -v
  # Sorting test passes
  # Error handler shows OSCP-specific suggestions

  🔍 STAGE 1 REVIEW GATE (30 minutes)

  Test Runner Checklist:

  - Run: pytest tests/track/interactive/test_tui_startup.py -v
  - Run: pytest tests/track/interactive/test_progress_dashboard.py -v
  - Run: pytest tests/track/interactive/test_session_snapshot.py -v
  - Run: pytest tests/track/interactive/test_task_retry.py -v
  - Run: ./run_tests.sh track (compare to baseline)
  - Manual test: Start TUI, test pd, ss, error display
  - Check logs: grep ERROR .debug_logs/tui_debug_*.log

  Go/No-Go Decision:

  - ✅ All Stage 1 tests passing → PROCEED TO STAGE 2
  - ⚠️ Minor issues (<3 failures) → Fix then proceed
  - 🔴 Major issues (>3 failures) → STOP, debug, reassign agents

  Rollback Procedure (if needed):

  git stash
  git checkout track/interactive/hotkey_input.py track/interactive/session.py
  rm tests/track/interactive/test_tui_startup.py
  rm tests/track/interactive/test_progress_dashboard.py
  rm tests/track/interactive/test_session_snapshot.py
  rm tests/track/interactive/test_task_retry.py

  ---
  STAGE 2: Core Features (4 hours)

  Goal: Implement high-ROI shortcuts that other features depend on

  Agent 2.1: Quick Note + Note Form

  Duration: 2 hours
  Files:
  - track/interactive/shortcuts.py (add qn)
  - track/interactive/session.py (add handle_quick_note)
  - track/interactive/panels/note_form.py (integrate)
  - tests/track/interactive/test_quick_note.py

  Tasks:

  - Register 'qn' shortcut
  - Add handle_quick_note() method
  - Direct note append (no form for quick)
  - Auto-timestamp notes
  - Source tracking ("quick-note" default)
  - Optional form for detailed notes
  - Save to profile.notes
  - Add 8 tests

  Success Criteria:

  # Quick test
  echo "test note" | crack track -i testbox-192.168.45.100
  > qn Found SQLi in login form
  # Note saved with timestamp

  Agent 2.2: Task Filter + Search

  Duration: 2 hours
  Files:
  - track/interactive/shortcuts.py (add tf)
  - track/interactive/session.py (add handle_task_filter)
  - track/interactive/search.py (create)
  - tests/track/interactive/test_task_filter.py

  Tasks:

  - Register 'tf' shortcut
  - Create filter parser (port:80 status:pending)
  - Filter by: status, port, service, tags
  - Display filtered results in table
  - Actions: execute, export, clear filter
  - Maintain filter state in session
  - Support combined filters
  - Add 10 tests

  Success Criteria:

  > tf port:80 status:pending
  # Shows only pending HTTP tasks
  > tf tag:QUICK_WIN
  # Shows high-value tasks

  Agent 2.3: Command History + Storage

  Duration: 2 hours
  Files:
  - track/interactive/shortcuts.py (add ch)
  - track/interactive/session.py (add handle_command_history)
  - track/interactive/history.py (create)
  - tests/track/interactive/test_command_history.py

  Tasks:

  - Register 'ch' shortcut
  - Store commands with timestamp, status, output length
  - Search history (fuzzy match)
  - Filter by success/failed
  - Export to file
  - Limit history size (configurable, default 1000)
  - Display with pagination
  - Add 8 tests

  Success Criteria:

  > ch
  # Shows command history
  > ch gobuster
  # Shows only gobuster commands
  > ch --failed
  # Shows only failed commands

  Agent 2.4: Batch Execute + Progress

  Duration: 2 hours
  Files:
  - track/interactive/shortcuts.py (add be)
  - track/interactive/session.py (update _execute_batch)
  - track/interactive/components/loading_indicator.py (use existing)
  - tests/track/interactive/test_batch_execute.py

  Tasks:

  - Register 'be' shortcut
  - Parse selection (1-5, 1,3,5, or filter)
  - Dependency analysis (sequential vs parallel)
  - Real-time progress bar with LoadingIndicator
  - Show task status (✓/✗)
  - Calculate ETA
  - Handle interruption (Ctrl+C)
  - Add 12 tests

  Success Criteria:

  > be 1-5
  # Executes tasks 1-5 with progress bar
  [##########----------] 50% | ✓ nmap-scan

  🔍 STAGE 2 REVIEW GATE (30 minutes)

  Test Runner Checklist:

  - Run: pytest tests/track/interactive/test_quick_note.py -v
  - Run: pytest tests/track/interactive/test_task_filter.py -v
  - Run: pytest tests/track/interactive/test_command_history.py -v
  - Run: pytest tests/track/interactive/test_batch_execute.py -v
  - Integration test: All 4 shortcuts together
  - Profile persistence test: cat ~/.crack/targets/testbox-192.168.45.100.json | jq .notes

  Manual Test Sequence:

  crack track -i testbox-192.168.45.100
  > qn Test note from Stage 2
  > tf port:80
  > be 1-3
  > ch --success
  > q
  # Restart and verify data persisted

  Go/No-Go Decision:

  - ✅ Core features working → PROCEED TO STAGE 3
  - ⚠️ Minor issues → Fix during Stage 3
  - 🔴 Major issues → STOP, fix Stage 2 before proceeding

  ---
  STAGE 3: Enhanced Features (3 hours)

  Goal: Build features that leverage Stage 2 infrastructure

  Agent 3.1: Time Tracker + Session Timing

  Duration: 1.5 hours
  Files:
  - track/interactive/shortcuts.py (add tt)
  - track/interactive/session.py (add handle_time_tracker)
  - track/interactive/timing.py (create)
  - tests/track/interactive/test_time_tracker.py

  Tasks:

  - Register 'tt' shortcut
  - Track session start time
  - Track time per phase
  - Track time per task
  - Exam countdown mode (optional)
  - Alert on long-running tasks (>20min)
  - Display time breakdown
  - Add 6 tests

  Success Criteria:

  > tt
  Session Time: 1h 45m
  Discovery: 15m (15%)
  Enumeration: 45m (45%)

  Agent 3.2: Quick Export + Formatting

  Duration: 1.5 hours
  Files:
  - track/interactive/shortcuts.py (add qx)
  - track/interactive/session.py (add handle_quick_export)
  - track/interactive/exporters.py (create)
  - tests/track/interactive/test_quick_export.py

  Tasks:

  - Register 'qx' shortcut
  - Export formats: findings, status, commands, json, timeline
  - Clipboard support (xclip integration)
  - File export with timestamp
  - Markdown formatting
  - JSON structured output
  - Add 8 tests

  Success Criteria:

  > qx findings
  ✓ Exported to findings_192.168.45.100_20251010.md
  > qx commands --clipboard
  ✓ Copied to clipboard

  Agent 3.3: Finding Correlator + Import

  Duration: 1.5 hours
  Files:
  - track/interactive/shortcuts.py (add fc)
  - track/interactive/session.py (add handle_finding_correlator)
  - track/interactive/panels/import_form.py (integrate)
  - tests/track/interactive/test_finding_correlator.py

  Tasks:

  - Register 'fc' shortcut
  - Detect credential reuse opportunities
  - Identify attack chains
  - CVE correlation with versions
  - Cache CVE database (from roadmap)
  - Integrate import form for scan results
  - Confidence scoring
  - Add 10 tests

  Success Criteria:

  > fc
  🔑 CREDENTIAL REUSE: admin:password found
    → Untested: SSH (22), SMB (445)
  🔗 ATTACK CHAIN: LFI → Config → Database → Shell

  Agent 3.4: Port Lookup + Quick Execute

  Duration: 1.5 hours
  Files:
  - track/interactive/shortcuts.py (add pl, qe)
  - track/interactive/session.py (add handlers)
  - track/interactive/references.py (create)
  - tests/track/interactive/test_port_tools.py

  Tasks:

  - Register 'pl' and 'qe' shortcuts
  - Port database (common OSCP ports)
  - Service enumeration commands
  - Common vulnerabilities per port
  - Quick execute without task tracking
  - Optional output capture
  - OSCP relevance scoring
  - Add 8 tests

  Success Criteria:

  > pl 445
  Port 445 - SMB
  Enumeration: enum4linux, smbclient, smbmap
  CVEs: EternalBlue (MS17-010)
  > qe nc -nv 192.168.45.100 80
  [output displayed]

  🔍 STAGE 3 REVIEW GATE (30 minutes)

  Test Runner Checklist:

  - Run all Stage 3 tests
  - Run full test suite: ./run_tests.sh track
  - Check test coverage: pytest --cov=track.interactive --cov-report=term-missing
  - Performance test: Execute 20 tasks, measure time
  - Memory test: Check for leaks after 100 operations

  Integration Test:

  # Complex workflow using Stage 1-3 features
  crack track -i testbox-192.168.45.100
  > import scan.xml        # Stage 3
  > tf port:80             # Stage 2
  > be 1-5                 # Stage 2
  > fc                     # Stage 3
  > qn Found SQLi          # Stage 2
  > tt                     # Stage 3
  > qx findings            # Stage 3
  > pd                     # Stage 1

  Go/No-Go Decision:

  - ✅ All features integrated → PROCEED TO STAGE 4
  - ⚠️ Performance issues → Optimize in Stage 4
  - 🔴 Integration failures → Fix before Stage 4

  ---
  STAGE 4: Forms & Polish (2 hours)

  Goal: Visual polish, form integration, UX improvements

  Agent 4.1: Finding + Credential Forms

  Duration: 1 hour
  Files:
  - track/interactive/panels/finding_form.py
  - track/interactive/panels/credential_form.py
  - track/interactive/session.py (integrate)
  - tests/track/interactive/test_forms.py

  Tasks:

  - Integrate finding form with dashboard
  - Multi-step wizard for findings
  - Integrate credential form
  - Form validation
  - Connect to profile storage
  - Add 10 tests

  Agent 4.2: Smart Confirmation Mode

  Duration: 45 minutes
  Files:
  - track/interactive/shortcuts.py (add c)
  - track/interactive/session.py (add confirmation logic)
  - tests/track/interactive/test_confirmation_mode.py

  Tasks:

  - Register 'c' shortcut
  - Modes: always, smart, never, batch
  - Skip read-only in smart mode
  - User preference persistence
  - Add 6 tests

  Agent 4.3: Error Messages + Help

  Duration: 45 minutes
  Files:
  - track/interactive/overlays/help_overlay.py (update)
  - track/interactive/components/error_handler.py (integrate everywhere)
  - tests/track/interactive/test_help_system.py

  Tasks:

  - Update help with all shortcuts
  - Add context-sensitive help
  - Integrate ErrorHandler in all try-except
  - OSCP-specific error messages
  - Add 5 tests

  Agent 4.4: Documentation + Changelog

  Duration: 30 minutes
  Files:
  - CHANGELOG.md
  - track/docs/INTERACTIVE_MODE_GUIDE.md
  - track/docs/components/SHORTCUTS_REFERENCE.md (create)

  Tasks:

  - Update CHANGELOG with all changes
  - Mark implemented shortcuts in guide
  - Create quick reference card
  - Update help text
  - Add usage examples

  🔍 FINAL REVIEW GATE (1 hour)

  Complete Test Suite:

  # Unit tests
  pytest tests/track/interactive/ -v --tb=short

  # Integration test
  ./run_tests.sh track

  # Coverage report
  pytest --cov=track.interactive --cov-report=html
  open htmlcov/index.html

  # Manual 30-minute session
  crack track -i testbox-192.168.45.100
  # Test ALL shortcuts systematically

  Acceptance Criteria:

  - Test pass rate > 95%
  - No crashes in 30min session
  - All 12 high-priority shortcuts working
  - Forms validate input correctly
  - Error messages helpful
  - Debug logs clean
  - Documentation updated

  Production Deployment:

  # If all tests pass
  git add -A
  git commit -m "feat(tui): implement layered pipeline features

  - Stage 1: Fixed critical bugs, added pd/ss handlers
  - Stage 2: Added qn, tf, ch, be shortcuts
  - Stage 3: Added tt, qx, fc, pl, qe features  
  - Stage 4: Integrated forms, smart confirmation

  Test coverage: 95%+
  All shortcuts documented in INTERACTIVE_MODE_GUIDE.md"

  git checkout main
  git merge tui-layered-pipeline

  ---
  Rollback Procedures

  Stage Rollback:

  # Save work in progress
  git stash

  # Rollback specific stage
  git checkout HEAD~1  # Previous stage

  # Or complete reset
  git checkout main
  git branch -D tui-layered-pipeline

  Individual Agent Rollback:

  # Revert specific file
  git checkout -- track/interactive/session.py

  # Remove test file
  rm tests/track/interactive/test_[feature].py

  ---
  Post-Implementation

  Monitoring (1 week):

  - Track debug logs for errors
  - Monitor shortcut usage frequency
  - Collect user feedback
  - Document pain points
  - Plan Phase 2 features

  Phase 2 Candidates:

  - Fuzzy search (/)
  - Command templates (x)
  - Workflow recorder (wr)
  - Success analyzer (sa)
  - Smart suggest (sg)

  ---
  Emergency Contacts

  If stage fails:
  1. Check debug logs: grep ERROR .debug_logs/tui_debug_*.log | tail -20
  2. Run minimal test: python3 -c "from crack.track.interactive.tui_session_v2 import 
  TUISessionV2"
  3. Rollback that stage
  4. Reassign agent work

  Common Issues:
  - Import errors → Check __init__.py files
  - Merge conflicts → Agents working on same method
  - Test failures → Usually missing test fixtures
  - TUI won't start → Check LogLevel fix applied

  ---

  ## Summary

  This **Layered Pipeline Checklist** provides:

  1. **Clear stage boundaries** with specific agent assignments
  2. **Review gates** between each stage to catch issues early
  3. **Detailed task lists** for each agent
  4. **Rollback procedures** if things go wrong
  5. **Test commands** at every checkpoint
  6. **Success criteria** that are measurable

  The approach minimizes risk by:
  - Running only 4 agents in parallel (manageable conflicts)
  - Testing after each stage (early issue detection)
  - Building dependencies correctly (Stage 2 needs Stage 1)
  - Keeping complex integrations for later stages

