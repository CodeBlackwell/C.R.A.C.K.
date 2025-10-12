# QA Profile Packages - Plugin Priority Testing

Pre-configured profile packages for testing plugin priority and event handler fixes. Each story bypasses the initial configuration window and loads instantly.

## Quick Start

```bash
# Generate all profiles (only needed once)
python qa_profiles/generate_profiles.py

# Run a specific story
./qa_profiles/run_qa_story.sh 1

# Run all stories sequentially
./qa_profiles/verify_all_stories.sh
```

## Available Stories

| # | Story | Target | Tests |
|---|-------|--------|-------|
| 1 | Generic HTTP | `qa-story-1-generic-http` | HTTP Plugin wins, PHP-Bypass returns 0 |
| 2 | HTTP with PHP | `qa-story-2-http-with-php` | Both plugins activate appropriately |
| 3 | Progressive Discovery | `qa-story-3-progressive` | Finding-based activation |
| 4 | Profile Load | `qa-story-4-profile-load` | Event handler registration on load |
| 5 | Webshell Finding | `qa-story-5-webshell` | Highest priority activation |
| 6 | Nmap Import | `qa-story-6-nmap-import` | Full integration test |
| 7 | Multi-Stage | `qa-story-7-multistage` | Cascading plugin activation |

## System Architecture

### Profile Storage: CRACK_targets/

Profiles are stored in `./CRACK_targets/` (project-local) instead of `~/.crack/targets/`:

```
CRACK_targets/
├── qa-story-1-generic-http.json    # Story 1 profile
├── qa-story-2-http-with-php.json   # Story 2 profile
├── qa-story-3-progressive.json     # Story 3 profile
├── qa-story-4-profile-load.json    # Story 4 profile
├── qa-story-5-webshell.json        # Story 5 profile
├── qa-story-6-nmap-import.json     # Story 6 profile
└── qa-story-7-multistage.json      # Story 7 profile
```

**Benefits:**
- ✅ Version controlled with code
- ✅ No manual profile creation
- ✅ Instant loading (no configuration window)
- ✅ Repeatable tests
- ✅ Separate from real work profiles

### Directory Structure

```
qa_profiles/
├── README.md                          # This file
├── generate_profiles.py               # Profile generator
├── run_qa_story.sh                    # Master script
├── verify_all_stories.sh              # Run all stories
│
├── 1_generic_http/
│   ├── STORY.md                       # Test instructions
│   └── verify.sh                      # Automated verification
│
├── 2_http_with_php/
│   ├── STORY.md
│   └── verify.sh
│
├── ... (3-7 similar structure)
```

## Workflow

### 1. Generate Profiles

```bash
python qa_profiles/generate_profiles.py
```

**Output:**
```
✅ Generated: qa-story-1-generic-http
   Path: /home/kali/OSCP/crack/CRACK_targets/qa-story-1-generic-http.json
   Ports: 1
   Findings: 0
... (7 total)
```

### 2. Run a Story

```bash
./qa_profiles/run_qa_story.sh 1
```

**What happens:**
1. Displays story instructions
2. Confirms profile exists in CRACK_targets/
3. Launches TUI with debug logging
4. After exit, runs automated verification
5. Shows PASS/FAIL results

### 3. Manual Testing (Alternative)

```bash
# Load profile directly
crack track --tui qa-story-1-generic-http \
  --debug \
  --debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE

# After testing, verify manually
./qa_profiles/1_generic_http/verify.sh
```

### 4. Run All Stories

```bash
./qa_profiles/verify_all_stories.sh
```

Runs stories 1-7 sequentially with automated verification.

## Story Details

### Story 1: Generic HTTP
**Tests:** HTTP Plugin priority over PHP-Bypass

**Starting State:**
- Port 80: `service='http'`, no PHP

**Expected:**
- HTTP Plugin: confidence 100 ✅
- PHP-Bypass: confidence 0 ✅
- Tasks: gobuster, nikto, whatweb
- NO PHP-Bypass tasks

**Verification:**
```bash
./qa_profiles/1_generic_http/verify.sh
```

**Debug Commands:**
```bash
# Check plugin winner
grep "Plugin.*won port.*80" .debug_logs/tui_debug_*.log | tail -5

# Check confidence scores
grep "confidence" .debug_logs/tui_debug_*.log | grep -E "(http|php-bypass)" | tail -10
```

### Story 2: HTTP with PHP
**Tests:** Both plugins activate when PHP detected

**Starting State:**
- Port 80: `service='http'`, version includes `PHP/7.4.3`

**Expected:**
- HTTP Plugin: confidence 100 (wins) ✅
- PHP-Bypass: confidence 95 (also activates) ✅
- Tasks: Both HTTP + PHP tasks

### Story 3: Progressive Discovery
**Tests:** Finding-based activation

**Starting State:**
- Port 80: generic HTTP (no PHP)

**Test Steps:**
1. Load profile → Only HTTP tasks
2. Add PHP finding: `X-Powered-By: PHP/8.0`
3. PHP-Bypass tasks appear automatically

**Verification:**
```bash
grep "finding_added" .debug_logs/tui_debug_*.log | tail -5
grep "PHP-Bypass.*activated via finding" .debug_logs/tui_debug_*.log | tail -3
```

### Story 4: Profile Load
**Tests:** Event handler registration on load

**Starting State:**
- Ports 80, 443 (pre-configured)
- Directory finding present
- Tests from_dict() → _init_runtime() fix

**Test Steps:**
1. Load existing profile
2. Add new port 8080
3. Verify tasks generated for 8080

**Verification:**
```bash
grep "_init_runtime" .debug_logs/tui_debug_*.log | head -3
grep "service_detected.*8080" .debug_logs/tui_debug_*.log | tail -3
```

### Story 5: Webshell
**Tests:** Highest priority activation

**Starting State:**
- Port 80: generic HTTP

**Test Steps:**
1. Load profile
2. Add webshell finding: `webshell uploaded: shell.php`
3. PHP-Bypass activates with confidence 100

**Expected:**
- High-priority RCE tasks
- disable_functions bypass
- open_basedir bypass

### Story 6: Nmap Import
**Tests:** Full Nmap XML import workflow

**Starting State:**
- Fresh profile (no ports)
- Includes test-scan.xml

**Test Steps:**
1. Load profile
2. Import test-scan.xml (ports 22, 80, 443)
3. Verify SSH + HTTP tasks, NO PHP tasks

### Story 7: Multi-Stage
**Tests:** Cascading plugin activation

**Starting State:**
- Port 80: generic HTTP

**Test Steps:**
1. Load → HTTP tasks
2. Add PHP finding → PHP tasks
3. Add `/admin/login.php` → Auth/SQLi tasks
4. Add SQLi vuln → Exploitation tasks

**Verification:**
```bash
grep "activated via finding" .debug_logs/tui_debug_*.log | tail -10
```

## Verification Scripts

Each story has a `verify.sh` script that checks debug logs for expected patterns:

### Example: Story 1 Verification

```bash
./qa_profiles/1_generic_http/verify.sh
```

**Checks:**
1. ✅ HTTP Plugin won port 80 (confidence 100)
2. ✅ PHP-Bypass confidence 0
3. ✅ service_detected event emitted
4. ✅ plugin_tasks_generated event emitted
5. ✅ NO PHP-Bypass tasks generated
6. ✅ No event handler errors
7. ✅ HTTP tasks generated

**Output:**
```
[TEST 1] HTTP Plugin won port 80
  ✓ PASS: HTTP Plugin won with confidence 100

[TEST 2] PHP-Bypass Plugin confidence is 0
  ✓ PASS: PHP-Bypass confidence is 0 (or not activated)

... (7 tests total)

Summary:
Tests Passed: 7
Tests Failed: 0

✓ ALL TESTS PASSED
```

## Debug Log Analysis

### Finding Latest Log

```bash
ls -t .debug_logs/tui_debug_*.log | head -1
```

### Common Patterns

**Plugin Priority:**
```bash
grep "Plugin.*won port" .debug_logs/tui_debug_*.log | tail -10
```

**Confidence Scores:**
```bash
grep "confidence" .debug_logs/tui_debug_*.log | grep -E "(http|php-bypass)" | tail -20
```

**Event Flow:**
```bash
grep "service_detected\|plugin_tasks_generated\|finding_added" .debug_logs/tui_debug_*.log | tail -30
```

**Errors:**
```bash
grep "ERROR\|Error in event handler" .debug_logs/tui_debug_*.log | tail -10
```

## Troubleshooting

### Issue: Profile not found

**Symptom:** `Error: Profile not found: CRACK_targets/qa-story-1-generic-http.json`

**Fix:**
```bash
python qa_profiles/generate_profiles.py
```

### Issue: No debug logs

**Symptom:** `.debug_logs/` directory empty

**Fix:** Ensure `--debug` flag is used:
```bash
crack track --tui qa-story-1-generic-http --debug --debug-categories=STATE:VERBOSE
```

### Issue: PHP-Bypass tasks appear for generic HTTP

**Symptom:** Story 1 fails, PHP-Bypass tasks visible

**Debug:**
```bash
grep "php-bypass.*confidence" .debug_logs/tui_debug_*.log | tail -5
```

**Expected:** Confidence should be 0
**Root Cause:** `track/services/php_bypass.py` detect() method not returning 0

### Issue: Event handler errors

**Symptom:** `Error in event handler` in logs

**Debug:**
```bash
grep -C 5 "Error in event handler" .debug_logs/tui_debug_*.log | tail -30
```

**Common Causes:**
- Plugin signature mismatch (missing `profile` parameter)
- Event handler not registered (_init_runtime not called)

## Migration from Legacy ~/.crack/targets/

If you have existing profiles in `~/.crack/targets/`, migrate them:

```bash
# Migrate all profiles
crack track --migrate

# Migrate specific target
crack track --migrate --migrate-target 192.168.45.100
```

**Result:**
```
Profile Migration: ~/.crack/targets/ → ./CRACK_targets/
Found 10 profile(s) to migrate

Migrate all 10 profiles? (yes/no): yes

Migration Results:
  ✓ Migrated: 10
  • Skipped (already exists): 0
  ✗ Errors: 0

Profiles are now stored in ./CRACK_targets/
Original files remain in ~/.crack/targets/ (backup)
```

## Environment Variable Override

Use custom location:

```bash
export CRACK_TARGETS_DIR=/tmp/qa_test
crack track --tui qa-story-1-generic-http
```

Profiles will be loaded from and saved to `/tmp/qa_test/`.

## Git Integration

QA profiles are version controlled:

```bash
# .gitignore configuration
CRACK_targets/*.json        # Ignore real work
!CRACK_targets/qa-*.json    # Include QA profiles
```

**Commit QA profiles:**
```bash
git add CRACK_targets/qa-*.json
git commit -m "Add QA profile packages for plugin priority testing"
```

**Real work profiles stay local:**
- `CRACK_targets/192.168.45.100.json` → Ignored
- `CRACK_targets/qa-story-1-generic-http.json` → Committed

## Integration with Existing Docs

- **QA_USER_STORIES.md** - Detailed test scenarios
- **QA_COMMAND_CHECKLIST.md** - Quick reference commands
- **PLUGIN_PRIORITY_FIX_SUMMARY.md** - Technical overview

## Success Criteria

After running all stories, verify:

- ✅ Story 1: HTTP Plugin wins generic HTTP (100 > 0)
- ✅ Story 2: Both plugins activate appropriately
- ✅ Story 3: Finding-based activation works
- ✅ Story 4: Event handlers registered on load
- ✅ Story 5: Webshell gets highest priority
- ✅ Story 6: Nmap import generates correct tasks
- ✅ Story 7: Cascading plugins work

All 7 stories should pass automated verification.

## Next Steps

1. **Run Story 1:**
   ```bash
   ./qa_profiles/run_qa_story.sh 1
   ```

2. **Review results:**
   - Check PASS/FAIL status
   - Review debug logs if needed
   - Iterate on fixes

3. **Run all stories:**
   ```bash
   ./qa_profiles/verify_all_stories.sh
   ```

4. **Update documentation:**
   - Document any new patterns
   - Update expected results if behavior changes
   - Add new stories as needed
