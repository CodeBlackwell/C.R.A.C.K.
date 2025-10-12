# QA Story 1: Generic HTTP Service

## Goal
Verify HTTP Plugin wins over PHP-Bypass when no PHP indicators are present.

## Starting State
- **Target:** `qa-story-1-generic-http`
- **Port 80:** `service='http'`, no PHP indicators
- **Findings:** None
- **Expected:** HTTP Plugin wins (confidence 100 > 0)

## Quick Start

```bash
# Load pre-configured profile (bypasses configuration window)
crack track --tui qa-story-1-generic-http \
  --debug \
  --debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE
```

## Expected Results

### 1. Profile Loads Successfully
- No configuration window
- Port 80 already present in profile
- TUI dashboard appears immediately

### 2. Task List Shows HTTP Enumeration Tasks
Press `l` (list tasks) and verify:
- ✅ `gobuster` directory enumeration
- ✅ `nikto` vulnerability scan
- ✅ `whatweb` technology detection
- ❌ **NO** `disable_functions` tasks
- ❌ **NO** `open_basedir` bypass tasks
- ❌ **NO** LD_PRELOAD exploitation tasks

### 3. Plugin Priority in Logs
Check debug logs after loading:

```bash
grep "Plugin.*won port.*80" .debug_logs/tui_debug_*.log | tail -5
```

**Expected:**
```
INFO:crack.track.services.registry:Plugin 'http' won port qa-story-1-generic-http:80 with confidence 100
```

**NOT Expected:**
```
INFO:crack.track.services.registry:Plugin 'php-bypass' won port qa-story-1-generic-http:80
```

### 4. Confidence Scores
Check confidence scores:

```bash
grep "confidence" .debug_logs/tui_debug_*.log | grep -E "(http|php-bypass)" | grep "80" | tail -10
```

**Expected:**
```
DEBUG: HTTP Plugin confidence: 100 (port 80)
DEBUG: PHP-Bypass Plugin confidence: 0 (port 80)
```

## Test Steps

### Step 1: Load Profile
```bash
crack track --tui qa-story-1-generic-http \
  --debug \
  --debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE
```

**Expected:**
- Profile loads instantly (no configuration)
- Port 80 visible in status display
- HTTP tasks visible in task tree

### Step 2: View Task Tree
**In TUI:**
- Press `t` (view task tree)

**Expected Tree:**
```
Enumeration: qa-story-1-generic-http
├─ Verify host is alive
├─ Port Discovery
└─ HTTP Enumeration (Port 80)     ← Should see this
   ├─ gobuster directory scan
   ├─ nikto vulnerability scan
   └─ whatweb technology detection
```

**Should NOT See:**
```
└─ PHP-Bypass Techniques           ← Should NOT exist
   ├─ Enumerate disable_functions
   └─ Test open_basedir bypass
```

### Step 3: List All Tasks
**In TUI:**
- Press `l` (list tasks)
- Press `f` (filter)
- Type `http` → Press Enter

**Expected:**
- Multiple HTTP enumeration tasks visible
- All related to port 80

**In TUI:**
- Press `f` (filter again)
- Type `php` → Press Enter

**Expected:**
- Zero tasks match
- "No tasks match filter" message

### Step 4: Exit and Verify Logs
**In TUI:**
- Press `q` (quit)

**Check logs:**
```bash
cd /home/kali/OSCP/crack
./qa_profiles/1_generic_http/verify.sh
```

## Pass Criteria

✅ **Plugin Priority:**
- HTTP Plugin confidence: 100
- PHP-Bypass Plugin confidence: 0
- HTTP Plugin won port 80

✅ **Task Generation:**
- gobuster, nikto, whatweb tasks present
- NO PHP-Bypass tasks generated

✅ **Event Flow:**
- `service_detected` event emitted for port 80
- HTTP Plugin responded to event
- PHP-Bypass Plugin did NOT generate tasks

✅ **No Errors:**
- No "Error in event handler" messages
- No event handler registration failures

## Troubleshooting

### Issue: PHP-Bypass tasks appear

**Debug:**
```bash
grep "php-bypass.*confidence" .debug_logs/tui_debug_*.log | tail -5
```

**Expected:** Confidence should be 0
**Fix:** Check `track/services/php_bypass.py` detect() method

### Issue: No tasks generated at all

**Debug:**
```bash
grep "service_detected.*80" .debug_logs/tui_debug_*.log | tail -5
grep "plugin_tasks_generated" .debug_logs/tui_debug_*.log | tail -5
```

**Expected:** Both events should be present
**Fix:** Check event handler registration in profile load

### Issue: Profile doesn't load

**Debug:**
```bash
ls -la CRACK_targets/qa-story-1-generic-http.json
```

**Expected:** File should exist (3.2KB)
**Fix:** Run `python qa_profiles/generate_profiles.py`

## Related Stories

- **Story 2:** HTTP with PHP in version (both plugins activate)
- **Story 3:** Progressive discovery (finding-based activation)
- **Story 4:** Profile load from disk (event handler test)
