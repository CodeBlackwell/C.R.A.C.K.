# QA Story 2: HTTP with PHP in Version String

## Test Scenario

**Objective:** Verify that when PHP is explicitly detected in the version string, BOTH HTTP Plugin and PHP-Bypass Plugin activate appropriately.

**Target Profile:** `qa-story-2-http-with-php`

**Starting State:**
- Port 80: `service='http'`, `version='Apache/2.4.41 (Ubuntu) PHP/7.4.3'`
- No findings
- Initial tasks: ping-check, port-discovery

**Expected Results:**
- ✅ HTTP Plugin: confidence 100 (wins priority)
- ✅ PHP-Bypass Plugin: confidence 95 (also activates)
- ✅ HTTP tasks generated (gobuster, nikto, whatweb)
- ✅ PHP-Bypass tasks generated (bypass techniques, disable_functions)

## Quick Start

```bash
./qa_profiles/run_qa_story.sh 2
```

**Manual Testing:**
```bash
crack track --tui qa-story-2-http-with-php \
  --debug \
  --debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE
```

## Test Steps

### 1. Launch TUI with Debug Logging

```bash
crack track --tui qa-story-2-http-with-php \
  --debug \
  --debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE
```

**Explanation:**
- `--tui` - Launches interactive TUI mode
- `qa-story-2-http-with-php` - Target name (loads pre-configured profile)
- `--debug` - Enables debug logging to `.debug_logs/tui_debug_*.log`
- `--debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE` - Captures state transitions and task execution

### 2. Verify Initial State

**In TUI Dashboard:**
- Press `t` to view task tree
- Check for initial tasks:
  - ✅ "Verify host is alive" (ping-check)
  - ✅ "Port Discovery" (port-discovery)

**Expected:** No HTTP or PHP tasks yet (waiting for service_detected event)

### 3. Observe Plugin Detection (Automatic)

**What Happens:**
1. Profile loads → Emits `service_detected` event for port 80
2. ServiceRegistry receives event
3. Both HTTP and PHP-Bypass plugins called with `detect()`
4. **HTTP Plugin:** Checks service='http', version contains 'PHP/7.4.3' → Returns confidence 100
5. **PHP-Bypass Plugin:** Checks version contains 'PHP/7.4.3' → Returns confidence 95
6. ServiceRegistry selects HTTP Plugin as winner (100 > 95)
7. **BOTH plugins generate tasks** (this is the key test)

**Expected Logs:**
```
Plugin 'http' won port 80 (confidence 100)
PHP-Bypass Plugin detected PHP in version: PHP/7.4.3 (confidence 95)
Generated tasks for 'http' on port 80
Generated tasks for 'php-bypass' on port 80
```

### 4. Verify Task Generation

**In TUI:**
- Press `t` to view task tree
- Look for HTTP tasks:
  - ✅ "Web Testing Methodology (Port 80)" (parent task)
  - ✅ gobuster tasks
  - ✅ nikto scan
  - ✅ whatweb enumeration

- Look for PHP-Bypass tasks:
  - ✅ "PHP Bypass Techniques (Port 80)" (parent task)
  - ✅ disable_functions bypass
  - ✅ open_basedir bypass
  - ✅ LFI/RFI testing

**Expected:** Both sets of tasks should be present

### 5. Check Plugin Confidence Scores

**Exit TUI (press `q`)**, then analyze logs:

```bash
# Find HTTP Plugin confidence
grep "http.*confidence" .debug_logs/tui_debug_*.log | grep "port.*80" | tail -5

# Find PHP-Bypass Plugin confidence
grep "php-bypass.*confidence" .debug_logs/tui_debug_*.log | grep "port.*80" | tail -5
```

**Expected Output:**
```
HTTP Plugin: confidence 100
PHP-Bypass Plugin: confidence 95
```

### 6. Verify Event Flow

```bash
# Check service_detected event
grep "service_detected.*port.*80" .debug_logs/tui_debug_*.log | tail -3

# Check plugin_tasks_generated events
grep "plugin_tasks_generated" .debug_logs/tui_debug_*.log | tail -10
```

**Expected:**
- 1x `service_detected` event for port 80
- 2x `plugin_tasks_generated` events (HTTP + PHP-Bypass)

### 7. Verify No Errors

```bash
grep "Error in event handler" .debug_logs/tui_debug_*.log | tail -10
```

**Expected:** No errors related to HTTP or PHP-Bypass plugins

## Pass Criteria

### Primary Checks

- [x] **HTTP Plugin Wins:** HTTP Plugin has confidence 100 and wins priority
- [x] **PHP-Bypass Activates:** PHP-Bypass Plugin has confidence 95 (not 0)
- [x] **HTTP Tasks Generated:** gobuster, nikto, whatweb tasks present
- [x] **PHP-Bypass Tasks Generated:** bypass technique tasks present
- [x] **Both Plugins Active:** Both plugins contributed tasks to the profile

### Log Validation

```bash
# Run automated verification
./qa_profiles/2_http_with_php/verify.sh
```

**Expected Result:** All tests pass

## Troubleshooting

### Issue: PHP-Bypass has confidence 0 instead of 95

**Symptom:** Only HTTP tasks generated, no PHP-Bypass tasks

**Debug:**
```bash
grep "php-bypass.*detect" .debug_logs/tui_debug_*.log | tail -5
```

**Expected:** Should see "Detected PHP in version: PHP/7.4.3"

**Fix:** Check `track/services/php_bypass.py` detect() method - should check version field for PHP

### Issue: HTTP Plugin confidence is not 100

**Symptom:** HTTP Plugin has lower confidence than expected

**Debug:**
```bash
grep "http.*detect" .debug_logs/tui_debug_*.log | tail -5
```

**Expected:** Should see "HTTP service detected on port 80"

**Fix:** Check `track/services/http.py` detect() method

### Issue: Only one plugin generated tasks

**Symptom:** Either HTTP or PHP-Bypass tasks missing

**Debug:**
```bash
grep "Generated tasks for" .debug_logs/tui_debug_*.log | tail -10
```

**Expected:** Should see both:
- "Generated tasks for 'http' on port 80"
- "Generated tasks for 'php-bypass' on port 80"

**Root Cause:** ServiceRegistry should call generate_tasks() for ALL plugins with confidence > 0, not just the winner

## Expected TUI Behavior

**Task Tree View:**
```
Enumeration: qa-story-2-http-with-php
├── Verify host is alive (pending)
├── Port Discovery (pending)
├── Web Testing Methodology (Port 80) [HTTP Plugin]
│   ├── gobuster -u http://qa-story-2-http-with-php:80
│   ├── nikto -h http://qa-story-2-http-with-php:80
│   └── whatweb http://qa-story-2-http-with-php:80
└── PHP Bypass Techniques (Port 80) [PHP-Bypass Plugin]
    ├── Test disable_functions bypass
    ├── Test open_basedir bypass
    └── LFI/RFI enumeration
```

## Key Learning Points

**Plugin Priority vs Activation:**
- **Priority:** HTTP Plugin wins (confidence 100 > 95) - controls which plugin's methodology is PRIMARY
- **Activation:** Both plugins activate (both confidence > 0) - both generate supplementary tasks

**Real-World Analogy:**
- HTTP Plugin: "This is an HTTP server, enumerate directories/files/CMS"
- PHP-Bypass Plugin: "PHP is running, test for disable_functions/open_basedir bypasses"

**Both are correct** - HTTP enumeration finds attack surface, PHP bypasses test for misconfigurations

## Related Documentation

- `qa_profiles/README.md` - QA system overview
- `track/docs/QA_USER_STORIES.md` - All 7 user stories
- `track/docs/PLUGIN_PRIORITY_FIX_SUMMARY.md` - Technical details
- `IMPLEMENTATION_COMPLETE.md` - Full implementation summary

## Next Steps

After Story 2 passes:
- Test Story 3: Progressive Discovery (finding-based activation)
- Test Story 4: Profile Load (event handler registration)
- Test Story 5: Webshell Finding (highest priority)
