# QA Story 3: Progressive Discovery (Finding-Based Activation)

## Test Scenario

**Objective:** Verify that PHP-Bypass Plugin activates dynamically when PHP is discovered through findings (not initial scan).

**Target Profile:** `qa-story-3-progressive`

**Starting State:**
- Port 80: `service='http'`, `version=null` (no PHP detected)
- No findings
- Initial tasks: ping-check, port-discovery

**Test Flow:**
1. **Initial Load:** Only HTTP Plugin activates (like Story 1)
2. **Add PHP Finding:** User documents `X-Powered-By: PHP/8.0` header
3. **Dynamic Activation:** PHP-Bypass Plugin detects finding and generates tasks

**Expected Results:**
- ✅ **Phase 1 (Initial):** HTTP Plugin only (confidence 100), no PHP tasks
- ✅ **Phase 2 (After Finding):** PHP-Bypass activates (confidence 90), generates bypass tasks
- ✅ **Event Flow:** finding_added → detect_from_finding() → new tasks

## Quick Start

```bash
./qa_profiles/run_qa_story.sh 3
```

**Manual Testing:**
```bash
crack track --tui qa-story-3-progressive \
  --debug \
  --debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE,DATA:VERBOSE
```

## Test Steps

### Phase 1: Initial State (No PHP)

#### 1.1 Launch TUI with Debug Logging

```bash
crack track --tui qa-story-3-progressive \
  --debug \
  --debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE,DATA:VERBOSE
```

**Explanation:**
- `DATA:VERBOSE` - Captures finding addition events

#### 1.2 Verify Initial Plugin Detection

**In TUI:**
- Press `t` to view task tree
- Expected tasks:
  - ✅ "Verify host is alive"
  - ✅ "Port Discovery"
  - ✅ "Web Testing Methodology (Port 80)" (HTTP Plugin)
  - ❌ **NO PHP-Bypass tasks** (PHP not detected yet)

**Expected Logs:**
```
Plugin 'http' won port 80 (confidence 100)
PHP-Bypass Plugin: confidence 0 (no PHP detected in version)
Generated tasks for 'http' on port 80
```

**Verification:**
```bash
# After closing TUI
grep "php-bypass.*confidence" .debug_logs/tui_debug_*.log | tail -5
# Expected: confidence 0
```

### Phase 2: Add PHP Finding (Progressive Discovery)

#### 2.1 Document PHP Finding

**In TUI:**
- Press `d` (Document finding)
- Or navigate to Findings panel and add manually

**Finding Details:**
- **Type:** `service` or `vulnerability`
- **Description:** `X-Powered-By: PHP/8.0`
- **Source:** `curl` or `whatweb`
- **Port:** `80`

**Example Finding Entry:**
```json
{
  "type": "service",
  "description": "X-Powered-By: PHP/8.0",
  "source": "curl -I http://target:80",
  "port": 80,
  "timestamp": "2025-10-12T10:00:00"
}
```

#### 2.2 Observe Dynamic Activation

**What Happens:**
1. User adds finding → `profile.add_finding()` called
2. EventBus emits `finding_added` event
3. PHP-Bypass Plugin receives event
4. `detect_from_finding()` checks finding for PHP indicators
5. Finding matches → Plugin activates with confidence 90
6. Plugin generates bypass tasks
7. EventBus emits `plugin_tasks_generated`
8. Tasks appear in TUI automatically

**Expected Logs:**
```
[DATA.WRITE] Finding added: X-Powered-By: PHP/8.0
[EVENT] finding_added event emitted
PHP-Bypass Plugin: detect_from_finding() checking...
PHP-Bypass Plugin: Found PHP indicator in finding: PHP/8.0
PHP-Bypass Plugin: confidence 90 (finding-based activation)
Generated tasks for 'php-bypass' on port 80
[EVENT] plugin_tasks_generated event emitted
```

#### 2.3 Verify New Tasks

**In TUI:**
- Press `t` to view task tree
- New tasks should appear:
  - ✅ "PHP Bypass Techniques (Port 80)"
  - ✅ "Test disable_functions bypass"
  - ✅ "Test open_basedir bypass"
  - ✅ "LFI/RFI enumeration"

**Expected:** Both HTTP and PHP-Bypass tasks now present

#### 2.4 Exit and Verify Logs

**Exit TUI (press `q`)**, then analyze:

```bash
# Check finding was added
grep "Finding added" .debug_logs/tui_debug_*.log | tail -5

# Check finding_added event
grep "finding_added" .debug_logs/tui_debug_*.log | tail -5

# Check PHP-Bypass activation
grep "PHP-Bypass.*finding" .debug_logs/tui_debug_*.log | tail -10

# Check new tasks generated
grep "Generated tasks for 'php-bypass'" .debug_logs/tui_debug_*.log | tail -3
```

## Pass Criteria

### Phase 1 Checks (Initial State)

- [x] **HTTP Plugin Activates:** HTTP Plugin detects port 80, confidence 100
- [x] **PHP-Bypass Defers:** PHP-Bypass returns confidence 0 (no PHP detected)
- [x] **HTTP Tasks Only:** gobuster, nikto, whatweb tasks present
- [x] **No PHP Tasks:** PHP-Bypass tasks NOT present initially

### Phase 2 Checks (After Finding)

- [x] **Finding Added:** User successfully adds PHP finding to profile
- [x] **finding_added Event:** EventBus emits event successfully
- [x] **PHP-Bypass Activates:** detect_from_finding() returns confidence 90
- [x] **PHP Tasks Generated:** PHP-Bypass tasks appear in task tree
- [x] **plugin_tasks_generated Event:** EventBus emits event for new tasks
- [x] **Both Plugins Active:** Both HTTP and PHP-Bypass tasks coexist

### Log Validation

```bash
# Run automated verification
./qa_profiles/3_progressive_discovery/verify.sh
```

**Expected Result:** All tests pass

## Troubleshooting

### Issue: PHP-Bypass doesn't activate after adding finding

**Symptom:** No PHP tasks appear even after documenting PHP finding

**Debug:**
```bash
# Check if finding was saved
grep "Finding added" .debug_logs/tui_debug_*.log | tail -5

# Check if event was emitted
grep "finding_added" .debug_logs/tui_debug_*.log | tail -5

# Check if plugin received event
grep "PHP-Bypass.*detect_from_finding" .debug_logs/tui_debug_*.log | tail -5
```

**Common Causes:**
1. **Event handler not registered** - Check `_init_runtime()` called on load
2. **detect_from_finding() doesn't check findings** - Verify method implementation
3. **Finding format incorrect** - Ensure description contains "PHP"

**Fix:**
- Verify `PHPBypassPlugin.detect_from_finding()` checks finding description
- Ensure finding is saved to profile JSON
- Check EventBus listener is registered

### Issue: Finding added but event not emitted

**Symptom:** Finding appears in profile but no tasks generated

**Debug:**
```bash
# Check profile JSON
cat ~/.crack/targets/qa-story-3-progressive.json | grep -A 5 "findings"

# Check event emission
grep "emit.*finding_added" .debug_logs/tui_debug_*.log | tail -5
```

**Fix:** Ensure `profile.add_finding()` calls `EventBus.emit('finding_added', {...})`

### Issue: Tasks generated but don't appear in TUI

**Symptom:** Logs show tasks generated, but TUI doesn't update

**Debug:**
```bash
grep "plugin_tasks_generated" .debug_logs/tui_debug_*.log | tail -5
```

**Fix:** Ensure TUI refreshes task tree after receiving plugin_tasks_generated event

## Expected TUI Behavior

### Phase 1 (Initial Load)
```
Enumeration: qa-story-3-progressive
├── Verify host is alive (pending)
├── Port Discovery (pending)
└── Web Testing Methodology (Port 80) [HTTP Plugin]
    ├── gobuster -u http://qa-story-3-progressive:80
    ├── nikto -h http://qa-story-3-progressive:80
    └── whatweb http://qa-story-3-progressive:80
```

### Phase 2 (After Adding PHP Finding)
```
Enumeration: qa-story-3-progressive
├── Verify host is alive (pending)
├── Port Discovery (pending)
├── Web Testing Methodology (Port 80) [HTTP Plugin]
│   ├── gobuster -u http://qa-story-3-progressive:80
│   ├── nikto -h http://qa-story-3-progressive:80
│   └── whatweb http://qa-story-3-progressive:80
└── PHP Bypass Techniques (Port 80) [PHP-Bypass Plugin - Finding-Based]
    ├── Test disable_functions bypass
    ├── Test open_basedir bypass
    └── LFI/RFI enumeration
```

## Key Learning Points

**Progressive Discovery Workflow:**
1. Initial scan detects service (HTTP) → HTTP Plugin activates
2. HTTP enumeration finds indicators (X-Powered-By header) → User documents as finding
3. Finding triggers re-evaluation → PHP-Bypass Plugin activates
4. New tasks generated automatically → No manual intervention needed

**Real-World Analogy:**
- Nmap scan: "Port 80 is HTTP" (no PHP version)
- Gobuster/Nikto: "Server responds with X-Powered-By: PHP/8.0"
- Analyst documents finding → System adapts enumeration strategy
- PHP-specific bypass tasks appear automatically

**Event-Driven Benefits:**
- Plugins react to new information dynamically
- No need to reload profile manually
- Infinite discovery depth (findings → tasks → findings → tasks)

## Related Documentation

- `qa_profiles/README.md` - QA system overview
- `track/docs/QA_USER_STORIES.md` - Story 3 detailed specification
- `track/core/events.py` - EventBus implementation
- `track/services/php_bypass.py` - detect_from_finding() method
- `IMPLEMENTATION_COMPLETE.md` - Full implementation summary

## Next Steps

After Story 3 passes:
- Test Story 4: Profile Load (event handler registration on disk load)
- Test Story 5: Webshell Finding (highest priority activation)
- Test Story 6: Nmap Import (full integration workflow)
