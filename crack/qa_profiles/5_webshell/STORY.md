# QA Story 5: Webshell Finding (Highest Priority Activation)

## Test Scenario

**Objective:** Verify that PHP-Bypass Plugin activates with highest priority (confidence 100) when webshell is detected.

**Target Profile:** `qa-story-5-webshell`

**Starting State:**
- Port 80: generic HTTP (no PHP)
- No findings

**Test Flow:**
1. Initial load: HTTP Plugin only
2. Add webshell finding: "webshell uploaded: shell.php"
3. PHP-Bypass activates with confidence 100
4. Critical RCE/bypass tasks generated

**Expected Results:**
- ✅ Initial: HTTP confidence 100, PHP-Bypass confidence 0
- ✅ After finding: PHP-Bypass confidence 100 (webshell = highest priority)
- ✅ Tasks: disable_functions bypass, open_basedir bypass, RCE attempts

## Quick Start

```bash
./qa_profiles/run_qa_story.sh 5
```

## Test Steps

### 1. Launch TUI

```bash
crack track --tui qa-story-5-webshell \
  --debug \
  --debug-categories=STATE:VERBOSE,DATA:VERBOSE
```

### 2. Verify Initial State (HTTP Only)

- Press `t`: HTTP tasks only, no PHP tasks

### 3. Add Webshell Finding

**In TUI:**
- Press `d` (Document finding)
- **Type:** `vulnerability`
- **Description:** `webshell uploaded: shell.php`
- **Source:** `file upload exploitation`

### 4. Observe Critical Activation

**Expected Logs:**
```
Finding added: webshell uploaded: shell.php
PHP-Bypass: Detected webshell in finding
PHP-Bypass: confidence 100 (CRITICAL - webshell detected)
Generated tasks for 'php-bypass' with HIGH PRIORITY
```

### 5. Verify High-Priority Tasks

- Press `t`: New PHP-Bypass tasks appear
- Tasks should include:
  - "Execute webshell: shell.php"
  - "Test disable_functions bypass"
  - "Privilege escalation enumeration"

## Pass Criteria

- [x] Webshell finding triggers confidence 100
- [x] PHP-Bypass tasks generated with high priority
- [x] Tasks include RCE and bypass techniques
- [x] Webshell execution tasks present

## Troubleshooting

**Issue:** Webshell doesn't trigger confidence 100

**Fix:** Check `PHPBypassPlugin.detect_from_finding()` checks for "webshell" keyword

**Debug:**
```bash
grep "webshell" .debug_logs/tui_debug_*.log | tail -10
```

## Related Documentation

- `track/services/php_bypass.py` - Webshell detection logic
- `QA_USER_STORIES.md` - Story 5 specification
