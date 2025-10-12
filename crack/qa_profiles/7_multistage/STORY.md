# QA Story 7: Multi-Stage Discovery (Cascading Plugin Activation)

## Test Scenario

**Objective:** Verify that plugins activate progressively as new findings reveal additional context.

**Target Profile:** `qa-story-7-multistage`

**Starting State:**
- Port 80: generic HTTP (no PHP)
- No findings

**Multi-Stage Flow:**
1. **Stage 1:** HTTP Plugin only (baseline enumeration)
2. **Stage 2:** Add PHP finding → PHP-Bypass activates
3. **Stage 3:** Add `/admin/login.php` → Auth/SQLi plugins activate
4. **Stage 4:** Add SQLi vulnerability → Exploitation plugins activate

**Expected Results:**
- ✅ Each stage triggers new plugin activation
- ✅ Cascading task generation (findings → tasks → findings → tasks)
- ✅ All plugins coexist without conflicts
- ✅ Complete attack chain visible in task tree

## Quick Start

```bash
./qa_profiles/run_qa_story.sh 7
```

## Test Steps

### Stage 1: Initial HTTP Enumeration

#### 1.1 Launch TUI

```bash
crack track --tui qa-story-7-multistage \
  --debug \
  --debug-categories=STATE:VERBOSE,DATA:VERBOSE
```

#### 1.2 Verify Baseline Tasks

- Press `t`: HTTP tasks only (gobuster, nikto, whatweb)

### Stage 2: PHP Detection

#### 2.1 Add PHP Finding

**In TUI:**
- Press `d` (Document finding)
- **Type:** `service`
- **Description:** `X-Powered-By: PHP/8.1`
- **Source:** `curl -I http://target:80`

#### 2.2 Verify PHP-Bypass Activation

- Press `t`: PHP-Bypass tasks appear
- Expected: disable_functions, open_basedir tasks

### Stage 3: Admin Panel Discovery

#### 3.1 Add Admin Directory Finding

**In TUI:**
- Press `d`
- **Type:** `directory`
- **Description:** `/admin/login.php`
- **Source:** `gobuster`

#### 3.2 Verify Auth/SQLi Plugin Activation

- Press `t`: New tasks appear
- Expected: Login form analysis, default credentials, SQLi testing

### Stage 4: SQLi Vulnerability Confirmed

#### 4.1 Add SQLi Finding

**In TUI:**
- Press `d`
- **Type:** `vulnerability`
- **Description:** `SQLi in /admin/login.php?id=1' OR '1'='1`
- **Source:** `manual testing`

#### 4.2 Verify Exploitation Tasks

- Press `t`: Exploitation tasks appear
- Expected: Database enumeration, privilege escalation

### Stage 5: Review Complete Attack Chain

**In TUI:**
- Press `t`: View full task tree
- All stages should be visible:
  - HTTP enumeration (Stage 1)
  - PHP-Bypass techniques (Stage 2)
  - Auth testing (Stage 3)
  - SQLi exploitation (Stage 4)

## Pass Criteria

### Multi-Stage Activation

- [x] **Stage 1:** HTTP Plugin only
- [x] **Stage 2:** PHP-Bypass activates on PHP finding
- [x] **Stage 3:** Auth/SQLi plugins activate on admin panel finding
- [x] **Stage 4:** Exploitation plugins activate on SQLi finding

### Event Flow

- [x] Each finding triggers `finding_added` event
- [x] Plugins detect relevant findings via `detect_from_finding()`
- [x] New tasks generated for each stage
- [x] Task tree grows progressively

### Integration

- [x] All plugins coexist without conflicts
- [x] No duplicate tasks generated
- [x] Complete attack chain documented

## Troubleshooting

**Issue:** Plugins don't activate after findings added

**Fix:**
- Verify `detect_from_finding()` implemented for each plugin
- Check EventBus listeners registered
- Ensure findings saved to profile JSON

**Issue:** Duplicate tasks generated

**Fix:** Check FindingsProcessor deduplication logic

## Expected Final Task Tree

```
Enumeration: qa-story-7-multistage
├── Verify host is alive
├── Port Discovery
├── Web Testing Methodology (Port 80) [Stage 1: HTTP]
│   ├── gobuster -u http://target:80
│   ├── nikto -h http://target:80
│   └── whatweb http://target:80
├── PHP Bypass Techniques (Port 80) [Stage 2: PHP detected]
│   ├── Test disable_functions bypass
│   └── Test open_basedir bypass
├── Authentication Testing (Port 80) [Stage 3: /admin found]
│   ├── Test default credentials
│   └── Brute force login form
├── SQL Injection Exploitation [Stage 4: SQLi confirmed]
    ├── Enumerate databases
    ├── Extract user credentials
    └── Attempt privilege escalation
```

## Key Learning Points

**Cascading Discovery:**
- Initial scan provides baseline
- Each finding reveals new attack vectors
- Plugins activate progressively
- System adapts enumeration strategy dynamically

**Real-World Workflow:**
1. Nmap → HTTP detected → Web enumeration
2. curl → PHP detected → PHP bypass tests
3. Gobuster → Admin panel → Auth testing
4. Manual testing → SQLi confirmed → Exploitation

**Event-Driven Benefits:**
- No manual task creation
- Automatic adaptation to new information
- Complete attack chain visibility
- Infinite discovery depth

## Related Documentation

- `track/core/events.py` - EventBus architecture
- `track/services/findings_processor.py` - Finding→Task conversion
- `CLAUDE.md` - Findings→Tasks→Findings loop documentation
