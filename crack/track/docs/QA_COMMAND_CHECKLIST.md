# QA Command Checklist - Quick Reference

## Quick Setup

```bash
# Create test Nmap scan file (used in Story 6)
cat > /tmp/test-scan.xml << 'EOF'
<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.45.100"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.41"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="Apache httpd" version="2.4.41"/>
      </port>
    </ports>
  </host>
</nmaprun>
EOF
```

---

## Story 1: Generic HTTP (PHP-Bypass Should NOT Activate)

```bash
# Start
rm ~/.crack/targets/qa-test-1.example.com.json
crack track --tui qa-test-1.example.com --debug --debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE

# In TUI:
# 4 → 2 → Port: 80 → Service: http → Confirm
# t (view tree)
# l (list tasks - should see gobuster/nikto, NO php-bypass)

# Verify
grep "Plugin.*won port.*80" .debug_logs/tui_debug_*.log | tail -5
grep "PHP-Bypass.*confidence.*0" .debug_logs/tui_debug_*.log | tail -3
grep "HTTP.*confidence.*100" .debug_logs/tui_debug_*.log | tail -3

# Expected: HTTP Plugin wins (100), PHP-Bypass returns 0
```

**Pass Criteria:**
- ✅ HTTP Plugin confidence: 100
- ✅ PHP-Bypass confidence: 0
- ✅ See: gobuster, nikto, whatweb tasks
- ✅ No: disable_functions, open_basedir tasks

---

## Story 2: HTTP with PHP in Version (Both Should Activate)

```bash
# Start
rm ~/.crack/targets/qa-test-2.example.com.json
crack track --tui qa-test-2.example.com --debug --debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE

# In TUI:
# 4 → 2 → Port: 80 → Service: http → Product: Apache httpd → Version: Apache/2.4.41 PHP/7.4.3 → Confirm
# l (list tasks)
# f → type "http" (filter)
# f → type "php" (filter)

# Verify
grep "HTTP.*confidence" .debug_logs/tui_debug_*.log | grep "80" | tail -3
grep "PHP-Bypass.*confidence" .debug_logs/tui_debug_*.log | grep "80" | tail -3

# Expected: HTTP wins (100), but PHP-Bypass also activates (95)
```

**Pass Criteria:**
- ✅ HTTP Plugin confidence: 100 (wins)
- ✅ PHP-Bypass confidence: 95 (also activates)
- ✅ See both: HTTP tasks AND PHP-Bypass tasks
- ✅ HTTP tasks listed first

---

## Story 3: Progressive Discovery (Finding-Based Activation)

```bash
# Start
rm ~/.crack/targets/qa-test-3.example.com.json
crack track --tui qa-test-3.example.com --debug --debug-categories=STATE:VERBOSE,DATA:VERBOSE

# In TUI:
# 4 → 2 → Port: 80 → Service: http → Confirm
# l (verify ONLY HTTP tasks, NO PHP tasks)
# d → Type: technology → Description: X-Powered-By: PHP/8.0 → Source: whatweb → Confirm
# l (verify PHP tasks NOW appear)

# Verify
grep "finding_added" .debug_logs/tui_debug_*.log | tail -5
grep "PHP-Bypass.*activated via finding" .debug_logs/tui_debug_*.log | tail -3
grep "plugin_tasks_generated" .debug_logs/tui_debug_*.log | tail -5

# Expected: PHP-Bypass activates AFTER finding documented
```

**Pass Criteria:**
- ✅ Step 1: Only HTTP tasks (no PHP)
- ✅ Step 2: Document PHP finding
- ✅ Step 3: PHP tasks appear automatically
- ✅ Log shows: "activated via finding (confidence: 90)"

---

## Story 4: Profile Load from Disk (Event Handler Fix)

```bash
# Start with EXISTING profile (google-gruyere or create one first)
crack track --tui google-gruyere.appspot.com --debug --debug-categories=STATE.TRANSITION:VERBOSE,STATE.PERSISTENCE:VERBOSE

# In TUI:
# (Profile loads from disk)
# 4 → 2 → Port: 8080 → Service: http → Confirm
# l (verify NEW tasks for port 8080)

# Verify
grep "_init_runtime" .debug_logs/tui_debug_*.log | head -3
grep "Event handlers registered" .debug_logs/tui_debug_*.log | head -1
grep "service_detected.*8080" .debug_logs/tui_debug_*.log | tail -3
grep "plugin_tasks_generated" .debug_logs/tui_debug_*.log | tail -5

# Expected: Event handlers registered on load, new port triggers tasks
```

**Pass Criteria:**
- ✅ Profile loads without errors
- ✅ Log shows: "_init_runtime called"
- ✅ Log shows: "Event handlers registered"
- ✅ Adding port 8080 generates tasks
- ✅ No "Error in event handler" logs

---

## Story 5: Webshell Finding (Highest Priority)

```bash
# Start
rm ~/.crack/targets/qa-test-5.example.com.json
crack track --tui qa-test-5.example.com --debug --debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE

# In TUI:
# 4 → 2 → Port: 80 → Service: http → Confirm
# d → Type: file → Description: webshell uploaded: shell.php → Source: manual → Confirm
# l (verify HIGH-PRIORITY PHP-Bypass tasks)

# Verify
grep "webshell" .debug_logs/tui_debug_*.log | tail -5
grep "PHP-Bypass.*confidence.*100" .debug_logs/tui_debug_*.log | tail -3

# Expected: PHP-Bypass activates with confidence 100 (highest)
```

**Pass Criteria:**
- ✅ Webshell finding triggers PHP-Bypass
- ✅ Confidence: 100 (highest priority)
- ✅ See: disable_functions bypass, open_basedir bypass, LD_PRELOAD
- ✅ Tasks marked [HIGH PRIORITY] or [QUICK WIN]

---

## Story 6: Nmap Import (Full Integration)

```bash
# Start
rm ~/.crack/targets/192.168.45.100.json
crack track --tui 192.168.45.100 --debug --debug-categories=STATE:VERBOSE,DATA.PARSE:VERBOSE

# In TUI:
# 4 → 1 → /tmp/test-scan.xml → Confirm
# l (list all tasks)
# f → type "ssh" (should see SSH tasks)
# f → type "http" (should see HTTP tasks for 80 and 443)
# f → type "php" (should see ZERO PHP tasks)

# Verify
grep "Parsing Nmap XML" .debug_logs/tui_debug_*.log | tail -1
grep "Found.*ports" .debug_logs/tui_debug_*.log | tail -1
grep "service_detected" .debug_logs/tui_debug_*.log | tail -10
grep "Plugin.*won port" .debug_logs/tui_debug_*.log | tail -5
grep "PHP-Bypass" .debug_logs/tui_debug_*.log | tail -5

# Expected: SSH + HTTP tasks generated, NO PHP tasks
```

**Pass Criteria:**
- ✅ Nmap XML parsed (3 ports found)
- ✅ SSH Plugin won port 22
- ✅ HTTP Plugin won ports 80 and 443
- ✅ SSH tasks generated (ssh-audit, searchsploit)
- ✅ HTTP tasks generated (gobuster, nikto)
- ✅ ZERO PHP-Bypass tasks (no PHP detected)

---

## Story 7: Multi-Stage Discovery (Cascading Plugins)

```bash
# Start
rm ~/.crack/targets/qa-test-7.example.com.json
crack track --tui qa-test-7.example.com --debug --debug-categories=STATE:VERBOSE,DATA:VERBOSE

# In TUI:
# 4 → 2 → Port: 80 → Service: http → Confirm
# l (only HTTP tasks)
# d → Type: technology → Description: PHP/7.4.3 → Source: whatweb → Confirm
# l (now see PHP tasks)
# d → Type: directory → Description: /admin/login.php → Source: gobuster → Confirm
# l (now see auth-bypass and SQLi tasks)
# d → Type: vulnerability → Description: SQL injection in login → Source: manual → Confirm
# l (now see SQLi exploitation tasks)
# t (view complete task tree)

# Verify
grep "activated via finding" .debug_logs/tui_debug_*.log | tail -10
grep "plugin_tasks_generated" .debug_logs/tui_debug_*.log | tail -15

# Expected: Each finding triggers appropriate plugin cascade
```

**Pass Criteria:**
- ✅ Stage 1: HTTP tasks only
- ✅ Stage 2: + PHP tasks (after PHP finding)
- ✅ Stage 3: + Auth/SQLi tasks (after login.php finding)
- ✅ Stage 4: + SQLi exploitation tasks (after vuln finding)
- ✅ No duplicate tasks
- ✅ Task tree reflects progression

---

## Quick Log Analysis

### Check Plugin Priority Decisions
```bash
grep "Plugin.*won port" .debug_logs/tui_debug_*.log | tail -20
```

### Check Event Flow
```bash
grep "Event emitted:" .debug_logs/tui_debug_*.log | tail -30
```

### Check Finding-Based Activation
```bash
grep "activated via finding" .debug_logs/tui_debug_*.log | tail -15
```

### Check Confidence Scores
```bash
grep "confidence" .debug_logs/tui_debug_*.log | grep -E "(http|php-bypass)" | tail -20
```

### Check for Errors
```bash
grep "ERROR" .debug_logs/tui_debug_*.log | tail -20
```

### Check Event Handler Registration
```bash
grep "_init_runtime\|Event handlers registered" .debug_logs/tui_debug_*.log | head -5
```

### Check Complete Event Flow for Port 80
```bash
grep "port.*80" .debug_logs/tui_debug_*.log | \
  grep -E "(service_detected|plugin_tasks_generated|won port|confidence)" | \
  tail -30
```

---

## Performance Checks

### Find Slow Operations (>1 second)
```bash
grep "elapsed=" .debug_logs/tui_debug_*.log | awk -F'=' '$2 > 1.0'
```

### Task Generation Timing
```bash
grep "Generated tasks" .debug_logs/tui_debug_*.log | grep "elapsed"
```

### Profile Load Time
```bash
grep "Loading profile\|Profile loaded" .debug_logs/tui_debug_*.log | head -4
```

---

## Troubleshooting Commands

### No tasks generated after port import
```bash
echo "=== Check service_detected event ==="
grep "service_detected" .debug_logs/tui_debug_*.log | tail -5

echo "=== Check plugin detection ==="
grep "Plugin.*confidence.*[1-9]" .debug_logs/tui_debug_*.log | tail -10

echo "=== Check event handler errors ==="
grep "Error in event handler" .debug_logs/tui_debug_*.log | tail -10

echo "=== Check runtime init ==="
grep "_init_runtime" .debug_logs/tui_debug_*.log | head -3
```

### PHP-Bypass activating too early
```bash
echo "=== Check PHP-Bypass confidence ==="
grep "php-bypass.*confidence" .debug_logs/tui_debug_*.log | tail -5

echo "=== Check port info ==="
grep "port.*80.*service.*http" .debug_logs/tui_debug_*.log | tail -3

echo "=== Check HTTP plugin won ==="
grep "http.*won port.*80" .debug_logs/tui_debug_*.log | tail -3
```

### Finding not triggering tasks
```bash
echo "=== Check finding saved ==="
grep "Finding added" .debug_logs/tui_debug_*.log | tail -5

echo "=== Check finding_added event ==="
grep "finding_added" .debug_logs/tui_debug_*.log | tail -5

echo "=== Check plugin response ==="
grep "activated via finding" .debug_logs/tui_debug_*.log | tail -5
```

---

## Expected Results Summary

| Test | HTTP Confidence | PHP-Bypass Confidence | Winner | Tasks Generated |
|------|----------------|----------------------|--------|-----------------|
| **Story 1: Generic HTTP** | 100 | 0 | HTTP | gobuster, nikto, whatweb |
| **Story 2: PHP in Version** | 100 | 95 | HTTP (both activate) | HTTP + PHP tasks |
| **Story 3: Finding-Based** | 100 | 0 → 90 | HTTP → PHP | HTTP first, then PHP |
| **Story 5: Webshell** | 100 | 100 | Both (high priority) | HTTP + PHP (priority) |
| **Story 6: Nmap Import** | 100 (80/443) | 0 | HTTP | SSH + HTTP, NO PHP |

---

## Pass/Fail Checklist

**Critical Fixes:**
- [ ] Story 1: HTTP wins generic HTTP (100 > 0) ✅
- [ ] Story 1: PHP-Bypass returns 0 for generic HTTP ✅
- [ ] Story 3: Finding-based activation works ✅
- [ ] Story 4: Event handlers registered on profile load ✅
- [ ] Story 4: Loaded profile can add new ports ✅

**Plugin Priority:**
- [ ] HTTP Plugin confidence 100 for port 80/443 ✅
- [ ] PHP-Bypass confidence 0 for generic HTTP ✅
- [ ] PHP-Bypass confidence 95 when PHP in version ✅
- [ ] PHP-Bypass confidence 90 via finding ✅
- [ ] PHP-Bypass confidence 100 for webshell ✅

**Task Generation:**
- [ ] HTTP tasks for port 80 (gobuster, nikto) ✅
- [ ] PHP tasks only when PHP confirmed ✅
- [ ] SSH tasks for port 22 ✅
- [ ] No duplicate tasks ✅
- [ ] Tasks reflect current attack surface ✅

**Event System:**
- [ ] service_detected events emitted ✅
- [ ] plugin_tasks_generated events received ✅
- [ ] finding_added events emitted ✅
- [ ] Event handlers registered on load ✅
- [ ] No event handler errors ✅

**Performance:**
- [ ] Profile load < 1 second ✅
- [ ] Task generation < 500ms ✅
- [ ] Smooth TUI responsiveness ✅
- [ ] No ERROR logs during normal operation ✅

---

## Final Validation

After completing all stories, run:

```bash
# Full test suite
python -m pytest tests/track/test_php_bypass_plugin.py -xvs

# Check for any regression
python /tmp/test_plugin_priority_fix.py
python /tmp/demonstrate_fix.py

# Verify google-gruyere profile works
crack track --tui google-gruyere.appspot.com --debug
# Add a new port and verify tasks generate
```

**All tests should pass with:**
- ✅ 29/29 PHP-Bypass plugin tests pass
- ✅ HTTP Plugin wins generic HTTP
- ✅ Progressive discovery works
- ✅ Event handlers registered correctly
- ✅ No event system errors
