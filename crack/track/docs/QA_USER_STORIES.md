# QA User Stories - Plugin Priority & Event Handler Fixes

## Story 1: Fresh Profile with Generic HTTP Service

**Goal:** Verify HTTP Plugin wins over PHP-Bypass when no PHP indicators present

**Starting Command:**
```bash
# Clean slate - remove any existing profile
rm ~/.crack/targets/qa-test-1.example.com.json

# Start TUI with comprehensive debug logging
crack track --tui qa-test-1.example.com \
  --debug \
  --debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE,UI:NORMAL \
  --debug-timing
```

**Test Steps:**

### Step 1: Create profile and add HTTP port
```
Action: From dashboard, press '4' (Import Scan Results)
Action: Press '2' (Manual port entry)
Input:  Port: 80
Input:  Service: http
Input:  Product: (leave empty)
Input:  Version: (leave empty)
Action: Press 'c' to confirm
```

**Expected Results:**
- Profile created successfully
- Port 80 added with service='http'
- Debug log shows: `service_detected event emitted for port 80`
- Debug log shows: `HTTP Plugin wins with confidence 100`
- Debug log shows: `PHP-Bypass Plugin confidence: 0`

### Step 2: View task tree
```
Action: Press 't' (Task Tree)
```

**Expected Results:**
- See HTTP enumeration tasks:
  - `gobuster dir -u http://qa-test-1.example.com:80`
  - `nikto -h http://qa-test-1.example.com:80`
  - `whatweb http://qa-test-1.example.com:80`
- NO PHP-Bypass tasks (no disable_functions, no open_basedir, no LD_PRELOAD)

### Step 3: Check debug logs
```bash
grep "Plugin.*won port.*80" .debug_logs/tui_debug_*.log | tail -5
grep "PHP-Bypass" .debug_logs/tui_debug_*.log | tail -10
```

**Expected Log Patterns:**
```
INFO:crack.track.services.registry:Plugin 'http' won port qa-test-1.example.com:80 with confidence 100
# Should NOT see: Plugin 'php-bypass' won port
```

**Success Criteria:**
- ✅ HTTP Plugin wins (confidence 100)
- ✅ PHP-Bypass returns confidence 0
- ✅ HTTP enumeration tasks generated
- ✅ NO PHP-Bypass tasks generated
- ✅ No errors in debug logs

---

## Story 2: Profile with PHP Explicitly Detected

**Goal:** Verify PHP-Bypass activates when PHP is in version string

**Starting Command:**
```bash
rm ~/.crack/targets/qa-test-2.example.com.json

crack track --tui qa-test-2.example.com \
  --debug \
  --debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE \
  --debug-timing
```

**Test Steps:**

### Step 1: Add HTTP port with PHP in version
```
Action: Dashboard → Press '4' (Import)
Action: Press '2' (Manual port entry)
Input:  Port: 80
Input:  Service: http
Input:  Product: Apache httpd
Input:  Version: Apache/2.4.41 (Ubuntu) PHP/7.4.3
Action: Confirm
```

**Expected Results:**
- Port 80 added with PHP in version string
- Debug log shows: `HTTP Plugin confidence: 100`
- Debug log shows: `PHP-Bypass Plugin confidence: 95` (PHP detected)
- HTTP Plugin still wins (100 > 95) for initial enumeration

### Step 2: View available tasks
```
Action: Press 'l' (List tasks)
Action: Filter for HTTP tasks (press 'f', type 'http')
Action: Filter for PHP tasks (press 'f', type 'php')
```

**Expected Results:**
- See HTTP enumeration tasks (gobuster, nikto, whatweb)
- ALSO see PHP-Bypass tasks:
  - PHP information disclosure tests
  - disable_functions enumeration
  - open_basedir bypass techniques

### Step 3: Verify both plugins generated tasks
```bash
grep "Generated tasks for.*http" .debug_logs/tui_debug_*.log | tail -1
grep "Generated tasks for.*php" .debug_logs/tui_debug_*.log | tail -1
```

**Expected Log Patterns:**
```
INFO:crack.track.services.registry:Plugin 'http' won port qa-test-2.example.com:80 with confidence 100
INFO:crack.track.services.registry:Plugin 'php-bypass' activated for port 80 (confidence 95)
```

**Success Criteria:**
- ✅ HTTP Plugin wins initial priority (100 > 95)
- ✅ PHP-Bypass also generates tasks (PHP confirmed)
- ✅ User sees both HTTP and PHP tasks
- ✅ HTTP tasks prioritized first

---

## Story 3: Progressive Discovery - Finding-Based Activation

**Goal:** Verify PHP-Bypass activates after WhatWeb finds PHP

**Starting Command:**
```bash
rm ~/.crack/targets/qa-test-3.example.com.json

crack track --tui qa-test-3.example.com \
  --debug \
  --debug-categories=STATE:VERBOSE,DATA:VERBOSE,EXECUTION:VERBOSE \
  --debug-timing
```

**Test Steps:**

### Step 1: Add generic HTTP port (no PHP indicators)
```
Action: Dashboard → Press '4' (Import)
Action: Press '2' (Manual port entry)
Input:  Port: 80
Input:  Service: http
Input:  Product: (empty)
Input:  Version: (empty)
Action: Confirm
```

**Expected Results:**
- Port 80 added as generic HTTP
- HTTP Plugin wins (100 > 0)
- Only HTTP enumeration tasks visible
- NO PHP-Bypass tasks yet

### Step 2: Simulate WhatWeb finding PHP
```
Action: Press 'd' (Document finding)
Input:  Type: technology
Input:  Description: X-Powered-By: PHP/8.0
Input:  Source: whatweb
Action: Confirm
```

**Expected Results:**
- Finding added to profile
- Debug log shows: `finding_added event emitted`
- Debug log shows: `PHP-Bypass activated via finding (confidence 90)`
- NEW PHP-Bypass tasks generated automatically

### Step 3: Verify PHP tasks now appear
```
Action: Press 'l' (List tasks)
Action: Look for PHP-specific tasks
```

**Expected Results:**
- Original HTTP tasks still present
- NEW PHP-Bypass tasks added:
  - `Check disable_functions restrictions`
  - `Test open_basedir bypass`
  - `Try LD_PRELOAD technique`

### Step 4: Check event flow in logs
```bash
grep "finding_added" .debug_logs/tui_debug_*.log | tail -5
grep "PHP-Bypass.*activated via finding" .debug_logs/tui_debug_*.log | tail -3
grep "plugin_tasks_generated" .debug_logs/tui_debug_*.log | tail -5
```

**Expected Log Patterns:**
```
INFO:crack.track.core.events:Event emitted: finding_added
INFO:crack.track.services.registry:Plugin 'php-bypass' activated via finding 'technology' (confidence: 90)
INFO:crack.track.services.registry:Generated tasks for 'php-bypass' from finding activation
```

**Success Criteria:**
- ✅ Generic HTTP → Only HTTP tasks initially
- ✅ Finding documented → PHP-Bypass activates
- ✅ PHP tasks appear automatically
- ✅ No manual intervention required
- ✅ Event chain works: finding_added → plugin activation → tasks generated

---

## Story 4: Profile Load from Disk (Event Handler Fix)

**Goal:** Verify profiles loaded from disk have working event handlers

**Starting Command:**
```bash
# Use existing google-gruyere profile (or create one with ports)
# This tests the from_dict() → _init_runtime() fix

crack track --tui google-gruyere.appspot.com \
  --debug \
  --debug-categories=STATE.TRANSITION:VERBOSE,STATE.PERSISTENCE:VERBOSE \
  --debug-timing
```

**Test Steps:**

### Step 1: Load existing profile
```
Action: TUI starts and loads profile from disk
```

**Expected Results:**
- Debug log shows: `Loading profile from ~/.crack/targets/google-gruyere.appspot.com.json`
- Debug log shows: `Profile loaded successfully`
- Debug log shows: `Initializing runtime components`
- Debug log shows: `Event handlers registered`
- NO errors about missing event handlers

### Step 2: Add new port to loaded profile
```
Action: Dashboard → Press '4' (Import)
Action: Press '2' (Manual port entry)
Input:  Port: 8080
Input:  Service: http
Action: Confirm
```

**Expected Results:**
- Debug log shows: `service_detected event emitted for port 8080`
- Debug log shows: `plugin_tasks_generated event received`
- NEW HTTP tasks generated for port 8080
- Tasks added to profile's task tree

### Step 3: Verify tasks were generated
```
Action: Press 'l' (List tasks)
Action: Filter for port 8080 tasks
```

**Expected Results:**
- See HTTP enumeration tasks for port 8080:
  - `gobuster dir -u http://google-gruyere.appspot.com:8080`
  - `nikto -h http://google-gruyere.appspot.com:8080`

### Step 4: Check event handler registration in logs
```bash
grep "_init_runtime" .debug_logs/tui_debug_*.log | head -3
grep "Event handlers registered" .debug_logs/tui_debug_*.log | head -1
grep "service_detected.*8080" .debug_logs/tui_debug_*.log | tail -3
```

**Expected Log Patterns:**
```
DEBUG:crack.track.core.state:Initializing runtime components (_init_runtime called)
DEBUG:crack.track.core.state:Event handlers registered successfully
INFO:crack.track.core.events:Event emitted: service_detected (port: 8080)
```

**Success Criteria:**
- ✅ Profile loads from disk without errors
- ✅ Event handlers registered during load
- ✅ New ports trigger service_detected events
- ✅ Plugins respond to events and generate tasks
- ✅ Tasks added to profile automatically

---

## Story 5: Webshell Finding (Highest Priority)

**Goal:** Verify PHP-Bypass gets highest priority when webshell detected

**Starting Command:**
```bash
rm ~/.crack/targets/qa-test-5.example.com.json

crack track --tui qa-test-5.example.com \
  --debug \
  --debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE \
  --debug-timing
```

**Test Steps:**

### Step 1: Create profile with HTTP port
```
Action: Dashboard → Press '4' (Import)
Action: Press '2' (Manual port entry)
Input:  Port: 80
Input:  Service: http
Action: Confirm
```

**Expected Results:**
- HTTP tasks generated (gobuster, nikto)

### Step 2: Document webshell upload
```
Action: Press 'd' (Document finding)
Input:  Type: file
Input:  Description: webshell uploaded: shell.php
Input:  Source: manual
Action: Confirm
```

**Expected Results:**
- Debug log shows: `PHP-Bypass activated via finding (confidence 100)`
- HIGH-PRIORITY PHP-Bypass tasks generated:
  - Immediate disable_functions bypass
  - Immediate open_basedir bypass
  - LD_PRELOAD exploitation
  - System command execution tests

### Step 3: Verify high-priority tasks
```
Action: Press 'l' (List tasks)
Action: Look for tasks with [HIGH PRIORITY] or [QUICK WIN] tags
```

**Expected Results:**
- PHP-Bypass tasks marked as high priority
- Tasks focused on webshell → RCE escalation
- Methodology: disable_functions enum → bypass → shell upgrade

### Step 4: Check priority in logs
```bash
grep "webshell" .debug_logs/tui_debug_*.log | tail -5
grep "PHP-Bypass.*confidence.*100" .debug_logs/tui_debug_*.log | tail -3
```

**Expected Log Patterns:**
```
INFO:crack.track.services.registry:Plugin 'php-bypass' activated via finding 'file' (confidence: 100)
INFO:crack.track.services.registry:Webshell detected - activating high-priority PHP bypass tasks
```

**Success Criteria:**
- ✅ Webshell finding triggers PHP-Bypass
- ✅ Confidence score 100 (highest)
- ✅ High-priority tasks generated
- ✅ Tasks focus on RCE escalation

---

## Story 6: Import Nmap Scan (Full Integration Test)

**Goal:** Verify complete workflow from Nmap import to task generation

**Prerequisites:**
Create test Nmap scan file:
```bash
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

**Starting Command:**
```bash
rm ~/.crack/targets/192.168.45.100.json

crack track --tui 192.168.45.100 \
  --debug \
  --debug-categories=STATE:VERBOSE,DATA.PARSE:VERBOSE,EXECUTION:VERBOSE \
  --debug-timing
```

**Test Steps:**

### Step 1: Import Nmap XML
```
Action: Dashboard → Press '4' (Import Scan Results)
Action: Press '1' (Enter custom file path)
Input:  /tmp/test-scan.xml
Action: Confirm
```

**Expected Results:**
- Debug log shows: `Parsing Nmap XML file: /tmp/test-scan.xml`
- Debug log shows: `Found 3 ports: 22, 80, 443`
- Debug log shows: `service_detected events emitted for each port`
- Debug log shows: `HTTP Plugin won ports 80 and 443`
- Debug log shows: `SSH Plugin won port 22`
- NO PHP-Bypass activation (no PHP indicators)

### Step 2: Verify SSH tasks generated
```
Action: Press 'l' (List tasks)
Action: Filter for 'ssh'
```

**Expected Results:**
- SSH enumeration tasks:
  - SSH version banner grab
  - SSH-audit scan
  - Searchsploit for OpenSSH 8.2p1

### Step 3: Verify HTTP tasks generated
```
Action: Press 'l' (List tasks)
Action: Filter for 'http'
```

**Expected Results:**
- HTTP tasks for port 80:
  - gobuster dir scan
  - nikto vulnerability scan
  - whatweb technology detection
- HTTPS tasks for port 443:
  - SSL certificate analysis
  - gobuster dir scan (HTTPS)
  - testssl.sh scan

### Step 4: Verify NO PHP tasks yet
```
Action: Press 'l' (List tasks)
Action: Filter for 'php'
```

**Expected Results:**
- Zero PHP-Bypass tasks
- No disable_functions tasks
- No open_basedir tasks

### Step 5: Check complete event flow
```bash
grep "service_detected" .debug_logs/tui_debug_*.log | tail -10
grep "Plugin.*won port" .debug_logs/tui_debug_*.log | tail -5
grep "plugin_tasks_generated" .debug_logs/tui_debug_*.log | tail -10
```

**Expected Log Patterns:**
```
INFO:crack.track.core.events:Event emitted: service_detected (port: 22, service: ssh)
INFO:crack.track.core.events:Event emitted: service_detected (port: 80, service: http)
INFO:crack.track.core.events:Event emitted: service_detected (port: 443, service: https)
INFO:crack.track.services.registry:Plugin 'ssh' won port 192.168.45.100:22 with confidence 100
INFO:crack.track.services.registry:Plugin 'http' won port 192.168.45.100:80 with confidence 100
INFO:crack.track.services.registry:Plugin 'http' won port 192.168.45.100:443 with confidence 90
```

**Success Criteria:**
- ✅ Nmap XML parsed successfully
- ✅ All 3 ports detected
- ✅ Correct plugins won for each service
- ✅ Appropriate tasks generated for each service
- ✅ NO PHP-Bypass tasks (no PHP detected)
- ✅ Complete event chain logged

---

## Story 7: Multi-Stage Discovery (HTTP → PHP → SQLi)

**Goal:** Verify cascading finding activation across multiple plugin types

**Starting Command:**
```bash
rm ~/.crack/targets/qa-test-7.example.com.json

crack track --tui qa-test-7.example.com \
  --debug \
  --debug-categories=STATE:VERBOSE,DATA:VERBOSE,EXECUTION:VERBOSE \
  --debug-timing
```

**Test Steps:**

### Step 1: Start with generic HTTP
```
Action: Dashboard → Import → Manual port entry
Input:  Port: 80, Service: http
Action: Confirm
```

**Expected:**
- HTTP tasks only (gobuster, nikto, whatweb)

### Step 2: Document PHP discovery
```
Action: Press 'd' (Document finding)
Input:  Type: technology
Input:  Description: PHP/7.4.3 detected via X-Powered-By header
Input:  Source: whatweb
Action: Confirm
```

**Expected:**
- PHP-Bypass tasks added automatically
- Debug log: `PHP-Bypass activated via finding (confidence 90)`

### Step 3: Document login form discovery
```
Action: Press 'd' (Document finding)
Input:  Type: directory
Input:  Description: /admin/login.php
Input:  Source: gobuster
Action: Confirm
```

**Expected:**
- Auth bypass tasks added
- SQL injection test tasks added (login form = potential SQLi)
- XSS test tasks added

### Step 4: Document SQLi vulnerability
```
Action: Press 'd' (Document finding)
Input:  Type: vulnerability
Input:  Description: SQL injection in login form (username parameter)
Input:  Source: manual testing
Action: Confirm
```

**Expected:**
- SQLi exploitation tasks added:
  - Database enumeration (sqlmap)
  - Table/column extraction
  - Data exfiltration
  - Potential webshell upload

### Step 5: View task tree progression
```
Action: Press 't' (Task Tree)
Action: Expand all nodes
```

**Expected Tree Structure:**
```
HTTP Enumeration (Port 80)
├─ gobuster dir scan
├─ nikto vulnerability scan
└─ whatweb technology detection
PHP-Bypass Techniques
├─ Enumerate disable_functions
├─ Test open_basedir bypass
└─ LD_PRELOAD technique
Web Security Testing
├─ SQL Injection Tests
│  ├─ Manual SQLi exploitation
│  ├─ sqlmap database enumeration
│  └─ Extract database credentials
└─ Auth Bypass Tests
   ├─ Test default credentials
   └─ SQL injection auth bypass
```

### Step 6: Verify cascading activation logs
```bash
grep "activated via finding" .debug_logs/tui_debug_*.log | tail -10
grep "plugin_tasks_generated" .debug_logs/tui_debug_*.log | tail -15
```

**Expected Log Patterns:**
```
INFO:crack.track.services.registry:Plugin 'php-bypass' activated via finding 'technology' (confidence: 90)
INFO:crack.track.services.registry:Plugin 'auth-bypass' activated via finding 'directory' (confidence: 85)
INFO:crack.track.services.registry:Plugin 'injection-attacks' activated via finding 'directory' (confidence: 80)
INFO:crack.track.services.registry:Plugin 'injection-attacks' activated via finding 'vulnerability' (confidence: 100)
```

**Success Criteria:**
- ✅ Progressive discovery workflow works
- ✅ Each finding triggers appropriate plugins
- ✅ Task tree grows organically
- ✅ No duplicate tasks generated
- ✅ Tasks reflect current attack surface

---

## Log Analysis Commands

**Quick checks for all stories:**

```bash
# Check plugin priority decisions
grep "Plugin.*won port" .debug_logs/tui_debug_*.log | tail -20

# Check event emission
grep "Event emitted:" .debug_logs/tui_debug_*.log | tail -30

# Check finding-based activation
grep "activated via finding" .debug_logs/tui_debug_*.log | tail -15

# Check for errors
grep "ERROR" .debug_logs/tui_debug_*.log | tail -20

# Check confidence scores
grep "confidence" .debug_logs/tui_debug_*.log | grep -E "(http|php-bypass)" | tail -20

# View complete event flow for a port
grep "port.*80" .debug_logs/tui_debug_*.log | grep -E "(service_detected|plugin_tasks_generated|won port)" | tail -30
```

**Performance checks:**
```bash
# Find slow operations (>1 second)
grep "elapsed=" .debug_logs/tui_debug_*.log | awk -F'=' '$2 > 1.0' | tail -20

# Task generation timing
grep "Generated tasks" .debug_logs/tui_debug_*.log | grep "elapsed" | tail -10
```

---

## Common Issues & Debugging

### Issue: No tasks generated after port import

**Debug Steps:**
```bash
# 1. Check if service_detected event was emitted
grep "service_detected" .debug_logs/tui_debug_*.log | tail -5

# 2. Check if any plugin detected the service
grep "Plugin.*confidence.*[1-9]" .debug_logs/tui_debug_*.log | tail -10

# 3. Check for event handler errors
grep "Error in event handler" .debug_logs/tui_debug_*.log | tail -10

# 4. Check if profile initialized runtime
grep "_init_runtime" .debug_logs/tui_debug_*.log | head -3
```

**Expected Fix:**
- Event handlers not registered → Ensure `_init_runtime()` was called
- No plugin matched → Check port info (service name, product, version)

### Issue: PHP-Bypass tasks appearing for generic HTTP

**Debug Steps:**
```bash
# 1. Check PHP-Bypass confidence score
grep "php-bypass.*confidence" .debug_logs/tui_debug_*.log | tail -5

# 2. Check if PHP was detected in port info
grep "port.*80.*service.*http" .debug_logs/tui_debug_*.log | tail -3

# 3. Verify HTTP plugin won
grep "http.*won port.*80" .debug_logs/tui_debug_*.log | tail -3
```

**Expected Fix:**
- PHP-Bypass should return confidence 0 for generic HTTP
- HTTP Plugin should win with confidence 100

### Issue: Finding doesn't trigger new tasks

**Debug Steps:**
```bash
# 1. Check if finding was saved
grep "Finding added" .debug_logs/tui_debug_*.log | tail -5

# 2. Check if finding_added event was emitted
grep "finding_added" .debug_logs/tui_debug_*.log | tail -5

# 3. Check if any plugin responded to finding
grep "activated via finding" .debug_logs/tui_debug_*.log | tail -5
```

**Expected Fix:**
- Ensure finding type matches plugin expectations
- Verify finding description contains trigger keywords

---

## Success Metrics

**After completing all stories, verify:**

1. **Event Handler Registration**
   - [ ] Profiles load from disk without errors
   - [ ] Event handlers registered on load
   - [ ] New ports trigger events
   - [ ] Tasks generated for loaded profiles

2. **Plugin Priority Resolution**
   - [ ] HTTP Plugin wins generic HTTP (100 > 0)
   - [ ] PHP-Bypass returns 0 for generic HTTP
   - [ ] PHP-Bypass activates when PHP detected (95)
   - [ ] Progressive discovery works (finding-based)

3. **Task Generation**
   - [ ] HTTP tasks generated for port 80/443
   - [ ] PHP tasks only when PHP confirmed
   - [ ] No duplicate task generation
   - [ ] Task tree reflects attack surface

4. **Performance**
   - [ ] Profile load < 1 second
   - [ ] Task generation < 500ms
   - [ ] No event handler errors
   - [ ] Smooth TUI responsiveness

5. **Log Quality**
   - [ ] No ERROR logs during normal operation
   - [ ] Event flow clearly visible
   - [ ] Plugin decisions logged with confidence
   - [ ] Timing data available for analysis
