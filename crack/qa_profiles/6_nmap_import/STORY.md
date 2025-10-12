# QA Story 6: Nmap Import (Full Integration Test)

## Test Scenario

**Objective:** Verify end-to-end Nmap XML import workflow with plugin activation.

**Target Profile:** `qa-story-6-nmap-import`

**Starting State:**
- No ports (fresh profile)
- No findings
- Tests full import → parse → detect → tasks workflow

**Test Flow:**
1. Create Nmap scan with ports 22, 80, 443
2. Import scan via TUI
3. ServiceRegistry processes all ports
4. SSH + HTTP plugins activate
5. Tasks generated automatically

**Expected Results:**
- ✅ Nmap XML imported successfully
- ✅ Ports 22, 80, 443 detected
- ✅ SSH tasks generated (port 22)
- ✅ HTTP tasks generated (ports 80, 443)
- ✅ NO PHP tasks (no PHP detected)

## Quick Start

```bash
./qa_profiles/run_qa_story.sh 6
```

## Test Steps

### 1. Create Test Nmap Scan (Optional - can use mock)

```bash
# Create minimal test XML
cat > /tmp/test-scan.xml <<'EOF'
<?xml version="1.0"?>
<nmaprun>
<host>
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

### 2. Launch TUI

```bash
crack track --tui qa-story-6-nmap-import \
  --debug \
  --debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE
```

### 3. Import Nmap Scan

**In TUI:**
- Press `i` (Import scan results)
- Select Nmap XML option
- Enter path: `/tmp/test-scan.xml`
- Confirm import

### 4. Observe Automatic Task Generation

**Expected Logs:**
```
Importing Nmap XML: /tmp/test-scan.xml
Parsed 3 ports: 22, 80, 443
service_detected event emitted for port 22
service_detected event emitted for port 80
service_detected event emitted for port 443
SSH Plugin activated for port 22
HTTP Plugin activated for port 80
HTTP Plugin activated for port 443
Generated tasks for 'ssh' on port 22
Generated tasks for 'http' on port 80
Generated tasks for 'http' on port 443
```

### 5. Verify Task Tree

- Press `t`: View all generated tasks
- Expected: SSH tasks + HTTP tasks (ports 80, 443)

## Pass Criteria

- [x] Nmap XML imported without errors
- [x] All 3 ports detected
- [x] SSH Plugin activated for port 22
- [x] HTTP Plugin activated for ports 80, 443
- [x] Tasks generated for all services
- [x] NO PHP tasks (no PHP in version strings)

## Troubleshooting

**Issue:** Import fails with parse error

**Fix:** Verify Nmap XML format is valid

**Issue:** Ports detected but no tasks generated

**Fix:** Check event handlers registered (_init_runtime called)

## Related Documentation

- `track/parsers/nmap_parser.py` - Nmap XML parsing
- `track/core/events.py` - service_detected events
